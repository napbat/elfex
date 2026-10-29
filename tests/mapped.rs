//! Integration tests for loader-mapped images, positional readers and image dumps.

use std::collections::BTreeMap;

use elfex::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use elfex::{
    BaseAddressReader, BuilderSection, ElfBuilder, ElfFile, ElfHeaders, ElfImage, Encoding, Error,
    FileType, ParseOptions, ReadAt, SegmentType, SourceLayout,
};

/// The four combinations of class and byte order.
const ENCODINGS: [Encoding; 4] = [
    Encoding::ELF32_LE,
    Encoding::ELF32_BE,
    Encoding::ELF64_LE,
    Encoding::ELF64_BE,
];

/// The page size of the simulated remote process.
const PAGE_SIZE: u64 = 0x1000;

/// Build a shared object with code, data and `.bss`, and return its bytes.
fn shared_object(encoding: Encoding) -> Vec<u8> {
    ElfBuilder::new(encoding)
        .file_type(FileType::DYN)
        .add_section(BuilderSection::progbits(
            ".rodata",
            SHF_ALLOC,
            b"mapped read-only data\0".to_vec(),
        ))
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            (0..=0xffu8).collect(),
        ))
        .add_section(BuilderSection::progbits(
            ".data",
            SHF_ALLOC | SHF_WRITE,
            vec![0xa5; 0x1800],
        ))
        .add_section(BuilderSection::nobits(
            ".bss",
            SHF_ALLOC | SHF_WRITE,
            0x3000,
        ))
        .add_section(BuilderSection::progbits(
            ".comment",
            0,
            b"not mapped\0".to_vec(),
        ))
        .entry_in_section(".text", 0)
        .try_build()
        .expect("the shared object should build")
        .try_build()
        .expect("the shared object should serialize")
}

/// Convert a `u64` to `usize` in a test.
fn to_usize(value: u64) -> usize {
    usize::try_from(value).expect("the value should fit in usize")
}

/// Check that each `PT_LOAD` segment of `mapped` starts with the file bytes of the same
/// segment of `raw`, and that the other memory bytes are zero.
fn assert_same_load_data(raw: &ElfImage<'_>, mapped: &ElfImage<'_>) {
    assert!(raw.program_headers().eq(mapped.program_headers()));
    for (file, memory) in raw.segments.iter().zip(&mapped.segments) {
        if !file.is_load() {
            continue;
        }
        let filesz = to_usize(file.header.filesz);
        assert_eq!(file.data.len(), filesz);
        assert_eq!(&memory.data[..filesz], &*file.data);
        assert!(memory.data[filesz..].iter().all(|byte| *byte == 0));
        assert!(memory.data.len() <= to_usize(memory.header.memsz));
    }
}

#[test]
fn raw_and_mapped_images_have_the_same_segment_data() {
    for encoding in ENCODINGS {
        let bytes = shared_object(encoding);
        let raw = ElfImage::parse(&bytes).expect("the raw file should parse");
        assert_eq!(raw.source_layout(), SourceLayout::File);
        assert_eq!(raw.runtime_base(), None);
        assert_eq!(raw.image_origin(), Some(0));

        let mapped_bytes = raw.to_mapped_image().expect("the image should map");
        let headers = ElfHeaders::from_slice(&bytes).expect("the headers should parse");
        assert_eq!(
            u64::try_from(mapped_bytes.len()).ok(),
            headers.mapped_size()
        );

        let mapped = ElfImage::parse_mapped(&mapped_bytes).expect("the mapped image should parse");
        assert_eq!(mapped.source_layout(), SourceLayout::Mapped);
        assert_same_load_data(&raw, &mapped);
        assert_eq!(
            mapped
                .to_mapped_image()
                .expect("the image should map again"),
            mapped_bytes
        );

        let runtime_base = 0x1000_0000;
        let relocated = ElfImage::parse_mapped_at(&mapped_bytes, runtime_base)
            .expect("the mapped image should parse at a runtime base");
        assert_same_load_data(&raw, &relocated);
        assert_eq!(relocated.runtime_base(), Some(runtime_base));
        assert_eq!(relocated.load_bias(), Some(runtime_base));
        assert_eq!(
            relocated.vaddr_to_runtime(relocated.entry_point()),
            Some(runtime_base + relocated.entry_point())
        );
        assert_eq!(relocated.runtime_to_vaddr(runtime_base + 0x10), Some(0x10));

        let mapped_headers =
            ElfHeaders::from_mapped_slice(&mapped_bytes).expect("the mapped headers should parse");
        assert_eq!(mapped_headers.program_headers, headers.program_headers);
        let text = headers
            .section_by_name(".text")
            .map(|(_, section)| *section)
            .expect("the file has .text");
        assert_eq!(
            headers.vaddr_to_source_offset(text.addr, SourceLayout::File),
            Some(text.offset)
        );
        assert_eq!(
            headers.vaddr_to_source_offset(text.addr, SourceLayout::Mapped),
            Some(text.addr)
        );
    }
}

#[test]
fn mapped_image_reads_bss_as_zero_memory() {
    let bytes = shared_object(Encoding::ELF64_LE);
    let file = ElfFile::parse(&bytes).expect("the file should parse");
    let bss = file
        .section_by_name(".bss")
        .expect("the file has .bss")
        .header
        .addr;
    let image = ElfImage::parse(&bytes).expect("the image should parse");
    assert_eq!(
        image.read_vaddr(bss, 0x3000).expect("the .bss is mapped"),
        vec![0; 0x3000]
    );
    let mapped_bytes = image.to_mapped_image().expect("the image should map");
    let mapped = ElfImage::parse_mapped(&mapped_bytes).expect("the mapped image should parse");
    assert_eq!(
        mapped.read_vaddr(bss, 0x3000).expect("the .bss is mapped"),
        vec![0; 0x3000]
    );
    assert!(mapped.read_vaddr(bss + 0x3000, 1).is_err());
}

/// A remote process with a sparse address space. It reads only the pages in its map.
struct SparseProcess {
    /// The pages, by page address.
    pages: BTreeMap<u64, Vec<u8>>,
}

impl SparseProcess {
    /// Map `image` at `address`, without the page at `missing`.
    fn new(image: &[u8], address: u64, missing: Option<u64>) -> Self {
        assert_eq!(address % PAGE_SIZE, 0);
        let mut pages = BTreeMap::new();
        for (index, chunk) in image.chunks(to_usize(PAGE_SIZE)).enumerate() {
            let page = address + PAGE_SIZE * u64::try_from(index).expect("the index fits");
            if Some(page) == missing {
                continue;
            }
            let mut bytes = chunk.to_vec();
            bytes.resize(to_usize(PAGE_SIZE), 0);
            pages.insert(page, bytes);
        }
        Self { pages }
    }
}

impl ReadAt for SparseProcess {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> elfex::Result<usize> {
        let page_address = offset - offset % PAGE_SIZE;
        let page = self
            .pages
            .get(&page_address)
            .ok_or_else(|| Error::invalid_address(offset))?;
        let start = to_usize(offset - page_address);
        let count = buf.len().min(page.len() - start);
        buf[..count].copy_from_slice(&page[start..start + count]);
        Ok(count)
    }

    fn size(&self) -> Option<u64> {
        None
    }
}

#[test]
fn sparse_remote_process_reads_with_missing_pages() {
    let runtime_base = 0x7f12_3456_0000;
    for encoding in ENCODINGS {
        let bytes = shared_object(encoding);
        let raw = ElfImage::parse(&bytes).expect("the raw file should parse");
        let mapped_bytes = raw.to_mapped_image().expect("the image should map");
        let file_headers = ElfHeaders::from_slice(&bytes).expect("the headers should parse");
        let data = file_headers
            .section_by_name(".data")
            .map(|(_, section)| *section)
            .expect("the file has .data");
        let missing_page = data.addr - data.addr % PAGE_SIZE;
        assert_ne!(missing_page, 0);
        let process = SparseProcess::new(
            &mapped_bytes,
            runtime_base,
            Some(runtime_base + missing_page),
        );

        let headers = ElfHeaders::read_from(&process, runtime_base, SourceLayout::Mapped)
            .expect("the headers should parse from the process");
        assert_eq!(headers.header, file_headers.header);
        assert_eq!(headers.program_headers, file_headers.program_headers);
        assert_eq!(headers.section_headers, []);

        assert!(ElfImage::read_mapped_from(&process, runtime_base, runtime_base).is_err());
        let image = ElfImage::read_from_with_options(
            &process,
            runtime_base,
            ParseOptions::mapped()
                .allow_missing_segment_data()
                .runtime_base(runtime_base),
        )
        .expect("the image should parse with missing pages");
        assert_eq!(image.runtime_base(), Some(runtime_base));

        let mut expected = mapped_bytes.clone();
        let page = to_usize(missing_page);
        let page_end = expected.len().min(page + to_usize(PAGE_SIZE));
        expected[page..page_end].fill(0);
        for segment in image.load_segments() {
            let start = to_usize(segment.header.vaddr);
            assert_eq!(&*segment.data, &expected[start..start + segment.data.len()]);
            assert!(segment.data.len() >= to_usize(segment.header.filesz));
        }
        assert_eq!(
            image
                .read_vaddr(data.addr, 4)
                .expect("the page reads as zeros"),
            [0; 4]
        );
        let text = file_headers
            .section_by_name(".text")
            .map(|(_, section)| *section)
            .expect("the file has .text");
        assert_eq!(
            image.read_vaddr(text.addr, 4).expect("the code is mapped"),
            [0, 1, 2, 3]
        );

        let complete = SparseProcess::new(&mapped_bytes, runtime_base, None);
        let image = ElfImage::read_mapped_from(&complete, runtime_base, runtime_base)
            .expect("the complete image should parse");
        let mapped = ElfImage::parse_mapped(&mapped_bytes).expect("the mapped image should parse");
        assert!(image.program_headers().eq(mapped.program_headers()));
        for (remote, local) in image.load_segments().zip(mapped.load_segments()) {
            let filesz = to_usize(remote.header.filesz);
            assert_eq!(remote.data[..filesz], local.data[..filesz]);
        }
    }
}

#[test]
fn dump_of_mapped_image_keeps_the_load_file_bytes() {
    for encoding in ENCODINGS {
        let bytes = shared_object(encoding);
        let original = ElfFile::parse(&bytes).expect("the file should parse");
        let mapped_bytes = ElfImage::parse(&bytes)
            .expect("the raw file should parse")
            .to_mapped_image()
            .expect("the image should map");
        let mapped = ElfImage::parse_mapped(&mapped_bytes).expect("the mapped image should parse");

        let dump = mapped.try_build().expect("the mapped image should dump");
        let file = ElfFile::parse(&dump).expect("the dump should parse as a file");
        assert_eq!(file.section_headers(), []);
        assert_eq!(file.header().shoff, 0);
        assert_eq!(file.entry_point(), original.entry_point());
        assert_eq!(file.program_headers(), original.program_headers());
        assert_eq!(file.try_build().expect("the dump should build"), dump);
        assert!(!file.validate().has_errors());

        let header_size = u64::from(original.header().ehsize);
        for (index, segment) in original.program_headers().iter().enumerate() {
            if segment.segment_type != SegmentType::LOAD {
                continue;
            }
            let expected = original
                .segment_data(index)
                .expect("the segment is in the file");
            let actual = file
                .segment_data(index)
                .expect("the segment is in the dump");
            let skip = to_usize(header_size.saturating_sub(segment.offset)).min(expected.len());
            assert_eq!(actual[skip..], expected[skip..], "PT_LOAD at {index}");
        }
    }
}

#[test]
fn base_address_reader_reads_a_local_mapped_image() {
    let bytes = shared_object(Encoding::ELF64_LE);
    let mapped_bytes = ElfImage::parse(&bytes)
        .expect("the raw file should parse")
        .to_mapped_image()
        .expect("the image should map");
    let expected = ElfImage::parse_mapped(&mapped_bytes).expect("the mapped image should parse");

    #[expect(
        unsafe_code,
        reason = "BaseAddressReader::new is unsafe; this test exercises it on a live buffer"
    )]
    // SAFETY: `mapped_bytes` stays alive and does not change while the reader is in use. The
    // reader reads at most `mapped_bytes.len()` bytes.
    let reader = unsafe { BaseAddressReader::new(mapped_bytes.as_ptr(), Some(mapped_bytes.len())) };
    let base = u64::try_from(mapped_bytes.as_ptr().addr()).expect("the address fits");
    let image = ElfImage::read_mapped_from(&reader, 0, base)
        .expect("the image should parse from the base address");
    assert_eq!(image.segments, expected.segments);
    assert_eq!(image.runtime_base(), Some(base));
    assert_eq!(image.load_bias(), Some(base));
}
