//! Tests for [`ElfImage`].

use super::{ElfImage, Segment};
use crate::elf::{ParseOptions, SourceLayout};
use crate::elf_file::ElfFile;
use crate::endian::Encoding;
use crate::error::ErrorKind;
use crate::header::{FileHeader, FileType, Machine};
use crate::note::{
    AT_ENTRY, AT_PAGESZ, AuxvEntry, ELF_NOTE_CORE, ELF_NOTE_LINUX, FileMapping, NT_AUXV, NT_FILE,
    Note, NoteTable, write_auxv, write_nt_file,
};
use crate::prelude::*;
use crate::program::{PF_R, PF_W, PF_X, ProgramHeader, SegmentType};
use crate::reader::{ReadAt, SliceReader};
use crate::validation::ValidationCode;
use crate::{Error, Result};
use core::cell::Cell;
use core::ops::Range;

mod borrow;
mod edges;
mod source;

/// The virtual address of the image origin in the sample.
const BASE: u64 = 0x1_0000;
/// The interpreter path in the sample, with its null byte.
const INTERP: &[u8] = b"/lib/ld-elfex.so.1\0";
/// The size of the sample file.
const FILE_SIZE: usize = 0x240;
/// The size of the mapped sample image.
const MAPPED_SIZE: usize = 0x1400;

/// Convert a test size to `u64`.
fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

/// Return `true` if all bytes are zero.
fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

/// Build a raw file without sections and without gaps, after `edit` changes the headers.
///
/// The file has the ELF header, the program header table (`PT_PHDR`, `PT_INTERP` and two
/// `PT_LOAD` segments) and the interpreter path. The first `PT_LOAD` segment maps file offsets
/// `0..0x200` at `BASE`. The second maps `0x200..0x240` at `BASE + 0x1200`, with `p_memsz`
/// 0x200.
fn sample_with(
    encoding: Encoding,
    edit: impl FnOnce(&mut FileHeader, &mut Vec<ProgramHeader>),
) -> Vec<u8> {
    let header_size = FileHeader::size(encoding.class);
    let table_size = 4 * ProgramHeader::size(encoding.class);
    let interp_offset = to_u64(header_size + table_size);
    let mut header = FileHeader::new(encoding, FileType::DYN, Machine::X86_64);
    header.phoff = to_u64(header_size);
    header.phnum = 4;
    header.entry = BASE + 0x180;
    let segment =
        |segment_type, flags, offset: u64, vaddr: u64, filesz: u64, memsz, align| ProgramHeader {
            segment_type,
            flags,
            offset,
            vaddr,
            paddr: vaddr,
            filesz,
            memsz,
            align,
        };
    let interp_size = to_u64(INTERP.len());
    let table = to_u64(table_size);
    let mut segments = vec![
        segment(
            SegmentType::PHDR,
            PF_R,
            header.phoff,
            BASE + header.phoff,
            table,
            table,
            8,
        ),
        segment(
            SegmentType::INTERP,
            PF_R,
            interp_offset,
            BASE + interp_offset,
            interp_size,
            interp_size,
            1,
        ),
        segment(
            SegmentType::LOAD,
            PF_R | PF_X,
            0,
            BASE,
            0x200,
            0x200,
            0x1000,
        ),
        segment(
            SegmentType::LOAD,
            PF_R | PF_W,
            0x200,
            BASE + 0x1200,
            0x40,
            0x200,
            0x1000,
        ),
    ];
    edit(&mut header, &mut segments);
    let mut out = header.to_bytes().unwrap();
    for segment in &segments {
        segment.write(&mut out, encoding).unwrap();
    }
    out.extend_from_slice(INTERP);
    while out.len() < 0x200 {
        out.push(u8::try_from(out.len() % 251).unwrap());
    }
    out.extend((0..0x40u8).map(|byte| byte ^ 0x5a));
    assert_eq!(out.len(), FILE_SIZE);
    out
}

/// Build the sample file without changes.
fn sample(encoding: Encoding) -> Vec<u8> {
    sample_with(encoding, |_, _| {})
}

/// Return the runtime base for the class of `encoding`.
fn runtime_base(encoding: Encoding) -> u64 {
    if encoding.is_64bit() {
        0x7f00_0000_0000
    } else {
        0x4000_0000
    }
}

/// A test source that holds `data` at the offset `base`, with a known or an unknown size.
///
/// A read that starts in `hole` fails. A read that starts before `hole` stops at its start.
/// The source records the largest read request. All the tests of special sources use this
/// type, so that one instantiation of the generic parser covers all the read paths.
struct TestReader<'a> {
    data: &'a [u8],
    base: u64,
    hole: Range<u64>,
    sized: bool,
    largest: Cell<usize>,
}

impl<'a> TestReader<'a> {
    /// Return a source of `data` with a known size.
    fn sized(data: &'a [u8]) -> Self {
        Self {
            data,
            base: 0,
            hole: 0..0,
            sized: true,
            largest: Cell::new(0),
        }
    }

    /// Return a source of `data` with an unknown size.
    fn unknown_size(data: &'a [u8]) -> Self {
        Self {
            sized: false,
            ..Self::sized(data)
        }
    }

    /// Make the reads in `hole` fail.
    fn with_hole(self, hole: Range<u64>) -> Self {
        Self { hole, ..self }
    }

    /// Put the data at the offset `base`.
    fn at(self, base: u64) -> Self {
        Self { base, ..self }
    }
}

impl ReadAt for TestReader<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        self.largest.set(self.largest.get().max(buf.len()));
        if self.hole.contains(&offset) || offset < self.base {
            return Err(Error::generic("the page is not readable"));
        }
        let end = offset.saturating_add(to_u64(buf.len()));
        let buf = if offset < self.hole.start && self.hole.start < end {
            let len = usize::try_from(self.hole.start - offset).unwrap();
            &mut buf[..len]
        } else {
            buf
        };
        SliceReader::new(self.data).read_at(offset - self.base, buf)
    }

    fn size(&self) -> Option<u64> {
        self.sized.then(|| self.base + to_u64(self.data.len()))
    }
}

#[test]
fn parses_raw_files() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let bytes = sample(encoding);
        let image = ElfImage::parse(&bytes).unwrap();
        assert_eq!(image.encoding(), encoding);
        assert_eq!(image.is_64bit(), encoding.is_64bit());
        assert_eq!(image.file_type(), FileType::DYN);
        assert_eq!(image.machine(), Machine::X86_64);
        assert_eq!(image.entry_point(), BASE + 0x180);
        assert_eq!(image.source_layout(), SourceLayout::File);
        assert_eq!(image.runtime_base(), None);
        assert_eq!(image.load_bias(), None);
        assert_eq!(image.segments.len(), 4);
        assert_eq!(image.program_headers().len(), 4);
        assert_eq!(*image.segments[0].data, []);
        assert_eq!(*image.segments[1].data, []);
        assert_eq!(*image.segments[2].data, bytes[..0x200]);
        assert_eq!(*image.segments[3].data, bytes[0x200..]);
        assert_eq!(image.segments[3].memory_size(), 0x200);
        assert_eq!(image.load_segments().count(), 2);
        assert!(
            image
                .segment(SegmentType::PHDR)
                .is_some_and(|segment| !segment.is_load())
        );
        assert_eq!(image.image_origin(), Some(BASE));
        assert_eq!(image.image_end(), Some(BASE + to_u64(MAPPED_SIZE)));
        assert_eq!(
            image.interpreter().unwrap().as_deref(),
            Some("/lib/ld-elfex.so.1")
        );
        let headers = image.headers();
        assert_eq!(headers.program_headers.len(), 4);
        assert_eq!(headers.section_headers, []);
        assert!(!image.validate().has_errors(), "{:?}", image.validate());
    }
}

#[test]
fn makes_mapped_image_with_zero_fill() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let bytes = sample(encoding);
        let mapped = ElfImage::parse(&bytes).unwrap().to_mapped_image().unwrap();
        assert_eq!(mapped.len(), MAPPED_SIZE);
        assert_eq!(mapped[..0x200], bytes[..0x200]);
        assert!(all_zero(&mapped[0x200..0x1200]));
        assert_eq!(mapped[0x1200..0x1240], bytes[0x200..]);
        assert!(all_zero(&mapped[0x1240..]));
    }
}

#[test]
fn parses_mapped_image() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let file = ElfImage::parse(&sample(encoding)).unwrap().into_owned();
        let mapped = file.to_mapped_image().unwrap();
        let image = ElfImage::parse_mapped(&mapped).unwrap();
        assert_eq!(image.source_layout(), SourceLayout::Mapped);
        assert_eq!(image.header, file.header);
        assert!(image.program_headers().eq(file.program_headers()));
        assert_eq!(*image.segments[0].data, []);
        assert_eq!(*image.segments[1].data, []);
        assert_eq!(*image.segments[2].data, mapped[..0x200]);
        assert_eq!(*image.segments[3].data, mapped[0x1200..]);
        assert_eq!(image.to_mapped_image().unwrap(), mapped);
        assert_eq!(image.interpreter().unwrap(), file.interpreter().unwrap());
        for vaddr in [BASE, BASE + 0x1200] {
            assert_eq!(
                image.read_vaddr(vaddr, 0x200).unwrap(),
                file.read_vaddr(vaddr, 0x200).unwrap()
            );
        }
    }
}

#[test]
fn mapped_image_at_runtime_base_has_load_bias() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let mapped = ElfImage::parse(&sample(encoding))
            .unwrap()
            .to_mapped_image()
            .unwrap();
        let base = runtime_base(encoding);
        let image = ElfImage::parse_mapped_at(&mapped, base).unwrap();
        assert_eq!(image.runtime_base(), Some(base));
        assert_eq!(image.load_bias(), Some(base - BASE));
        assert_eq!(image.vaddr_to_runtime(BASE + 0x10), Some(base + 0x10));
        assert_eq!(image.runtime_to_vaddr(base + 0x1210), Some(BASE + 0x1210));

        let reader = SliceReader::new(&mapped);
        let read = ElfImage::read_mapped_from(&reader, 0, base).unwrap();
        assert_eq!(read, image);
    }
}

#[test]
fn build_reproduces_raw_file() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let bytes = sample(encoding);
        let image = ElfImage::parse(&bytes).unwrap();
        assert_eq!(image.try_build().unwrap(), bytes);
        assert_eq!(image.build(), bytes);
        let mut written = Vec::new();
        image.write_to(&mut written).unwrap();
        assert_eq!(written, bytes);
    }
}

#[test]
fn mapped_image_builds_raw_file() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let bytes = sample(encoding);
        let mapped = ElfImage::parse(&bytes).unwrap().to_mapped_image().unwrap();
        let rebuilt = ElfImage::parse_mapped(&mapped)
            .unwrap()
            .try_build()
            .unwrap();
        assert_eq!(rebuilt, bytes);
        let again = ElfImage::parse(&rebuilt).unwrap();
        let original = ElfImage::parse(&bytes).unwrap();
        assert!(
            again
                .load_segments()
                .map(|segment| &segment.data)
                .eq(original.load_segments().map(|segment| &segment.data))
        );
    }
}

#[test]
fn build_clears_section_fields_and_checks_counts() {
    let bytes = sample_with(Encoding::ELF64_LE, |header, _| {
        header.shoff = 0x1f0;
        header.shnum = 1;
        header.shstrndx = 0;
    });
    let image = ElfImage::parse(&bytes).unwrap();
    let rebuilt = ElfImage::parse(&image.try_build().unwrap())
        .unwrap()
        .into_owned();
    assert_eq!(rebuilt.header.shoff, 0);
    assert_eq!(rebuilt.header.shnum, 0);

    let mut image = ElfImage::parse(&sample(Encoding::ELF64_LE))
        .unwrap()
        .into_owned();
    let note = Segment {
        header: ProgramHeader {
            segment_type: SegmentType::NOTE,
            ..image.segments[0].header
        },
        data: Vec::new().into(),
    };
    image.segments.resize(0xffff, note);
    assert!(matches!(
        image.try_build().unwrap_err().kind(),
        ErrorKind::InvalidHeader(_)
    ));
}

/// Read `data` with `options` from a [`TestReader`] with a known size.
fn read_sized(data: &[u8], options: ParseOptions) -> Result<ElfImage<'_>> {
    ElfImage::read_from_with_options(&TestReader::sized(data), 0, options)
}

#[test]
fn truncated_file_needs_missing_data_option() {
    let bytes = sample(Encoding::ELF64_LE);
    let truncated = &bytes[..0x220];
    let error = read_sized(truncated, ParseOptions::file()).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidSegment(_)),
        "{error:?}"
    );
    assert_eq!(error.context().unwrap().file_offset, Some(0x200));

    let options = ParseOptions::file().allow_missing_segment_data();
    let image = read_sized(truncated, options).unwrap();
    assert_eq!(image.segments[3].data.len(), 0x40);
    assert_eq!(image.segments[3].data[..0x20], bytes[0x200..0x220]);
    assert!(all_zero(&image.segments[3].data[0x20..]));

    let huge = sample_with(Encoding::ELF64_LE, |_, segments| {
        segments[3].filesz = 0x10_0000;
        segments[3].memsz = 0x10_0000;
    });
    assert!(read_sized(&huge, ParseOptions::file()).is_err());
    let error = read_sized(&huge, options).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidSegment(_)),
        "{error:?}"
    );
    assert_eq!(error.context().unwrap().file_offset, Some(0x200));
}

#[test]
fn truncated_mapped_image() {
    let mapped = ElfImage::parse(&sample(Encoding::ELF32_BE))
        .unwrap()
        .to_mapped_image()
        .unwrap();
    // The source ends after `p_filesz`: the segment keeps the bytes that the source has.
    let image = read_sized(&mapped[..0x1300], ParseOptions::mapped()).unwrap();
    assert_eq!(*image.segments[3].data, mapped[0x1200..0x1300]);
    assert_eq!(image.read_vaddr(BASE + 0x13f0, 0x10).unwrap(), [0; 0x10]);

    // The source ends before `p_filesz`.
    assert!(read_sized(&mapped[..0x1220], ParseOptions::mapped()).is_err());
    let options = ParseOptions::mapped().allow_missing_segment_data();
    let image = read_sized(&mapped[..0x1220], options).unwrap();
    assert_eq!(image.segments[3].data.len(), 0x40);
    assert_eq!(image.segments[3].data[..0x20], mapped[0x1200..0x1220]);
    assert!(all_zero(&image.segments[3].data[0x20..]));
}

#[test]
fn missing_page_reads_as_zeros() {
    let mut image = ElfImage::parse(&sample(Encoding::ELF64_LE))
        .unwrap()
        .into_owned();
    image.segments[2].header.filesz = 0x3000;
    image.segments[2].header.memsz = 0x3000;
    image.segments[2].data.to_mut().resize(0x3000, 0x77);
    image.segments[3].header.offset = 0x3200;
    image.segments[3].header.vaddr = BASE + 0x3200;
    // Build a raw file first, so that the mapped headers describe the changed segments.
    let built = image.try_build().unwrap();
    let mapped = ElfImage::parse(&built).unwrap().to_mapped_image().unwrap();
    let reader = TestReader::unknown_size(&mapped).with_hole(0x1800..0x1810);
    assert!(ElfImage::read_from_with_options(&reader, 0, ParseOptions::mapped()).is_err());

    let options = ParseOptions::mapped().allow_missing_segment_data();
    let parsed = ElfImage::read_from_with_options(&reader, 0, options).unwrap();
    let data = &parsed.segments[2].data;
    assert_eq!(data.len(), 0x3000);
    assert_eq!(data[..0x1800], mapped[..0x1800]);
    assert!(all_zero(&data[0x1800..0x2000]));
    assert_eq!(data[0x2000..], mapped[0x2000..0x3000]);
    assert_eq!(*parsed.segments[3].data, mapped[0x3200..]);
}

#[test]
fn unsized_mapped_source_reads_large_segment_in_chunks() {
    let mut mapped = ElfImage::parse(&sample(Encoding::ELF64_LE))
        .unwrap()
        .to_mapped_image()
        .unwrap();
    // `p_memsz` of the second `PT_LOAD` segment (program header 3) is 1 GiB.
    let memsz = 64 + 3 * 56 + 40;
    Encoding::ELF64_LE
        .put_u64(&mut mapped, memsz, 1 << 30)
        .unwrap();
    let reader = TestReader::unknown_size(&mapped);
    let image = ElfImage::read_from_with_options(&reader, 0, ParseOptions::mapped()).unwrap();
    // The source ends after `p_filesz`: the segment keeps the bytes that the source has.
    assert_eq!(*image.segments[3].data, mapped[0x1200..]);
    assert!(reader.largest.get() <= 0x1_0000, "{}", reader.largest.get());

    let options = ParseOptions::mapped().allow_missing_segment_data();
    let image = ElfImage::read_from_with_options(&reader, 0, options).unwrap();
    assert_eq!(*image.segments[3].data, mapped[0x1200..]);
    assert!(reader.largest.get() <= 0x1_0000, "{}", reader.largest.get());
}

#[test]
fn unsized_file_source_rejects_large_segment_without_large_reads() {
    let bytes = sample_with(Encoding::ELF64_LE, |_, segments| {
        segments[3].filesz = 1 << 30;
        segments[3].memsz = 1 << 30;
    });
    let reader = TestReader::unknown_size(&bytes);
    let error = ElfImage::read_from(&reader, 0, SourceLayout::File).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::BufferTooSmall { .. }),
        "{error:?}"
    );
    assert!(reader.largest.get() <= 0x1_0000, "{}", reader.largest.get());
}

#[test]
fn non_load_segment_outside_loads_keeps_data() {
    let bytes = sample_with(Encoding::ELF32_BE, |_, segments| {
        segments[3].filesz = 0x20;
        segments[0] = ProgramHeader {
            segment_type: SegmentType::NOTE,
            offset: 0x230,
            vaddr: 0,
            paddr: 0,
            filesz: 0x10,
            memsz: 0,
            ..segments[0]
        };
    });
    let image = ElfImage::parse(&bytes).unwrap();
    assert_eq!(*image.segments[0].data, bytes[0x230..]);
    assert_eq!(*image.segments[3].data, bytes[0x200..0x220]);
    let rebuilt = image.try_build().unwrap();
    assert_eq!(rebuilt[0x230..], bytes[0x230..]);
    assert!(all_zero(&rebuilt[0x220..0x230]));

    let mapped = ElfImage::parse_mapped(&image.to_mapped_image().unwrap())
        .unwrap()
        .into_owned();
    assert_eq!(*mapped.segments[0].data, []);
}

#[test]
fn reads_memory_across_file_size() {
    let bytes = sample(Encoding::ELF64_LE);
    let image = ElfImage::parse(&bytes).unwrap();
    let data = BASE + 0x1200;
    let read = image.read_vaddr(data + 0x30, 0x20).unwrap();
    assert_eq!(read[..0x10], bytes[0x230..]);
    assert!(all_zero(&read[0x10..]));
    assert_eq!(image.read_vaddr(data + 0x1f0, 0x10).unwrap(), [0; 0x10]);
    assert!(matches!(
        image.read_vaddr(data + 0x1f0, 0x20).unwrap_err().kind(),
        ErrorKind::InvalidAddress(_)
    ));
    assert!(image.read_vaddr(BASE + 0x300, 4).is_err());

    assert_eq!(
        image.slice_from_vaddr(data + 0x30).unwrap(),
        &bytes[0x230..]
    );
    assert_eq!(image.slice_from_vaddr(data + 0x100).unwrap(), []);
    assert!(image.slice_from_vaddr(data + 0x200).is_err());
}

#[test]
fn writes_memory_and_grows_data() {
    let bytes = sample(Encoding::ELF64_LE);
    let mut image = ElfImage::parse(&bytes).unwrap();
    let data = BASE + 0x1200;
    image.write_vaddr(data + 0x100, &[1, 2, 3, 4]).unwrap();
    assert_eq!(image.segments[3].data.len(), 0x104);
    assert!(all_zero(&image.segments[3].data[0x40..0x100]));
    assert_eq!(image.read_vaddr(data + 0x100, 4).unwrap(), [1, 2, 3, 4]);

    image.write_vaddr(data, &[9]).unwrap();
    assert_eq!(image.segments[3].data[0], 9);
    assert!(image.write_vaddr(data + 0x1fe, &[1, 2, 3]).is_err());
    assert_eq!(image.segments[3].data.len(), 0x104);
    image.write_vaddr(data + 0x1fe, &[1, 2]).unwrap();
    assert_eq!(image.segments[3].data.len(), 0x200);

    // The raw file keeps only `p_filesz` bytes of each segment.
    let rebuilt = image.try_build().unwrap();
    assert_eq!(rebuilt.len(), bytes.len());
    assert_eq!(rebuilt[0x200], 9);
}

#[test]
fn interpreter_is_optional() {
    let header = FileHeader::new(Encoding::ELF64_LE, FileType::EXEC, Machine::X86_64);
    let image = ElfImage::new(header, Vec::new());
    assert_eq!(image.interpreter().unwrap(), None);
    assert!(image.to_mapped_image().is_err());
    assert_eq!(image.try_build().unwrap(), header.to_bytes().unwrap());

    let bytes = sample_with(Encoding::ELF64_LE, |_, segments| {
        segments[1].vaddr = BASE + 0x8000;
    });
    assert!(ElfImage::parse(&bytes).unwrap().interpreter().is_err());
}

#[test]
fn validation_detects_segment_problems() {
    let overlapping = sample_with(Encoding::ELF64_LE, |_, segments| {
        segments[3].vaddr = BASE + 0x100;
        segments[3].align = 0;
    });
    let result = ElfImage::parse(&overlapping).unwrap().validate();
    assert!(result.contains(ValidationCode::OverlappingSegments));

    let entry = sample_with(Encoding::ELF32_BE, |header, _| header.entry = BASE + 0x1210);
    let result = ElfImage::parse(&entry).unwrap().validate();
    assert!(result.contains(ValidationCode::EntryPointOutOfBounds));

    let misaligned = sample_with(Encoding::ELF64_LE, |_, segments| {
        segments[3].vaddr = BASE + 0x1201;
    });
    let result = ElfImage::parse(&misaligned).unwrap().validate();
    assert!(result.contains(ValidationCode::MisalignedSegment));
}

/// Build an `ET_CORE` file with one `PT_NOTE` segment and no sections. The notes are a
/// `LINUX` note, an `NT_FILE` note and an `NT_AUXV` note.
fn core_file(
    encoding: Encoding,
    page_size: u64,
    mappings: &[FileMapping],
    auxv: &[AuxvEntry],
) -> Vec<u8> {
    let notes = NoteTable {
        notes: vec![
            Note::new(ELF_NOTE_LINUX, NT_AUXV, vec![0xff; 8]),
            Note::new(
                ELF_NOTE_CORE,
                NT_FILE,
                write_nt_file(page_size, mappings, encoding).unwrap(),
            ),
            Note::new(ELF_NOTE_CORE, NT_AUXV, write_auxv(auxv, encoding).unwrap()),
        ],
    }
    .write(encoding, 4)
    .unwrap();
    let mut header = FileHeader::new(encoding, FileType::CORE, Machine::X86_64);
    header.phoff = u64::from(header.ehsize);
    header.phnum = 1;
    let note_offset = header.phoff + u64::from(header.phentsize);
    let segment = ProgramHeader {
        segment_type: SegmentType::NOTE,
        offset: note_offset,
        filesz: to_u64(notes.len()),
        align: 4,
        ..ProgramHeader::default()
    };
    let mut bytes = Vec::new();
    header.write(&mut bytes).unwrap();
    segment.write(&mut bytes, encoding).unwrap();
    assert_eq!(to_u64(bytes.len()), note_offset);
    bytes.extend_from_slice(&notes);
    bytes
}

#[test]
fn core_file_notes() {
    let mappings = [
        FileMapping {
            start: 0x40_0000,
            end: 0x40_1000,
            file_offset: 0,
            path: "/bin/demo".to_string(),
        },
        FileMapping {
            start: 0x60_0000,
            end: 0x60_2000,
            file_offset: 0x2000,
            path: "/lib/libdemo.so".to_string(),
        },
    ];
    let auxv = [
        AuxvEntry {
            key: AT_PAGESZ,
            value: 0x1000,
        },
        AuxvEntry {
            key: AT_ENTRY,
            value: 0x40_0100,
        },
    ];
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let bytes = core_file(encoding, 0x1000, &mappings, &auxv);
        let file = ElfFile::parse(&bytes).unwrap();
        let image = ElfImage::parse(&bytes).unwrap();
        let expected = Some((0x1000, mappings.to_vec()));
        assert_eq!(file.core_file_mappings().unwrap(), expected);
        assert_eq!(image.core_file_mappings().unwrap(), expected);
        assert_eq!(file.auxv().unwrap(), Some(auxv.to_vec()));
        assert_eq!(image.auxv().unwrap(), Some(auxv.to_vec()));
    }

    // A file without core notes gives `None`.
    let image = ElfImage::parse(&sample(Encoding::ELF64_LE))
        .unwrap()
        .into_owned();
    assert_eq!(image.core_file_mappings().unwrap(), None);
    assert_eq!(image.auxv().unwrap(), None);
}
