//! Tests for the boundary values and the errors of the mapped image, the raw file build, the
//! memory accessors and the stream and file I/O.

use super::*;

/// Return a `PT_LOAD` segment at `vaddr` with file offset `offset`, size `memsz` and `data`.
fn load(offset: u64, vaddr: u64, memsz: u64, data: Vec<u8>) -> Segment {
    Segment {
        header: ProgramHeader {
            segment_type: SegmentType::LOAD,
            flags: PF_R | PF_W,
            offset,
            vaddr,
            paddr: vaddr,
            filesz: to_u64(data.len()),
            memsz,
            align: 0x1000,
        },
        data,
    }
}

/// Return an ELF64 image with `segments` and the program header table after the ELF header.
fn image_with(segments: Vec<Segment>) -> ElfImage {
    let mut header = FileHeader::new(Encoding::ELF64_LE, FileType::DYN, Machine::X86_64);
    header.phoff = 64;
    ElfImage::new(header, segments)
}

/// Return a length that the allocator rejects without an allocation: `isize::MAX + 1`.
fn unallocatable() -> usize {
    usize::MAX / 2 + 1
}

#[test]
fn mapped_image_rejects_bad_sizes() {
    let overflow = image_with(vec![
        load(0, 0x1000, 0x100, vec![1; 0x10]),
        load(0x100, u64::MAX - 0x10, 0x100, Vec::new()),
    ]);
    let error = overflow.to_mapped_image().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidSegment(_)),
        "{error:?}"
    );

    let huge = image_with(vec![load(0, 0, to_u64(unallocatable()), Vec::new())]);
    let error = huge.to_mapped_image().unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Generic(_)), "{error:?}");
}

#[test]
fn mapped_image_keeps_zeros_for_segment_without_data() {
    let image = image_with(vec![
        load(0, 0x1000, 0x10, vec![7; 0x10]),
        load(0x10, 0x1010, 0x10, Vec::new()),
    ]);
    let mapped = image.to_mapped_image().unwrap();
    assert_eq!(mapped[..0x10], [7; 0x10]);
    assert!(all_zero(&mapped[0x10..]));
    assert_eq!(mapped.len(), 0x20);
}

#[test]
fn build_rejects_bad_layout() {
    let mut image = image_with(vec![load(0x100, 0x1000, 0x10, vec![1; 0x10])]);
    image.header.phoff = 0;
    let error = image.try_build().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidHeader(_)),
        "{error:?}"
    );
    let mut stream = nostdio::Cursor::new(Vec::new());
    let error = image.write_to(&mut stream).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidHeader(_)),
        "{error:?}"
    );
    assert_eq!(stream.into_inner(), []);

    let image = image_with(vec![load(u64::MAX - 1, 0x1000, 0x10, vec![1; 0x10])]);
    let error = image.try_build().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidSegment(_)),
        "{error:?}"
    );
}

#[test]
fn memory_access_rejects_bad_ranges() {
    let mut image = image_with(vec![load(0, 0, u64::MAX, vec![1; 0x10])]);
    let error = image.read_vaddr(u64::MAX - 1, 4).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidAddress(_)));
    let error = image.write_vaddr(u64::MAX - 1, &[0; 4]).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidAddress(_)));

    // The memory range contains the bytes, but the allocator rejects the size.
    let error = image.read_vaddr(0, unallocatable()).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Generic(_)), "{error:?}");
    let error = image
        .write_vaddr(to_u64(unallocatable()) + 0x10, &[1])
        .unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Generic(_)), "{error:?}");
    assert_eq!(image.segments[0].data, [1; 0x10]);
}

#[test]
fn interpreter_must_be_utf8() {
    let bytes = sample(Encoding::ELF64_LE);
    let mut image = ElfImage::parse(&bytes).unwrap();
    let vaddr = image.segments[1].header.vaddr;
    image.write_vaddr(vaddr, &[0xff, 0xfe]).unwrap();
    let error = image.interpreter().unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidUtf8), "{error:?}");
    assert_eq!(
        error.context().unwrap().structure.as_deref(),
        Some("PT_INTERP")
    );
}

#[test]
fn dynamic_segment_without_data_reads_load_memory() {
    let mut data = vec![0; 0x100];
    // One `DT_DEBUG` entry at 0x1080, then `DT_NULL`.
    data[0x80] = 21;
    data[0x88] = 0x42;
    let mut image = image_with(vec![load(0, 0x1000, 0x100, data)]);
    let dynamic = |vaddr| Segment {
        header: ProgramHeader {
            segment_type: SegmentType::DYNAMIC,
            vaddr,
            memsz: 0x20,
            ..ProgramHeader::default()
        },
        data: Vec::new(),
    };
    image.segments.push(dynamic(0x1080));
    let table = image.dynamic().unwrap().unwrap();
    assert_eq!(table.entries.len(), 1);
    assert_eq!(table.entries[0].value, 0x42);

    image.segments[1] = dynamic(0x8000);
    let error = image.dynamic().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidAddress(0x8000)),
        "{error:?}"
    );
    assert_eq!(
        error.context().unwrap().structure,
        Some(format!("{}", SegmentType::DYNAMIC))
    );
}

#[test]
fn reads_from_seekable_stream() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let bytes = sample(encoding);
        let reader =
            crate::SeekReader::with_discovered_size(nostdio::Cursor::new(bytes.clone())).unwrap();
        let image = ElfImage::read_from(&reader, 0, SourceLayout::File).unwrap();
        assert_eq!(image, ElfImage::parse(&bytes).unwrap());
        let headers = crate::ElfHeaders::read_from(&reader, 0, SourceLayout::File).unwrap();
        assert_eq!(headers, image.headers());
    }
}

#[cfg(feature = "std")]
#[test]
fn file_io_reports_missing_paths() {
    let directory = std::env::temp_dir().join(format!(
        "elfex-image-file-io-{}-missing",
        std::process::id()
    ));
    let path = directory.join("image.elf");
    assert!(matches!(
        ElfImage::from_file(&path).unwrap_err().kind(),
        ErrorKind::Io(_)
    ));
    assert!(matches!(
        crate::ElfHeaders::from_file(&path).unwrap_err().kind(),
        ErrorKind::Io(_)
    ));
    let image = ElfImage::parse(&sample(Encoding::ELF64_LE)).unwrap();
    assert!(matches!(
        image.write_to_file(&path).unwrap_err().kind(),
        ErrorKind::Io(_)
    ));
    assert!(!directory.exists());
}
