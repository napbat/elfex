use super::*;

/// Return `elf` with `count` program headers: the headers of `elf` and `PT_NULL` headers. The
/// program header table goes to a free file offset after the end of the file.
fn with_program_headers(mut elf: ElfFile, count: usize) -> ElfFile {
    let null = ProgramHeader {
        segment_type: SegmentType::NULL,
        offset: 0,
        filesz: 0,
        ..elf.program_headers()[0]
    };
    elf.program_headers_mut().resize(count, null);
    let end = u64::try_from(elf.len()).unwrap();
    elf.header_mut().phoff = end.next_multiple_of(8) + 0x1000;
    elf
}

#[test]
fn repairs_entry_sizes_below_the_structure_size() {
    for encoding in ENCODINGS {
        let mut elf = sample(encoding);
        let header = elf.header_mut();
        header.phentsize = 0;
        header.shentsize = 0;
        let parsed = rebuild(&elf);
        let class = encoding.class;
        assert_eq!(
            usize::from(parsed.header().phentsize),
            ProgramHeader::size(class)
        );
        assert_eq!(
            usize::from(parsed.header().shentsize),
            SectionHeader::size(class)
        );
        assert_eq!(parsed.program_headers(), elf.program_headers());
        assert_eq!(parsed.section_headers(), elf.section_headers());
    }
}

#[test]
fn rejects_program_headers_without_e_phoff() {
    let mut elf = sample(Encoding::ELF64_LE);
    elf.header_mut().phoff = 0;
    assert!(matches!(
        error_kind(elf.try_build()),
        ErrorKind::InvalidSegment(_)
    ));
}

#[test]
fn builds_a_file_without_program_headers() {
    let mut elf = sample(Encoding::ELF32_LE);
    let phnum = elf.header().phnum;
    elf.program_headers_mut().clear();
    elf.header_mut().phoff = 0;
    let parsed = ElfFile::parse(&elf.try_build().unwrap()).unwrap();
    assert_eq!(parsed.program_headers(), []);
    // An `e_phoff` of 0 gives no program headers, so the build keeps `e_phnum`.
    assert_eq!((parsed.header().phoff, parsed.header().phnum), (0, phnum));
    assert_eq!(parsed.section_headers(), elf.section_headers());
}

#[test]
fn leaves_extended_program_numbering_for_fewer_headers() {
    let mut elf = sample(Encoding::ELF64_LE);
    let phnum = u32::try_from(elf.program_headers().len()).unwrap();
    elf.header_mut().phnum = PN_XNUM;
    elf.section_headers_mut()[0].info = phnum;
    let mut parsed = rebuild(&elf);
    assert_eq!(parsed.header().phnum, PN_XNUM);
    let removed = parsed.program_headers_mut().pop().unwrap();
    assert_eq!(removed.segment_type, SegmentType::GNU_STACK);
    let rebuilt = ElfFile::parse(&parsed.try_build().unwrap()).unwrap();
    assert_eq!(u32::from(rebuilt.header().phnum), phnum - 1);
    assert_eq!(rebuilt.section_headers()[0].info, 0);
    assert_eq!(rebuilt.program_headers(), parsed.program_headers());
}

#[test]
fn uses_pn_xnum_for_many_program_headers() {
    let elf = with_program_headers(sample(Encoding::ELF64_LE), usize::from(PN_XNUM));
    let parsed = ElfFile::parse(&elf.try_build().unwrap()).unwrap();
    assert_eq!(parsed.header().phnum, PN_XNUM);
    assert_eq!(parsed.section_headers()[0].info, u32::from(PN_XNUM));
    assert_eq!(parsed.program_headers(), elf.program_headers());

    // Without section header 0, the file cannot give the count.
    let mut stripped = elf;
    stripped.section_headers_mut().clear();
    stripped.header_mut().shoff = 0;
    assert!(matches!(
        error_kind(stripped.try_build()),
        ErrorKind::ValueOutOfRange(_)
    ));
}

#[test]
fn moves_a_section_table_without_offset_to_the_end_of_the_data() {
    let elf = sample(Encoding::ELF32_BE);
    let mut moved = with_program_headers(elf.clone(), elf.program_headers().len());
    moved.header_mut().shoff = 0;
    let parsed = ElfFile::parse(&moved.try_build().unwrap()).unwrap();
    let end = u64::try_from(elf.len()).unwrap();
    assert_eq!(parsed.header().shoff, end.next_multiple_of(4));
    assert_eq!(parsed.header().phoff, moved.header().phoff);
    assert_eq!(parsed.section_headers(), elf.section_headers());
    assert_eq!(parsed.program_headers(), elf.program_headers());
}

#[test]
fn rejects_values_that_do_not_fit_in_elf32() {
    let mut segment = sample(Encoding::ELF32_LE);
    segment.program_headers_mut()[2].offset = 1 << 40;
    assert!(matches!(
        error_kind(segment.try_build()),
        ErrorKind::ValueOutOfRange(_)
    ));
    let mut section = sample(Encoding::ELF32_LE);
    section.section_headers_mut()[2].addr = 1 << 40;
    assert!(matches!(
        error_kind(section.try_build()),
        ErrorKind::ValueOutOfRange(_)
    ));
}

#[test]
fn rejects_a_program_table_past_the_address_space() {
    // The first end overflows `u64`. The second end is past `isize::MAX`.
    for phoff in [u64::MAX - 8, 1 << 63] {
        let mut elf = sample(Encoding::ELF64_LE);
        elf.header_mut().phoff = phoff;
        assert!(matches!(error_kind(elf.try_build()), ErrorKind::Generic(_)));
    }
}
