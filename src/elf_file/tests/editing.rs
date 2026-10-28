use super::*;
use crate::section::SHN_LORESERVE;

/// Return the index of the last `PT_LOAD` program header.
fn last_load(elf: &ElfFile) -> usize {
    elf.program_headers()
        .iter()
        .rposition(ProgramHeader::is_load)
        .unwrap()
}

/// Add `shift` to the virtual and physical addresses of all `PT_LOAD` segments.
fn shift_loads(elf: &mut ElfFile, shift: u64) {
    for segment in elf
        .program_headers_mut()
        .iter_mut()
        .filter(|segment| segment.is_load())
    {
        segment.vaddr += shift;
        segment.paddr += shift;
    }
}

#[test]
fn rejects_invalid_new_sections() {
    let mut elf = sample(Encoding::ELF64_LE);
    let named = NewSection::new(".a\0b", SectionType::PROGBITS, Vec::new());
    assert!(matches!(
        error_kind(elf.add_section(named)),
        ErrorKind::InvalidSection(_)
    ));
    for (section_type, flags) in [(SectionType::PROGBITS, 0), (SectionType::STRTAB, SHF_ALLOC)] {
        let mut broken = elf.clone();
        let table = &mut broken.section_headers_mut()[8];
        table.section_type = section_type;
        table.flags = flags;
        let section = NewSection::new(".x", SectionType::PROGBITS, vec![1]);
        assert!(matches!(
            error_kind(broken.add_section(section)),
            ErrorKind::InvalidSection(_)
        ));
    }
    // An `e_shstrndx` of 0 or out of range gives no section name string table.
    for shstrndx in [0, 99] {
        let mut missing = elf.clone();
        missing.header_mut().shstrndx = shstrndx;
        let section = NewSection::new(".x", SectionType::PROGBITS, vec![1]);
        assert!(matches!(
            error_kind(missing.add_section(section)),
            ErrorKind::InvalidSection(_)
        ));
    }
}

#[test]
fn adds_an_empty_nobits_section_at_the_end_of_the_file() {
    let mut elf = sample(Encoding::ELF32_LE);
    let index = elf
        .add_section(NewSection::new(".tbss", SectionType::NOBITS, Vec::new()))
        .unwrap();
    let header = elf.section_headers()[index];
    assert_eq!(
        (header.offset, header.size),
        (u64::try_from(elf.len()).unwrap(), 0)
    );
    let parsed = rebuild(&elf);
    let section = parsed.section(index).unwrap();
    assert_eq!(
        (section.name, section.header.section_type, section.data),
        (".tbss", SectionType::NOBITS, &[][..])
    );
}

#[test]
fn adds_a_name_to_a_name_table_without_a_final_nul() {
    let mut elf = sample(Encoding::ELF64_BE);
    let mut names = elf.section_names().to_vec();
    elf.section_headers_mut()[8].size -= 1;
    let index = elf
        .add_section(NewSection::new(".extra", SectionType::PROGBITS, vec![1]))
        .unwrap();
    names.push(".extra".into());
    let parsed = rebuild(&elf);
    assert_eq!(parsed.section_names()[index], ".extra");
    assert_eq!(parsed.section_names(), names);
}

#[test]
fn keeps_the_bytes_of_a_removed_section_in_a_segment() {
    let mut elf = sample(Encoding::ELF64_LE);
    elf.remove_section(1).unwrap();
    assert_eq!(elf.section_names()[1], ".text");
    let parsed = rebuild(&elf);
    assert_eq!(parsed.interpreter().unwrap().as_deref(), Some("/lib/ld.so"));
}

#[test]
fn removes_a_section_below_an_extended_name_table_index() {
    let mut elf = sample(Encoding::ELF64_LE);
    let shstrtab = elf.section_headers()[8];
    let padding = SectionHeader {
        section_type: SectionType::PROGBITS,
        ..SectionHeader::default()
    };
    let headers = elf.section_headers_mut();
    headers.resize(headers.len() + usize::from(SHN_LORESERVE), padding);
    headers.push(shstrtab);
    let index = headers.len() - 1;
    headers[0].link = u32::try_from(index).unwrap();
    elf.header_mut().shstrndx = SHN_XINDEX;

    elf.remove_section(5).unwrap();
    let parsed = ElfFile::parse(&elf.try_build().unwrap()).unwrap();
    let count = parsed.section_headers().len();
    assert_eq!(count, index);
    assert_eq!(
        (parsed.header().shnum, parsed.header().shstrndx),
        (0, SHN_XINDEX)
    );
    let zero = parsed.section_headers()[0];
    assert_eq!(
        (zero.size, zero.link),
        (
            u64::try_from(count).unwrap(),
            u32::try_from(count - 1).unwrap()
        )
    );
    assert_eq!(parsed.section_names()[count - 1], ".shstrtab");
    assert_eq!(parsed.section_names()[5], ".ref");
}

#[test]
fn moves_a_program_table_that_cannot_grow() {
    let mut grown = sample(Encoding::ELF64_LE);
    grown.add_load_segment(PF_R, vec![1], 0).unwrap();
    let phoff = grown.header().phoff;
    let entries = u64::try_from(grown.program_headers().len()).unwrap();
    let table_size = entries * u64::from(grown.header().phentsize);
    let file_size = u64::try_from(grown.len()).unwrap();
    let stack = grown
        .program_headers()
        .iter()
        .position(|segment| segment.segment_type == SegmentType::GNU_STACK)
        .unwrap();
    let edits: [&dyn Fn(&mut ElfFile); 4] = [
        // The table goes past the end of the file.
        &|elf| elf.header_mut().phoff = file_size,
        // The end of a larger table overflows.
        &|elf| elf.header_mut().phoff = u64::MAX - table_size,
        // The file range of a segment overflows.
        &|elf| {
            let segment = &mut elf.program_headers_mut()[stack];
            segment.offset = u64::MAX;
            segment.filesz = 1;
        },
        // The entry size is too small.
        &|elf| elf.header_mut().phentsize = 0,
    ];
    for edit in edits {
        let mut elf = grown.clone();
        edit(&mut elf);
        let vaddr = elf.add_load_segment(PF_R, vec![2], 0).unwrap();
        assert_ne!(elf.header().phoff, phoff);
        assert_eq!(
            usize::from(elf.header().phentsize),
            ProgramHeader::size(elf.encoding().class)
        );
        let parsed = ElfFile::parse(&elf.try_build().unwrap()).unwrap();
        assert_eq!(parsed.read_vaddr(vaddr, 1).unwrap(), [2]);
    }
}

#[test]
fn rejects_a_program_table_move_that_does_not_fit() {
    let elf = plain(0x1000, 0);
    let last = last_load(&elf);
    let add = |mut elf: ElfFile| error_kind(elf.add_load_segment(PF_R, vec![1], 0));

    let mut unbounded = elf.clone();
    unbounded.program_headers_mut()[last].memsz = u64::MAX;
    assert!(matches!(add(unbounded), ErrorKind::InvalidSegment(_)));

    let mut high = elf.clone();
    let end = high.headers().image_end().unwrap();
    shift_loads(&mut high, (u64::MAX - end) & !0xfff);
    assert!(matches!(add(high), ErrorKind::ValueOutOfRange(_)));

    let mut elf32 = sample(Encoding::ELF32_LE);
    let end = elf32.headers().image_end().unwrap();
    shift_loads(&mut elf32, ((1 << 32) - end) & !0xfff);
    assert!(matches!(add(elf32), ErrorKind::ValueOutOfRange(_)));

    // A section past the end of the file covers the new table.
    let mut covered = elf.clone();
    let file_size = u64::try_from(covered.len()).unwrap();
    let data = &mut covered.section_headers_mut()[3];
    data.offset = file_size;
    data.size = 1 << 32;
    assert!(matches!(add(covered), ErrorKind::InvalidSegment(_)));

    // The file must grow past `isize::MAX` bytes.
    let mut huge = elf;
    huge.program_headers_mut()[last].memsz = 1 << 63;
    assert!(matches!(add(huge), ErrorKind::Generic(_)));
}

#[test]
fn rejects_a_load_segment_at_the_end_of_the_address_space() {
    let mut elf = plain(0x1000, 0);
    elf.add_load_segment(PF_R, vec![1], 0).unwrap();
    let last = last_load(&elf);
    let add = |mut elf: ElfFile| error_kind(elf.add_load_segment(PF_R, vec![1], 0));

    let mut unbounded = elf.clone();
    unbounded.program_headers_mut()[last].memsz = u64::MAX;
    assert!(matches!(add(unbounded), ErrorKind::InvalidSegment(_)));

    let mut high = elf;
    let segment = &mut high.program_headers_mut()[last];
    segment.vaddr = u64::MAX - 0x10;
    segment.memsz = 0x10;
    assert!(matches!(add(high), ErrorKind::ValueOutOfRange(_)));
}
