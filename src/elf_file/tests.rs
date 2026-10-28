use super::*;
use crate::ElfImage;
use crate::ErrorKind;
use crate::builder::{BuilderSection, ElfBuilder};
use crate::program::{PF_R, PF_W, PF_X, SegmentType};
use crate::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_INFO_LINK, SHF_WRITE};
use crate::validation::ValidationCode;

const ENCODINGS: [Encoding; 4] = [
    Encoding::ELF32_LE,
    Encoding::ELF32_BE,
    Encoding::ELF64_LE,
    Encoding::ELF64_BE,
];

/// Build a sample executable. The sections are:
///
/// 0 null, 1 `.interp`, 2 `.text`, 3 `.data`, 4 `.bss`, 5 `.comment`, 6 `.ref` (link 2,
/// info 7), 7 `.target`, 8 `.shstrtab`.
fn sample(encoding: Encoding) -> ElfFile {
    ElfBuilder::new(encoding)
        .machine(Machine::X86_64)
        .interpreter("/lib/ld.so")
        .add_section(BuilderSection {
            addralign: 16,
            ..BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0xc3; 32])
        })
        .add_section(BuilderSection {
            addralign: 8,
            ..BuilderSection::progbits(".data", SHF_ALLOC | SHF_WRITE, (0..64).collect())
        })
        .add_section(BuilderSection::nobits(".bss", SHF_ALLOC | SHF_WRITE, 0x100))
        .add_section(BuilderSection::progbits(
            ".comment",
            0,
            b"compiler 1.0\0".to_vec(),
        ))
        .add_section(BuilderSection {
            link_name: Some(".text".into()),
            info: 7,
            flags: SHF_INFO_LINK,
            ..BuilderSection::progbits(".ref", 0, vec![1, 2, 3, 4])
        })
        .add_section(BuilderSection::progbits(".target", 0, vec![5; 8]))
        .entry_in_section(".text", 0)
        .build()
}

/// Build `elf`, parse the output, and check the round trip and the validation.
fn rebuild(elf: &ElfFile) -> ElfFile {
    let bytes = elf.try_build().unwrap();
    let parsed = ElfFile::parse(&bytes).unwrap();
    assert_eq!(parsed.try_build().unwrap(), bytes);
    let result = parsed.validate();
    assert!(!result.has_errors(), "{result:?}");
    parsed
}

/// Check that `PT_PHDR` is the first program header, describes the table at `e_phoff`, and
/// that a `PT_LOAD` segment maps the table.
fn check_phdr(elf: &ElfFile) {
    let header = elf.header();
    let phdr = elf.program_headers()[0];
    assert_eq!(phdr.segment_type, SegmentType::PHDR);
    assert_eq!(phdr.offset, header.phoff);
    let size = u64::try_from(elf.program_headers().len()).unwrap() * u64::from(header.phentsize);
    assert_eq!((phdr.filesz, phdr.memsz), (size, size));
    assert!(elf.headers().load_segments().any(|load| {
        load.offset <= header.phoff
            && header.phoff + size <= load.offset + load.filesz
            && load.vaddr + (header.phoff - load.offset) == phdr.vaddr
    }));
    let vaddrs: Vec<u64> = elf
        .headers()
        .load_segments()
        .map(|load| load.vaddr)
        .collect();
    assert!(
        vaddrs.windows(2).all(|pair| pair[0] < pair[1]),
        "{vaddrs:x?}"
    );
}

#[test]
fn round_trips_builder_output() {
    for encoding in ENCODINGS {
        let elf = sample(encoding);
        let bytes = elf.try_build().unwrap();
        assert_eq!(bytes, elf.as_bytes());
        let parsed = ElfFile::parse(&bytes).unwrap();
        assert_eq!(parsed, elf);
        assert_eq!(parsed.build(), bytes);

        let mut shifted = vec![0xee; 16];
        shifted.extend_from_slice(&bytes);
        let read = ElfFile::read_from(&SliceReader::new(&shifted), 16).unwrap();
        assert_eq!(read, elf);
        assert_eq!(ElfFile::from_vec(bytes.clone()).unwrap(), elf);
    }
}

#[test]
fn rejects_malformed_input() {
    let bytes = sample(Encoding::ELF64_LE).build();
    assert!(ElfFile::parse(&[]).is_err());
    assert!(ElfFile::parse(&bytes[..10]).is_err());
    assert!(ElfFile::parse(&bytes[..40]).is_err());
    let reader = SliceReader::new(&bytes);
    let past_end = u64::try_from(bytes.len()).unwrap() + 1;
    assert!(matches!(
        ElfFile::read_from(&reader, past_end).unwrap_err().kind,
        ErrorKind::OffsetOutOfBounds { .. }
    ));
}

#[test]
fn round_trips_extended_numbering() {
    let mut elf = sample(Encoding::ELF64_LE);
    let phnum = u32::try_from(elf.program_headers().len()).unwrap();
    let shnum = elf.section_headers().len();
    let header = elf.header_mut();
    header.phnum = PN_XNUM;
    header.shnum = 0;
    header.shstrndx = SHN_XINDEX;
    let zero = &mut elf.section_headers_mut()[0];
    zero.info = phnum;
    zero.size = u64::try_from(shnum).unwrap();
    zero.link = 8;
    let parsed = rebuild(&elf);
    assert_eq!((parsed.header().phnum, parsed.header().shnum), (PN_XNUM, 0));
    assert_eq!(parsed.header().shstrndx, SHN_XINDEX);
    assert_eq!(parsed.program_headers(), elf.program_headers());
    assert_eq!(parsed.section_headers(), elf.section_headers());
    assert_eq!(parsed.section_names(), elf.section_names());

    // An edit that keeps the counts keeps the extended form.
    let mut edited = parsed.clone();
    edited.set_entry_point(parsed.entry_point() + 1);
    let rebuilt = rebuild(&edited);
    assert_eq!(
        (rebuilt.header().phnum, rebuilt.header().shnum),
        (PN_XNUM, 0)
    );
    assert_eq!(rebuilt.entry_point(), parsed.entry_point() + 1);

    // A removal changes the section count: the build uses the normal form for it.
    let comment = *edited.section_by_name(".comment").unwrap().header;
    edited.remove_section(5).unwrap();
    let removed = rebuild(&edited);
    assert_eq!(
        (removed.header().phnum, removed.header().shnum),
        (PN_XNUM, 8)
    );
    assert_eq!(removed.header().shstrndx, 7);
    let zero = removed.section_headers()[0];
    assert_eq!((zero.size, zero.link, zero.info), (0, 0, phnum));
    assert_eq!(
        removed.section_names(),
        [
            "",
            ".interp",
            ".text",
            ".data",
            ".bss",
            ".ref",
            ".target",
            ".shstrtab"
        ]
    );
    let comment_len = usize::try_from(comment.size).unwrap();
    assert_eq!(
        removed.bytes_at(comment.offset, comment_len).unwrap(),
        vec![0; comment_len]
    );
}

#[test]
fn reads_sections_and_segments() {
    let mut elf = sample(Encoding::ELF32_LE);
    assert_eq!(elf.sections().count(), 9);
    assert_eq!(elf.len(), elf.as_bytes().len());
    assert!(!elf.is_empty());
    let target = elf.section_by_name(".target").unwrap();
    assert_eq!((target.index, target.data), (7, &[5u8; 8][..]));
    assert_eq!(
        elf.section_by_type(SectionType::NOBITS).unwrap().name,
        ".bss"
    );
    assert_eq!(elf.section_data(4).unwrap(), []);
    assert!(elf.section(99).is_none());
    assert!(matches!(
        elf.section_data(99).unwrap_err().kind,
        ErrorKind::InvalidSection(_)
    ));
    assert!(matches!(
        elf.segment_data(99).unwrap_err().kind,
        ErrorKind::InvalidSegment(_)
    ));
    let end = u64::try_from(elf.len()).unwrap();
    assert!(matches!(
        elf.bytes_at(end, 1).unwrap_err().kind,
        ErrorKind::OffsetOutOfBounds { .. }
    ));
    elf.section_data_mut(7).unwrap().fill(6);
    assert_eq!(elf.section_data(7).unwrap(), [6; 8]);
    elf.bytes_at_mut(target_offset(&elf, 7), 1).unwrap()[0] = 9;
    assert_eq!(elf.section_data(7).unwrap()[0], 9);

    elf.section_headers_mut()[7].offset = 1 << 40;
    assert_eq!(elf.section(7).unwrap().data, []);
    assert!(matches!(
        elf.section_data(7).unwrap_err().kind,
        ErrorKind::OffsetOutOfBounds { .. }
    ));
}

/// Return the file offset of section `index`.
fn target_offset(elf: &ElfFile, index: usize) -> u64 {
    elf.section_headers()[index].offset
}

#[test]
fn reads_and_writes_virtual_addresses() {
    let mut elf = sample(Encoding::ELF64_BE);
    let data = *elf.section_by_name(".data").unwrap().header;
    let bss = *elf.section_by_name(".bss").unwrap().header;
    let expected: Vec<u8> = (0..64).collect();
    assert_eq!(elf.read_vaddr(data.addr, 64).unwrap(), expected);
    elf.write_vaddr(data.addr + 8, &[0xee; 4]).unwrap();
    assert_eq!(elf.section_data(3).unwrap()[8..12], [0xee; 4]);
    assert_eq!(
        elf.slice_from_vaddr(data.addr + 60).unwrap(),
        [60, 61, 62, 63]
    );

    let invalid = |error: Error| matches!(error.kind, ErrorKind::InvalidAddress(_));
    assert!(invalid(elf.read_vaddr(data.addr + 60, 8).unwrap_err()));
    assert!(invalid(elf.read_vaddr(bss.addr, 1).unwrap_err()));
    assert!(invalid(elf.read_vaddr(0x10, 1).unwrap_err()));
    assert!(invalid(elf.slice_from_vaddr(bss.addr).unwrap_err()));
    assert!(invalid(elf.write_vaddr(bss.addr, &[1]).unwrap_err()));
    let parsed = rebuild(&elf);
    assert_eq!(parsed.read_vaddr(data.addr + 8, 4).unwrap(), [0xee; 4]);
}

#[test]
fn sets_section_data() {
    let mut elf = sample(Encoding::ELF32_BE);
    let old = *elf.section_by_name(".comment").unwrap().header;
    elf.set_section_data(5, b"abc".to_vec()).unwrap();
    assert_eq!(elf.section_data(5).unwrap(), b"abc");
    let old_len = usize::try_from(old.size).unwrap();
    let mut expected = b"abc".to_vec();
    expected.resize(old_len, 0);
    assert_eq!(elf.bytes_at(old.offset, old_len).unwrap(), expected);
    let shrunk = rebuild(&elf);
    assert_eq!(shrunk.section_data(5).unwrap(), b"abc");

    // A larger non-SHF_ALLOC section goes after the section header table at the file end.
    let shoff = elf.header().shoff;
    let file_len = u64::try_from(elf.len()).unwrap();
    elf.set_section_data(5, vec![0x55; 100]).unwrap();
    assert!(elf.section_headers()[5].offset >= file_len);
    assert_eq!(elf.bytes_at(old.offset, 3).unwrap(), [0; 3]);
    let grown = rebuild(&elf);
    assert_eq!(grown.header().shoff, shoff);
    assert_eq!(grown.section_data(5).unwrap(), [0x55; 100]);

    // The section name table can grow, and the names stay.
    let mut names = elf.section_data(8).unwrap().to_vec();
    names.extend_from_slice(b"unused\0");
    let before = elf.section_names().to_vec();
    elf.set_section_data(8, names).unwrap();
    assert_eq!(elf.section_names(), before);
    assert_eq!(rebuild(&elf).section_names(), before);
}

#[test]
fn rejects_invalid_section_data() {
    let mut elf = sample(Encoding::ELF64_LE);
    let kind = |result: Result<()>| result.unwrap_err().kind;
    assert!(matches!(
        kind(elf.set_section_data(3, vec![0; 1000])),
        ErrorKind::InvalidSection(_)
    ));
    assert!(matches!(
        kind(elf.set_section_data(4, vec![1])),
        ErrorKind::InvalidSection(_)
    ));
    assert!(matches!(
        kind(elf.set_section_data(0, Vec::new())),
        ErrorKind::InvalidSection(_)
    ));
    assert!(matches!(
        kind(elf.set_section_data(99, Vec::new())),
        ErrorKind::InvalidSection(_)
    ));

    // A SHF_ALLOC section can shrink in place.
    let data = *elf.section_by_name(".data").unwrap().header;
    elf.set_section_data(3, vec![9; 8]).unwrap();
    assert_eq!(
        elf.read_vaddr(data.addr, 9).unwrap(),
        [9, 9, 9, 9, 9, 9, 9, 9, 0]
    );
    elf.set_section_data(4, Vec::new()).unwrap();
    assert_eq!(elf.section_headers()[4].size, 0);
    rebuild(&elf);
}

#[test]
fn adds_a_section_to_a_section_table() {
    let mut elf = sample(Encoding::ELF64_BE);
    let count = elf.section_headers().len();
    let shoff = elf.header().shoff;
    let mut section = NewSection::new(".note.extra", SectionType::NOTE, (1..=8).collect());
    section.addralign = 4;
    let index = elf.add_section(section).unwrap();
    assert_eq!(index, count);
    assert_eq!(elf.section_names()[index], ".note.extra");
    let parsed = rebuild(&elf);
    assert_ne!(parsed.header().shoff, shoff);
    assert_eq!(parsed.header().shoff % 8, 0);
    assert_eq!(parsed.section_names(), elf.section_names());
    let added = parsed.section_by_name(".note.extra").unwrap();
    assert_eq!(added.data, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(added.header.offset % 4, 0);

    let alloc = NewSection {
        flags: SHF_ALLOC,
        ..NewSection::new(".x", SectionType::PROGBITS, vec![1])
    };
    assert!(matches!(
        elf.add_section(alloc).unwrap_err().kind,
        ErrorKind::InvalidSection(_)
    ));
    let nobits = NewSection::new(".y", SectionType::NOBITS, vec![1]);
    assert!(matches!(
        elf.add_section(nobits).unwrap_err().kind,
        ErrorKind::InvalidSection(_)
    ));
}

#[test]
fn adds_a_section_to_a_file_without_section_table() {
    for encoding in ENCODINGS {
        let mut elf = sample(encoding);
        let header = elf.header_mut();
        header.shoff = 0;
        header.shnum = 0;
        header.shstrndx = 0;
        elf.section_headers_mut().clear();
        let mut stripped = ElfFile::parse(&elf.try_build().unwrap()).unwrap();
        assert_eq!(stripped.section_headers(), []);

        let index = stripped
            .add_section(NewSection::new(
                ".comment",
                SectionType::PROGBITS,
                b"hi\0".to_vec(),
            ))
            .unwrap();
        assert_eq!(index, 2);
        let parsed = rebuild(&stripped);
        assert_eq!(parsed.section_names(), ["", ".shstrtab", ".comment"]);
        assert_eq!(parsed.header().shstrndx, 1);
        assert_eq!(parsed.section_data(2).unwrap(), b"hi\0");
    }
}

#[test]
fn keeps_an_unreadable_section_table() {
    // Point `e_shoff` (offset 32 in `Elf32_Ehdr`) past the end of the file.
    let mut bytes = sample(Encoding::ELF32_LE).build();
    Encoding::ELF32_LE
        .put_u32(&mut bytes, 32, 0x7fff_0000)
        .unwrap();
    let mut parsed = ElfFile::parse(&bytes).unwrap();
    assert_eq!(parsed.section_headers(), []);
    assert_eq!(parsed.try_build().unwrap(), bytes);
    let section = NewSection::new(".comment", SectionType::PROGBITS, Vec::new());
    assert!(matches!(
        parsed.add_section(section).unwrap_err().kind,
        ErrorKind::InvalidSection(_)
    ));
}

#[test]
fn removes_a_section() {
    let mut elf = sample(Encoding::ELF32_LE);
    let invalid =
        |result: Result<()>| matches!(result.unwrap_err().kind, ErrorKind::InvalidSection(_));
    assert!(invalid(elf.remove_section(0)));
    assert!(invalid(elf.remove_section(99)));
    assert!(invalid(elf.remove_section(8)));
    assert!(invalid(elf.remove_section(7)));
    assert!(invalid(elf.remove_section(2)));

    let comment = *elf.section_by_name(".comment").unwrap().header;
    elf.remove_section(5).unwrap();
    assert_eq!(
        elf.section_names(),
        [
            "",
            ".interp",
            ".text",
            ".data",
            ".bss",
            ".ref",
            ".target",
            ".shstrtab"
        ]
    );
    let reference = elf.section_headers()[5];
    assert_eq!((reference.link, reference.info), (2, 6));
    assert_eq!(elf.header().shstrndx, 7);
    let parsed = rebuild(&elf);
    assert_eq!(parsed.section_names(), elf.section_names());
    assert_eq!(parsed.header().shnum, 8);
    assert_eq!(parsed.bytes_at(comment.offset, 4).unwrap(), [0; 4]);
}

#[test]
fn removes_only_the_last_section_with_a_symbol_table() {
    let mut elf = sample(Encoding::ELF64_LE);
    let index = elf
        .add_section(NewSection::new(".symtab", SectionType::SYMTAB, vec![0; 24]))
        .unwrap();
    assert!(matches!(
        elf.remove_section(5).unwrap_err().kind,
        ErrorKind::InvalidSection(_)
    ));
    elf.remove_section(index).unwrap();
    elf.remove_section(5).unwrap();
    rebuild(&elf);
}

#[test]
fn adds_load_segments() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        let mut elf = sample(encoding);
        let phoff = elf.header().phoff;
        let vaddr = elf
            .add_load_segment(PF_R | PF_W, vec![0xab; 100], 0)
            .unwrap();
        assert_ne!(elf.header().phoff, phoff);
        let parsed = rebuild(&elf);
        check_phdr(&parsed);
        assert_eq!(parsed.read_vaddr(vaddr, 100).unwrap(), [0xab; 100]);
        let segment = parsed
            .headers()
            .load_segments()
            .find(|load| load.vaddr == vaddr)
            .unwrap();
        assert_eq!(
            (segment.flags, segment.align, segment.offset % 0x1000),
            (PF_R | PF_W, 0x1000, 0)
        );

        // The relocated table has free entries: the next segment does not move it.
        let mut again = parsed.clone();
        let phoff = again.header().phoff;
        let second = again
            .add_load_segment(PF_R | PF_X, vec![0xcc; 10], 0x2000)
            .unwrap();
        assert_eq!(again.header().phoff, phoff);
        assert_eq!(second % 0x2000, 0);
        let reparsed = rebuild(&again);
        check_phdr(&reparsed);
        assert_eq!(reparsed.read_vaddr(second, 10).unwrap(), [0xcc; 10]);
        assert_eq!(reparsed.read_vaddr(vaddr, 100).unwrap(), [0xab; 100]);
    }
}

#[test]
fn rejects_invalid_load_segments() {
    let mut elf = sample(Encoding::ELF64_LE);
    let error = elf.add_load_segment(PF_R, vec![1], 0x300).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSegment(_)));
    let mut no_loads = elf.clone();
    no_loads
        .program_headers_mut()
        .retain(|segment| !segment.is_load());
    let error = no_loads.add_load_segment(PF_R, vec![1], 0).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSegment(_)));

    // A program header table that grows without a relocation overlaps `.interp`.
    let null = ProgramHeader {
        segment_type: SegmentType::NULL,
        ..elf.program_headers()[0]
    };
    elf.program_headers_mut().push(null);
    assert!(matches!(
        elf.try_build().unwrap_err().kind,
        ErrorKind::InvalidSegment(_)
    ));
}

#[test]
fn sets_the_interpreter_in_place() {
    let mut elf = sample(Encoding::ELF64_LE);
    let interp = *elf.headers().segment(SegmentType::INTERP).unwrap();
    elf.set_interpreter("/lib/a.so").unwrap();
    let parsed = rebuild(&elf);
    let segment = parsed.headers().segment(SegmentType::INTERP).unwrap();
    assert_eq!(
        (segment.offset, segment.filesz, segment.memsz),
        (interp.offset, 10, 10)
    );
    assert_eq!(
        parsed.bytes_at(interp.offset, 11).unwrap(),
        b"/lib/a.so\0\0"
    );
    let section = parsed.section_by_name(".interp").unwrap();
    assert_eq!(section.data, b"/lib/a.so\0");
}

#[test]
fn sets_a_longer_interpreter() {
    for encoding in [Encoding::ELF64_BE, Encoding::ELF32_LE] {
        let mut elf = sample(encoding);
        let old = *elf.headers().segment(SegmentType::INTERP).unwrap();
        let path = format!("{}ld.so", "/very/long/path".repeat(8));
        elf.set_interpreter(&path).unwrap();
        let parsed = rebuild(&elf);
        check_phdr(&parsed);
        let interp = *parsed.headers().segment(SegmentType::INTERP).unwrap();
        assert_ne!(interp.offset, old.offset);
        let mut expected = path.into_bytes();
        expected.push(0);
        let len = expected.len();
        assert_eq!(parsed.read_vaddr(interp.vaddr, len).unwrap(), expected);
        let section = parsed.section_by_name(".interp").unwrap();
        assert_eq!(
            (section.header.addr, section.header.offset, section.data),
            (interp.vaddr, interp.offset, &expected[..])
        );
    }
}

#[test]
fn rejects_invalid_interpreters() {
    let mut elf = sample(Encoding::ELF64_LE);
    let error = elf.set_interpreter("/lib\0/x").unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSegment(_)));
    let mut static_file = ElfBuilder::new(Encoding::ELF64_LE).build();
    let error = static_file.set_interpreter("/lib/ld.so").unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSegment(_)));
}

/// Build an executable with `.rodata`, `.text` and `.data`, without an interpreter, with
/// pages of `page` bytes. `.rodata` follows the program header table in the file.
fn plain(page: u64, bss: u64) -> ElfFile {
    ElfBuilder::new(Encoding::ELF64_LE)
        .machine(Machine::X86_64)
        .page_size(page)
        .add_section(BuilderSection::progbits(
            ".rodata",
            SHF_ALLOC,
            vec![0xab; 64],
        ))
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0x90; 32],
        ))
        .add_section(BuilderSection::progbits(
            ".data",
            SHF_ALLOC | SHF_WRITE,
            vec![1; 16],
        ))
        .add_section(BuilderSection::nobits(".bss", SHF_ALLOC | SHF_WRITE, bss))
        .entry_in_section(".text", 0)
        .build()
}

/// Return the `PT_LOAD` segment at virtual address `vaddr`.
fn load_at(elf: &ElfFile, vaddr: u64) -> ProgramHeader {
    *elf.headers()
        .load_segments()
        .find(|load| load.vaddr == vaddr)
        .unwrap()
}

#[test]
fn relocates_the_program_table_at_the_image_origin() {
    for elf in [
        sample(Encoding::ELF64_LE),
        sample(Encoding::ELF32_BE),
        plain(0x1000, 0x5000),
    ] {
        let origin = elf.headers().image_origin().unwrap();
        let image_size = elf.headers().mapped_size().unwrap();
        let mut edited = elf.clone();
        edited.add_load_segment(PF_R, vec![7; 100], 0).unwrap();
        let parsed = rebuild(&edited);
        check_phdr(&parsed);
        let phdr = parsed.program_headers()[0];
        assert_eq!(phdr.offset, parsed.header().phoff);
        assert_eq!(phdr.vaddr - phdr.offset, origin);
        assert!(phdr.offset >= image_size);

        let built = parsed.try_build().unwrap();
        let image = ElfImage::parse(&built).unwrap();
        let mapped = ElfImage::parse_mapped(&image.to_mapped_image().unwrap()).unwrap();
        assert!(mapped.program_headers().eq(parsed.program_headers().iter()));
    }
}

#[test]
fn rejects_a_program_table_move_without_an_image_origin() {
    let mut elf = sample(Encoding::ELF64_LE);
    let first = elf
        .program_headers()
        .iter()
        .position(ProgramHeader::is_load)
        .unwrap();
    let load = &mut elf.program_headers_mut()[first];
    load.offset = load.vaddr + 0x1000;
    let error = elf.add_load_segment(PF_R, vec![1], 0).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSegment(_)));
}

#[test]
fn rejects_a_segment_alignment_below_the_page_size() {
    let mut elf = sample(Encoding::ELF64_LE);
    elf.add_load_segment(PF_R, vec![7; 100], 0).unwrap();
    for align in [16, 0x800] {
        let error = elf.add_load_segment(PF_R, vec![7; 100], align).unwrap_err();
        assert!(matches!(error.kind, ErrorKind::InvalidSegment(_)));
    }
    let mut large = plain(0x1_0000, 0);
    let error = large.add_load_segment(PF_R, vec![1], 0x1000).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSegment(_)));
}

#[test]
fn uses_the_largest_load_alignment_as_the_page_size() {
    let mut elf = plain(0x1_0000, 0);
    let previous_end = elf.headers().image_end().unwrap();
    let vaddr = elf.add_load_segment(PF_R, vec![7; 100], 0).unwrap();
    elf.add_section(NewSection::new(".pad", SectionType::PROGBITS, vec![0; 5]))
        .unwrap();
    let second = elf.add_load_segment(PF_R, vec![8; 10], 0).unwrap();
    let parsed = rebuild(&elf);
    check_phdr(&parsed);
    assert!(
        !parsed
            .validate()
            .contains(ValidationCode::MisalignedSegment)
    );
    assert!(vaddr >= previous_end.next_multiple_of(0x1_0000));
    for vaddr in [vaddr, second] {
        let load = load_at(&parsed, vaddr);
        assert_eq!(load.align, 0x1_0000);
        assert_eq!(load.offset % 0x1_0000, load.vaddr % 0x1_0000);
    }
    assert_eq!(parsed.read_vaddr(second, 10).unwrap(), [8; 10]);
}

#[test]
fn does_not_grow_the_program_table_without_section_headers() {
    let elf = plain(0x1000, 0);
    let rodata = *elf.section_by_name(".rodata").unwrap().header;
    let mut stripped = elf.clone();
    stripped.section_headers_mut().clear();
    let header = stripped.header_mut();
    header.shoff = 0;
    header.shnum = 0;
    header.shstrndx = 0;
    let mut stripped = ElfFile::parse(&stripped.try_build().unwrap()).unwrap();
    let phoff = stripped.header().phoff;
    stripped.add_load_segment(PF_R, vec![7; 8], 0).unwrap();
    assert_ne!(stripped.header().phoff, phoff);
    let parsed = rebuild(&stripped);
    check_phdr(&parsed);
    let len = usize::try_from(rodata.size).unwrap();
    assert_eq!(parsed.bytes_at(rodata.offset, len).unwrap(), [0xab; 64]);
}

#[test]
fn ignores_a_section_range_past_the_end_of_the_file() {
    let mut elf = sample(Encoding::ELF64_LE);
    let index = elf
        .add_section(NewSection::new(".x", SectionType::PROGBITS, vec![1]))
        .unwrap();
    elf.section_headers_mut()[index].offset = 0x1000_0000;
    let bytes = elf.try_build().unwrap();
    let size = bytes.len();

    let mut added = ElfFile::parse(&bytes).unwrap();
    added
        .add_section(NewSection::new(".y", SectionType::PROGBITS, vec![2]))
        .unwrap();
    assert!(added.try_build().unwrap().len() < size + 0x1000);

    let mut loaded = ElfFile::parse(&bytes).unwrap();
    loaded.add_load_segment(PF_R, vec![1; 4], 0).unwrap();
    assert!(loaded.try_build().unwrap().len() < size + 0x4000);
}

#[test]
fn keeps_an_unreadable_section_table_out_of_appends() {
    // Set `e_shentsize` (offset 58 in `Elf64_Ehdr`) to 0x80: the table goes past the end of
    // the file, and the parser cannot read it.
    let mut bytes = sample(Encoding::ELF64_LE).build();
    Encoding::ELF64_LE.put_u16(&mut bytes, 58, 0x80).unwrap();
    let mut elf = ElfFile::parse(&bytes).unwrap();
    assert_eq!(elf.section_headers(), []);
    let error = elf.add_load_segment(PF_R, vec![7; 0x100], 0).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSection(_)));
    let error = elf.set_interpreter(&"/long".repeat(20)).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::InvalidSection(_)));
    assert_eq!(elf.try_build().unwrap(), bytes);
}

#[test]
fn changes_only_an_interp_section_at_the_pt_interp_range() {
    let mut elf = sample(Encoding::ELF64_LE);
    let index = elf.section_by_name(".interp").unwrap().index;
    let end = u64::try_from(elf.len()).unwrap();
    let moved = SectionHeader {
        offset: end - 2,
        size: 2,
        ..elf.section_headers()[index]
    };
    elf.section_headers_mut()[index] = moved;

    let mut in_place = elf.clone();
    in_place.set_interpreter("/lib/a.so").unwrap();
    assert_eq!(in_place.section_headers()[index], moved);
    let mut longer = elf.clone();
    longer.set_interpreter(&"/long".repeat(20)).unwrap();
    assert_eq!(longer.section_headers()[index], moved);
}

#[test]
fn rejects_header_bytes_that_change_an_overlapping_program_table() {
    // Point `e_phoff` (offset 32 in `Elf64_Ehdr`) into the file header and set `e_phnum`
    // (offset 56) to 1. The entry holds `e_entry` at offset 24 as its `p_offset`.
    let mut bytes = sample(Encoding::ELF64_LE).build();
    Encoding::ELF64_LE.put_u64(&mut bytes, 32, 0x10).unwrap();
    Encoding::ELF64_LE.put_u16(&mut bytes, 56, 1).unwrap();
    let mut elf = ElfFile::parse(&bytes).unwrap();
    assert_eq!(elf.program_headers().len(), 1);
    assert_eq!(elf.try_build().unwrap(), bytes);
    elf.set_entry_point(0x1234);
    assert!(matches!(
        elf.try_build().unwrap_err().kind,
        ErrorKind::InvalidHeader(_)
    ));
}

#[test]
fn does_not_remove_a_group_member() {
    let encoding = Encoding::ELF64_LE;
    let mut elf = sample(encoding);
    let mut members = Vec::new();
    encoding.write_u32(&mut members, 1);
    encoding.write_u32(&mut members, 5);
    let group = elf
        .add_section(NewSection::new(".group", SectionType::GROUP, members))
        .unwrap();
    assert!(matches!(
        elf.remove_section(5).unwrap_err().kind,
        ErrorKind::InvalidSection(_)
    ));
    elf.remove_section(group).unwrap();
    elf.remove_section(5).unwrap();
}

#[test]
fn builds_a_header_with_zero_table_entry_sizes() {
    // Fuzz regression: a header without tables and with zero entry sizes made the build
    // divide the empty table image into chunks of size 0, which panics.
    let mut header = FileHeader::new(Encoding::ELF64_BE, FileType::NONE, Machine::NONE);
    header.phentsize = 0;
    header.shentsize = 0;
    header.shoff = 0x83_ffff_ffe8;
    let bytes = header.to_bytes().unwrap();
    let elf = ElfFile::parse(&bytes).unwrap();
    assert_eq!(elf.try_build().unwrap(), bytes);
}
