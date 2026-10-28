use super::*;
use crate::elf::ElfHeaders;
use crate::header::FileHeader;
use crate::program::{PF_X, ProgramHeader};
use crate::section::{SHF_EXECINSTR, SHF_WRITE, SHN_XINDEX, SectionHeader};
use crate::{ErrorKind, SourceLayout};

const INTERP: &str = "/lib64/ld-linux-x86-64.so.2";

/// Return a note with the name `GNU` and a 4-byte descriptor in `encoding`.
fn note_bytes(encoding: Encoding) -> Vec<u8> {
    let mut out = Vec::new();
    encoding.write_u32(&mut out, 4);
    encoding.write_u32(&mut out, 4);
    encoding.write_u32(&mut out, 1);
    out.extend_from_slice(b"GNU\0");
    out.extend_from_slice(&[1, 2, 3, 4]);
    out
}

fn exec_builder() -> ElfBuilder {
    ElfBuilder::new(Encoding::ELF64_LE)
        .machine(Machine::X86_64)
        .interpreter(INTERP)
        .add_section(BuilderSection::note(
            ".note.test",
            note_bytes(Encoding::ELF64_LE),
        ))
        .add_section(BuilderSection {
            addralign: 16,
            ..BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0x90; 37])
        })
        .add_section(BuilderSection::progbits(
            ".rodata",
            SHF_ALLOC,
            b"hello\0".to_vec(),
        ))
        .add_section(BuilderSection {
            addralign: 8,
            ..BuilderSection::progbits(".data", SHF_ALLOC | SHF_WRITE, vec![1; 24])
        })
        .add_section(BuilderSection {
            addralign: 32,
            ..BuilderSection::nobits(".bss", SHF_ALLOC | SHF_WRITE, 0x2000)
        })
        .add_section(BuilderSection::progbits(".comment", 0, b"elfex\0".to_vec()))
        .add_section(BuilderSection {
            link_name: Some(".comment".into()),
            ..BuilderSection::progbits(".linked", 0, vec![7; 3])
        })
        .add_segment_for_section(SegmentType::NOTE, ".note.test")
        .entry_in_section(".text", 4)
}

/// Check that the file parses again to the same file, validates without errors, and has
/// congruent offsets and addresses.
fn check_layout(elf: &ElfFile, page: u64) {
    let bytes = elf.try_build().unwrap();
    assert_eq!(bytes, elf.as_bytes());
    assert_eq!(&ElfFile::parse(&bytes).unwrap(), elf);
    let result = elf.validate();
    assert!(!result.has_errors(), "{result:?}");
    for segment in elf.headers().load_segments() {
        assert_eq!(segment.offset % page, segment.vaddr % page, "{segment:?}");
        assert_eq!(segment.align, page);
    }
    for section in elf.sections().filter(|section| section.header.is_alloc()) {
        let header = section.header;
        if header.has_file_data() {
            assert_eq!(header.offset % page, header.addr % page, "{}", section.name);
        }
        assert_eq!(header.addr % header.addralign.max(1), 0, "{}", section.name);
    }
}

#[test]
fn builds_elf64_le_executable() {
    let elf = exec_builder().build();
    check_layout(&elf, DEFAULT_PAGE_SIZE);
    assert_eq!(elf.encoding(), Encoding::ELF64_LE);
    assert_eq!(elf.file_type(), FileType::EXEC);
    assert_eq!(elf.machine(), Machine::X86_64);
    let names: Vec<&str> = elf.section_names().iter().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "",
            ".interp",
            ".note.test",
            ".rodata",
            ".text",
            ".data",
            ".bss",
            ".comment",
            ".linked",
            ".shstrtab"
        ]
    );
    assert_eq!(elf.header().shstrndx, 9);

    let types: Vec<SegmentType> = elf
        .program_headers()
        .iter()
        .map(|segment| segment.segment_type)
        .collect();
    assert_eq!(
        types,
        [
            SegmentType::PHDR,
            SegmentType::INTERP,
            SegmentType::LOAD,
            SegmentType::LOAD,
            SegmentType::LOAD,
            SegmentType::NOTE,
            SegmentType::GNU_STACK,
        ]
    );
    let phdr = elf.program_headers()[0];
    assert_eq!((phdr.offset, phdr.vaddr), (64, DEFAULT_EXEC_BASE + 64));
    assert_eq!(phdr.filesz, 7 * 56);
    let loads: Vec<&ProgramHeader> = elf.headers().load_segments().collect();
    assert_eq!(
        (loads[0].offset, loads[0].vaddr, loads[0].flags),
        (0, DEFAULT_EXEC_BASE, PF_R)
    );
    assert_eq!(loads[1].flags, PF_R | PF_X);
    assert_eq!(loads[2].flags, PF_R | PF_W);
    assert!(loads[2].memsz >= loads[2].filesz + 0x2000);

    let text = elf.section_by_name(".text").unwrap();
    assert_eq!(elf.entry_point(), text.header.addr + 4);
    assert_eq!(text.data, [0x90; 37]);
    let interp = elf.headers().segment(SegmentType::INTERP).unwrap();
    let interp_index = elf
        .program_headers()
        .iter()
        .position(|p| p == interp)
        .unwrap();
    assert_eq!(
        elf.segment_data(interp_index).unwrap(),
        b"/lib64/ld-linux-x86-64.so.2\0"
    );
    let note = elf.headers().segment(SegmentType::NOTE).unwrap();
    let note_section = elf.section_by_name(".note.test").unwrap();
    assert_eq!((note.vaddr, note.align), (note_section.header.addr, 4));
    let bss = elf.section_by_type(SectionType::NOBITS).unwrap();
    assert_eq!(
        (bss.name, bss.header.size, bss.data.len()),
        (".bss", 0x2000, 0)
    );
    assert!(loads[2].contains_vaddr(bss.header.addr + 0x1fff));
    let linked = elf.section_by_name(".linked").unwrap();
    assert_eq!(linked.header.link, 7);
    let stack = elf.headers().segment(SegmentType::GNU_STACK).unwrap();
    assert_eq!(stack.flags, PF_R | PF_W);
}

#[test]
fn builds_elf32_be_shared_object() {
    let elf = ElfBuilder::new(Encoding::ELF32_BE)
        .file_type(FileType::DYN)
        .machine(Machine::PPC)
        .add_section(BuilderSection {
            addralign: 4,
            ..BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0x60, 0, 0, 0])
        })
        .add_section(BuilderSection::note(
            ".note.gnu",
            note_bytes(Encoding::ELF32_BE),
        ))
        .add_section(BuilderSection {
            addralign: 4,
            entsize: 8,
            ..BuilderSection::progbits(".dynamic", SHF_ALLOC | SHF_WRITE, vec![0; 16])
        })
        .add_segment_for_section(SegmentType::DYNAMIC, ".dynamic")
        .gnu_stack(PF_R | PF_W)
        .page_size(0x1_0000)
        .entry_in_section(".text", 0)
        .build();
    check_layout(&elf, 0x1_0000);
    assert_eq!(elf.encoding(), Encoding::ELF32_BE);
    assert_eq!(elf.file_type(), FileType::DYN);
    assert_eq!(elf.headers().image_origin(), Some(0));
    let dynamic = elf.headers().segment(SegmentType::DYNAMIC).unwrap();
    let section = elf.section_by_name(".dynamic").unwrap();
    assert_eq!(
        (dynamic.vaddr, dynamic.offset, dynamic.filesz),
        (section.header.addr, section.header.offset, 16)
    );
    assert_eq!(dynamic.flags, PF_R | PF_W);
    assert_eq!(section.header.entsize, 8);
    let text = elf.section_by_name(".text").unwrap();
    assert_eq!(elf.entry_point(), text.header.addr);
    assert_eq!(
        elf.read_vaddr(text.header.addr, 4).unwrap(),
        [0x60, 0, 0, 0]
    );
}

#[test]
fn builds_all_encodings_with_only_headers() {
    for encoding in [
        Encoding::ELF32_LE,
        Encoding::ELF32_BE,
        Encoding::ELF64_LE,
        Encoding::ELF64_BE,
    ] {
        let elf = ElfBuilder::new(encoding).file_type(FileType::DYN).build();
        check_layout(&elf, DEFAULT_PAGE_SIZE);
        assert_eq!(elf.section_names(), ["", ".shstrtab"]);
        let headers = ElfHeaders::read_from(
            &crate::reader::SliceReader::new(elf.as_bytes()),
            0,
            SourceLayout::File,
        )
        .unwrap();
        assert_eq!(&headers, elf.headers());
    }
}

#[test]
fn builds_only_bss_in_the_writable_segment() {
    let elf = ElfBuilder::new(Encoding::ELF64_BE)
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0; 8],
        ))
        .add_section(BuilderSection {
            addralign: 64,
            ..BuilderSection::nobits(".bss", SHF_ALLOC | SHF_WRITE, 0x100)
        })
        .entry_in_section(".text", 0)
        .build();
    check_layout(&elf, DEFAULT_PAGE_SIZE);
    let data = elf.headers().load_segments().nth(2).unwrap();
    assert_eq!((data.filesz, data.flags), (0, PF_R | PF_W));
    let bss = elf.section_by_name(".bss").unwrap();
    assert!(data.contains_vaddr(bss.header.addr));
    assert_eq!(bss.header.addr % 64, 0);
}

#[test]
fn uses_extended_numbering_for_many_sections() {
    let mut builder = ElfBuilder::new(Encoding::ELF32_LE).gnu_stack(PF_R);
    for _ in 0..usize::from(crate::section::SHN_LORESERVE) {
        builder = builder.add_section(BuilderSection::progbits("s", 0, Vec::new()));
    }
    let elf = builder.build();
    let count = usize::from(crate::section::SHN_LORESERVE) + 2;
    assert_eq!(elf.section_headers().len(), count);
    assert_eq!(elf.header().shnum, 0);
    assert_eq!(elf.header().shstrndx, SHN_XINDEX);
    let zero: SectionHeader = elf.section_headers()[0];
    assert_eq!(zero.size, u64::try_from(count).unwrap());
    assert_eq!(usize::try_from(zero.link).unwrap(), count - 1);
    assert_eq!(elf.section_names()[count - 1], ".shstrtab");
    assert_eq!(elf.try_build().unwrap(), elf.as_bytes());
}

#[test]
fn rejects_invalid_input() {
    let kind = |builder: ElfBuilder| builder.try_build().unwrap_err().kind;
    let unknown_link = ElfBuilder::new(Encoding::ELF64_LE).add_section(BuilderSection {
        link_name: Some(".missing".into()),
        ..BuilderSection::progbits(".a", 0, Vec::new())
    });
    assert!(matches!(kind(unknown_link), ErrorKind::InvalidSection(_)));
    let unknown_entry = ElfBuilder::new(Encoding::ELF64_LE).entry_in_section(".text", 0);
    assert!(matches!(kind(unknown_entry), ErrorKind::InvalidSection(_)));
    let duplicate = ElfBuilder::new(Encoding::ELF64_LE)
        .interpreter("/a")
        .interpreter("/b");
    assert!(matches!(kind(duplicate), ErrorKind::InvalidSection(_)));
    let with_interp_section = ElfBuilder::new(Encoding::ELF64_LE)
        .interpreter("/a")
        .add_section(BuilderSection::progbits(
            ".interp",
            SHF_ALLOC,
            b"/b\0".to_vec(),
        ));
    assert!(matches!(
        kind(with_interp_section),
        ErrorKind::InvalidSection(_)
    ));
    let unknown_segment = ElfBuilder::new(Encoding::ELF64_LE)
        .add_segment_for_section(SegmentType::DYNAMIC, ".dynamic");
    assert!(matches!(
        kind(unknown_segment),
        ErrorKind::InvalidSection(_)
    ));
    let bad_align = ElfBuilder::new(Encoding::ELF64_LE).add_section(BuilderSection {
        addralign: 3,
        ..BuilderSection::progbits(".a", 0, Vec::new())
    });
    assert!(matches!(kind(bad_align), ErrorKind::InvalidSection(_)));
    let bad_page = ElfBuilder::new(Encoding::ELF64_LE).page_size(0x1800);
    assert!(matches!(kind(bad_page), ErrorKind::InvalidSegment(_)));
    let bad_base = ElfBuilder::new(Encoding::ELF64_LE).base_address(0x40_0800);
    assert!(matches!(kind(bad_base), ErrorKind::InvalidSegment(_)));
    let elf32_base = ElfBuilder::new(Encoding::ELF32_LE).base_address(0x1_0000_0000);
    assert!(matches!(kind(elf32_base), ErrorKind::ValueOutOfRange(_)));
    let elf32_end = ElfBuilder::new(Encoding::ELF32_BE)
        .base_address(0xffff_f000)
        .add_section(BuilderSection::nobits(
            ".bss",
            SHF_ALLOC | SHF_WRITE,
            0x10_0000,
        ));
    assert!(matches!(kind(elf32_end), ErrorKind::ValueOutOfRange(_)));
}

#[test]
fn rejects_invalid_names_data_and_flags() {
    let new = || ElfBuilder::new(Encoding::ELF64_LE);
    let comment = || BuilderSection::progbits(".comment", 0, vec![1]);
    let invalid = [
        new().interpreter("/lib\0/ld.so"),
        new().add_section(BuilderSection::progbits(".shstrtab", 0, Vec::new())),
        new().add_section(BuilderSection::progbits(".a\0b", 0, Vec::new())),
        new().add_section(BuilderSection {
            data: vec![1],
            ..BuilderSection::nobits(".bss", SHF_ALLOC | SHF_WRITE, 0)
        }),
        new()
            .add_section(comment())
            .add_segment_for_section(SegmentType::NOTE, ".comment"),
        new().add_section(comment()).entry_in_section(".comment", 0),
    ];
    for builder in invalid {
        let error = builder.try_build().unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::InvalidSection(_)),
            "{error}"
        );
    }
}

#[test]
fn rejects_layouts_that_overflow() {
    let text = BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0x90; 0x2000]);
    let mut many = ElfBuilder::new(Encoding::ELF64_LE).add_section(text.clone());
    for _ in 0..crate::program::PN_XNUM {
        many = many.add_segment_for_section(SegmentType::NOTE, ".text");
    }
    let high_base = ElfBuilder::new(Encoding::ELF64_LE)
        .base_address(0xffff_ffff_ffff_f000)
        .add_section(text.clone());
    let far_entry = ElfBuilder::new(Encoding::ELF64_LE)
        .add_section(text)
        .entry_in_section(".text", u64::MAX);
    for builder in [many, high_base, far_entry] {
        let error = builder.try_build().unwrap_err();
        assert!(
            matches!(error.kind, ErrorKind::ValueOutOfRange(_)),
            "{error}"
        );
    }
    // The section data must go past `isize::MAX` bytes.
    let far_section = ElfBuilder::new(Encoding::ELF64_LE).add_section(BuilderSection {
        addralign: 1 << 63,
        ..BuilderSection::progbits(".far", 0, vec![1])
    });
    let error = far_section.try_build().unwrap_err();
    assert!(matches!(error.kind, ErrorKind::Generic(_)), "{error}");
}

#[test]
fn makes_segments_and_links_for_all_section_kinds() {
    let elf = ElfBuilder::new(Encoding::ELF64_LE)
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0xc3; 4],
        ))
        .add_section(BuilderSection::nobits(".tbss", SHF_ALLOC | SHF_WRITE, 0x40))
        .add_section(BuilderSection::progbits(".comment", 0, b"x\0".to_vec()))
        .add_section(BuilderSection::nobits(".unused", 0, 0x10))
        .add_section(BuilderSection {
            link_name: Some(".shstrtab".into()),
            ..BuilderSection::progbits(".names", 0, Vec::new())
        })
        .add_segment_for_section(SegmentType::TLS, ".tbss")
        .add_segment_for_section(SegmentType::GNU_EH_FRAME, ".text")
        .build();
    check_layout(&elf, DEFAULT_PAGE_SIZE);
    let tbss = *elf.section_by_name(".tbss").unwrap().header;
    let tls = elf.headers().segment(SegmentType::TLS).unwrap();
    assert_eq!(
        (tls.vaddr, tls.flags, tls.filesz, tls.memsz),
        (tbss.addr, PF_R | PF_W, 0, 0x40)
    );
    let frame = elf.headers().segment(SegmentType::GNU_EH_FRAME).unwrap();
    assert_eq!(frame.flags, PF_R | PF_X);
    let comment = *elf.section_by_name(".comment").unwrap().header;
    let unused = *elf.section_by_name(".unused").unwrap().header;
    assert_eq!(unused.offset, comment.offset + comment.size);
    let names = elf.section_by_name(".names").unwrap().header.link;
    assert_eq!(names, u32::from(elf.header().shstrndx));
}

#[test]
fn keeps_the_header_values() {
    let elf = ElfBuilder::new(Encoding::ELF64_BE)
        .os_abi(OsAbi::FREEBSD)
        .flags(0x1234)
        .entry(0x40_0000)
        .base_address(0x20_0000)
        .build();
    let header: &FileHeader = elf.header();
    assert_eq!(header.ident.os_abi, OsAbi::FREEBSD);
    assert_eq!(header.flags, 0x1234);
    assert_eq!(header.entry, 0x40_0000);
    assert_eq!(elf.headers().image_origin(), Some(0x20_0000));
}
