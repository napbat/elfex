//! Tests of [`ElfFile::remove_section`] with symbol tables and section groups.

use super::*;
use crate::group::{GRP_COMDAT, GroupTable};
use crate::reloc::{Relocation, RelocationTable};
use crate::section::{SHF_GROUP, SHN_ABS, SHN_LORESERVE, SHN_UNDEF};
use crate::symbol::{Symbol, SymbolBinding, SymbolSectionIndexTable, SymbolTable, SymbolType};

/// Return the index of the section `name`.
fn index_of(elf: &ElfFile, name: &str) -> usize {
    elf.section_by_name(name).unwrap().index
}

/// Return the index of the section `name` as a `st_shndx` value.
fn shndx_of(elf: &ElfFile, name: &str) -> u16 {
    u16::try_from(index_of(elf, name)).unwrap()
}

/// Make a symbol without a name and a value.
fn symbol(symbol_type: SymbolType, binding: SymbolBinding, shndx: u16) -> Symbol {
    Symbol {
        info: Symbol::make_info(binding, symbol_type),
        shndx,
        ..Symbol::default()
    }
}

/// Build an executable with a `.dynsym`, a `.symtab` and a COMDAT group. The `.symtab`
/// symbols are:
///
/// 0 null, 1 `STT_SECTION` of `.note.extra`, 2 `STT_SECTION` of `.comment`, 3 an object in
/// `.data`, 4 a symbol in `.comment`, 5 an `SHN_ABS` symbol, 6 an undefined symbol.
///
/// The `.dynsym` symbols are a function in `.text` and an object in `.data`. The group has the
/// signature symbol 3 and the members `.comment` and `.note.extra`.
fn symbol_sample(encoding: Encoding) -> ElfFile {
    let entry = Symbol::size(encoding.class);
    let table = |name: &str, section_type, flags, count: usize, link: &str, info| BuilderSection {
        section_type,
        link_name: Some(link.into()),
        info,
        entsize: u64::try_from(entry).unwrap(),
        addralign: 8,
        ..BuilderSection::progbits(name, flags, vec![0; count * entry])
    };
    let strings = |name: &str, flags| BuilderSection {
        section_type: SectionType::STRTAB,
        ..BuilderSection::progbits(name, flags, vec![0])
    };
    let mut elf = ElfBuilder::new(encoding)
        .machine(Machine::X86_64)
        .add_section(BuilderSection::progbits(".rodata", SHF_ALLOC, vec![1; 8]))
        .add_section(table(
            ".dynsym",
            SectionType::DYNSYM,
            SHF_ALLOC,
            3,
            ".dynstr",
            1,
        ))
        .add_section(strings(".dynstr", SHF_ALLOC))
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0xc3; 16],
        ))
        .add_section(BuilderSection::progbits(
            ".data",
            SHF_ALLOC | SHF_WRITE,
            vec![0; 16],
        ))
        .add_section(BuilderSection::progbits(
            ".comment",
            SHF_GROUP,
            b"x\0".to_vec(),
        ))
        .add_section(BuilderSection::progbits(
            ".note.extra",
            SHF_GROUP,
            vec![2; 8],
        ))
        .add_section(BuilderSection {
            section_type: SectionType::GROUP,
            link_name: Some(".symtab".into()),
            info: 3,
            entsize: 4,
            addralign: 4,
            ..BuilderSection::progbits(".group", 0, vec![0; 12])
        })
        .add_section(table(".symtab", SectionType::SYMTAB, 0, 7, ".strtab", 3))
        .add_section(strings(".strtab", 0))
        .entry_in_section(".text", 0)
        .build();

    let (local, global) = (SymbolBinding::LOCAL, SymbolBinding::GLOBAL);
    let dynsym = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(SymbolType::FUNC, global, shndx_of(&elf, ".text")),
            symbol(SymbolType::OBJECT, global, shndx_of(&elf, ".data")),
        ],
    };
    let symtab = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(SymbolType::SECTION, local, shndx_of(&elf, ".note.extra")),
            symbol(SymbolType::SECTION, local, shndx_of(&elf, ".comment")),
            symbol(SymbolType::OBJECT, global, shndx_of(&elf, ".data")),
            symbol(SymbolType::NOTYPE, global, shndx_of(&elf, ".comment")),
            symbol(SymbolType::NOTYPE, global, SHN_ABS),
            symbol(SymbolType::NOTYPE, global, SHN_UNDEF),
        ],
    };
    let group = GroupTable {
        flags: GRP_COMDAT,
        members: [".comment", ".note.extra"]
            .map(|name| u32::from(shndx_of(&elf, name)))
            .to_vec(),
    };
    let data = [
        (".dynsym", dynsym.write(encoding).unwrap()),
        (".symtab", symtab.write(encoding).unwrap()),
        (".group", group.write(encoding)),
    ];
    for (name, bytes) in data {
        elf.set_section_data(index_of(&elf, name), bytes).unwrap();
    }
    elf
}

/// Return the section of each symbol in each symbol table, by name. `UND` is `SHN_UNDEF`, and
/// a reserved value is in hexadecimal.
fn symbol_sections(elf: &ElfFile) -> Vec<Vec<String>> {
    let encoding = elf.encoding();
    elf.sections()
        .filter(|section| {
            section.header.section_type == SectionType::SYMTAB
                || section.header.section_type == SectionType::DYNSYM
        })
        .map(|section| {
            let symbols =
                SymbolTable::parse_with_entsize(section.data, encoding, section.header.entsize)
                    .unwrap();
            let indices = elf.symbol_index_section(section.index).map(|index| {
                SymbolSectionIndexTable::parse(elf.section_data(index).unwrap(), encoding).unwrap()
            });
            let reserved = u32::from(SHN_LORESERVE);
            symbols
                .iter()
                .enumerate()
                .map(
                    |(position, symbol)| match symbol.section_index(position, indices.as_ref()) {
                        Some(0) => "UND".into(),
                        Some(index) if symbol.shndx != SHN_XINDEX && index >= reserved => {
                            format!("{index:#x}")
                        }
                        Some(index) => elf.section_names()[usize::try_from(index).unwrap()].clone(),
                        None => "?".into(),
                    },
                )
                .collect()
        })
        .collect()
}

/// Return `sections` with each symbol in `removed` as an undefined symbol.
fn without(sections: &[Vec<String>], removed: &str) -> Vec<Vec<String>> {
    sections
        .iter()
        .map(|table| {
            table
                .iter()
                .map(|name| {
                    if name == removed {
                        "UND".into()
                    } else {
                        name.clone()
                    }
                })
                .collect()
        })
        .collect()
}

/// Return the member names of the first section group.
fn group_members(elf: &ElfFile) -> Vec<String> {
    elf.section_groups().unwrap()[0]
        .members
        .iter()
        .map(|member| elf.section_names()[usize::try_from(*member).unwrap()].clone())
        .collect()
}

/// Remove section `name`, and check that the call fails without a change to the file.
fn assert_not_removed(elf: &mut ElfFile, name: &str) {
    let before = elf.clone();
    let error = elf.remove_section(index_of(elf, name)).unwrap_err();
    assert!(
        matches!(error.kind, ErrorKind::InvalidSection(_)),
        "{name}: {error}"
    );
    assert_eq!(*elf, before, "{name}");
}

#[test]
fn removes_sections_from_a_file_with_symbol_tables() {
    for encoding in ENCODINGS {
        let mut elf = symbol_sample(encoding);
        // A symbol that is not an `STT_SECTION` symbol is in each of these sections.
        for name in [".text", ".data", ".comment"] {
            assert_not_removed(&mut elf, name);
        }

        // All sections after `.rodata` get a new index.
        let before = symbol_sections(&elf);
        let rodata = index_of(&elf, ".rodata");
        elf.remove_section(rodata).unwrap();
        assert_eq!(symbol_sections(&elf), before);
        assert_eq!(group_members(&elf), [".comment", ".note.extra"]);
        rebuild(&elf);

        // The `STT_SECTION` symbol of `.note.extra` becomes undefined, and the group loses
        // a member.
        let before = symbol_sections(&elf);
        let group_size = elf.section_by_name(".group").unwrap().header.size;
        elf.remove_section(index_of(&elf, ".note.extra")).unwrap();
        assert_eq!(symbol_sections(&elf), without(&before, ".note.extra"));
        assert_eq!(group_members(&elf), [".comment"]);
        let group = elf.section_by_name(".group").unwrap();
        assert_eq!(group.header.size, group_size - 4);
        assert_eq!(elf.section_groups().unwrap()[0].flags, GRP_COMDAT);
        rebuild(&elf);

        // The member of a removed group loses `SHF_GROUP`.
        elf.remove_section(index_of(&elf, ".group")).unwrap();
        let comment = elf.section_by_name(".comment").unwrap().header.flags;
        assert_eq!(comment & SHF_GROUP, 0);
        assert_eq!(elf.section_groups().unwrap(), []);
        rebuild(&elf);
    }
}

#[test]
fn keeps_a_section_with_a_used_section_symbol() {
    let encoding = Encoding::ELF64_LE;
    let mut elf = symbol_sample(encoding);
    let mut relocations = RelocationTable::new(true);
    relocations
        .relocations
        .push(Relocation::with_addend(0, 1, 1, 0));
    let rela = elf
        .add_section(NewSection {
            link: u32::try_from(index_of(&elf, ".symtab")).unwrap(),
            entsize: 24,
            ..NewSection::new(
                ".rela.extra",
                SectionType::RELA,
                relocations.write(encoding, elf.machine()).unwrap(),
            )
        })
        .unwrap();
    // A relocation refers to the `STT_SECTION` symbol of `.note.extra`.
    assert_not_removed(&mut elf, ".note.extra");
    elf.remove_section(rela).unwrap();

    // The group signature is the `STT_SECTION` symbol of `.note.extra`.
    let group = index_of(&elf, ".group");
    elf.section_headers_mut()[group].info = 1;
    assert_not_removed(&mut elf, ".note.extra");
    elf.section_headers_mut()[group].info = 3;
    elf.remove_section(index_of(&elf, ".note.extra")).unwrap();
}

#[test]
fn renumbers_extended_section_indices() {
    let encoding = Encoding::ELF32_BE;
    let mut elf = symbol_sample(encoding);
    let symtab = index_of(&elf, ".symtab");
    let mut symbols = elf.symbols().unwrap().unwrap();
    let mut indices = SymbolSectionIndexTable {
        indices: vec![0; symbols.len()],
    };
    // Symbols 1 (`STT_SECTION` of `.note.extra`) and 3 (in `.data`) use `SHN_XINDEX`.
    for position in [1, 3] {
        indices.indices[position] = u32::from(symbols.symbols[position].shndx);
        symbols.symbols[position].shndx = SHN_XINDEX;
    }
    elf.set_section_data(symtab, symbols.write(encoding).unwrap())
        .unwrap();
    elf.add_section(NewSection {
        link: u32::try_from(symtab).unwrap(),
        entsize: 4,
        addralign: 4,
        ..NewSection::new(
            ".symtab_shndx",
            SectionType::SYMTAB_SHNDX,
            indices.write(encoding),
        )
    })
    .unwrap();
    let extended = |elf: &ElfFile| {
        let index = elf.symbol_index_section(index_of(elf, ".symtab")).unwrap();
        SymbolSectionIndexTable::parse(elf.section_data(index).unwrap(), encoding).unwrap()
    };

    let before = symbol_sections(&elf);
    elf.remove_section(index_of(&elf, ".rodata")).unwrap();
    assert_eq!(symbol_sections(&elf), before);
    assert_eq!(elf.symbols().unwrap().unwrap().symbols[3].shndx, SHN_XINDEX);
    assert_eq!(
        extended(&elf).get(3),
        Some(u32::from(shndx_of(&elf, ".data")))
    );

    let before = symbol_sections(&elf);
    elf.remove_section(index_of(&elf, ".note.extra")).unwrap();
    assert_eq!(symbol_sections(&elf), without(&before, ".note.extra"));
    assert_eq!(elf.symbols().unwrap().unwrap().symbols[1].shndx, SHN_UNDEF);
    assert_eq!(extended(&elf).get(1), Some(0));

    // Symbol 3 needs the `SHT_SYMTAB_SHNDX` section.
    assert_not_removed(&mut elf, ".symtab_shndx");
    rebuild(&elf);
}

#[test]
fn removes_a_group_member() {
    let encoding = Encoding::ELF64_LE;
    let mut elf = sample(encoding);
    let members = GroupTable {
        flags: 0,
        members: vec![1, 5, 7],
    };
    elf.add_section(NewSection::new(
        ".group",
        SectionType::GROUP,
        members.write(encoding),
    ))
    .unwrap();
    elf.remove_section(5).unwrap();
    assert_eq!(elf.section_groups().unwrap()[0].members, [1, 6]);
}

#[test]
fn rejects_a_malformed_symbol_or_group_table() {
    let encoding = Encoding::ELF64_LE;
    let mut elf = symbol_sample(encoding);
    // A symbol table size that is not a multiple of the entry size.
    let symtab = index_of(&elf, ".symtab");
    elf.section_headers_mut()[symtab].size -= 1;
    let before = elf.clone();
    assert!(elf.remove_section(index_of(&elf, ".rodata")).is_err());
    assert_eq!(elf, before);

    // A `SHN_XINDEX` symbol without a `SHT_SYMTAB_SHNDX` section.
    let mut elf = symbol_sample(encoding);
    let mut symbols = elf.symbols().unwrap().unwrap();
    symbols.symbols[3].shndx = SHN_XINDEX;
    elf.set_section_data(symtab, symbols.write(encoding).unwrap())
        .unwrap();
    assert_not_removed(&mut elf, ".rodata");

    // A group size that is not a multiple of 4.
    let mut elf = symbol_sample(encoding);
    let group = index_of(&elf, ".group");
    elf.section_headers_mut()[group].size = 6;
    let before = elf.clone();
    assert!(elf.remove_section(index_of(&elf, ".rodata")).is_err());
    assert_eq!(elf, before);
}
