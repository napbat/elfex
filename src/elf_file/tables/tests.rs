//! Tests of the section table accessors with a built relocatable file.

use super::{RelocationSection, SectionGroup};
use crate::ErrorKind;
use crate::builder::{BuilderSection, ElfBuilder};
use crate::elf_file::ElfFile;
use crate::endian::Encoding;
use crate::header::{FileType, Machine};
use crate::prelude::*;
use crate::reloc::x86_64::{R_X86_64_32, R_X86_64_PLT32};
use crate::reloc::{Relocation, RelocationTable};
use crate::section::{
    GRP_COMDAT, SHF_ALLOC, SHF_EXECINSTR, SHF_GROUP, SHF_INFO_LINK, SHN_ABS, SHN_XINDEX,
    SectionType,
};
use crate::symbol::{
    BuiltSymbolTable, NewSymbol, SymbolBinding, SymbolSectionIndexTable, SymbolTableBuilder,
    SymbolType,
};

/// The section indices of the relocatable sample. The builder keeps the order of the
/// sections without `SHF_ALLOC`.
const TEXT: u32 = 1;
const TEXT_FOO: u32 = 2;
const RELA_TEXT_FOO: u32 = 3;
const GROUP: u32 = 4;
const SECTION_GROUP: u32 = 5;
const SYMTAB: u32 = 6;
const SYMTAB_SHNDX: u32 = 8;
const REL_TEXT: u32 = 9;

/// The `sh_entsize` of `.rela.text.foo`: larger than `Elf64_Rela`.
const RELA_ENTSIZE: usize = 32;

/// The symbol indices of the relocatable sample.
struct Indices {
    section: u32,
    foo: u32,
    bar: u32,
    absolute: u32,
}

fn usize_of(value: u32) -> usize {
    usize::try_from(value).unwrap()
}

fn words(encoding: Encoding, values: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        encoding.write_u32(&mut out, *value);
    }
    out
}

/// Write `table` with `entsize` bytes for each entry.
fn padded(table: &RelocationTable, encoding: Encoding, entsize: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for relocation in table {
        let single = RelocationTable {
            relocations: vec![*relocation],
            with_addend: table.with_addend,
        };
        let mut entry = single.write(encoding, Machine::X86_64).unwrap();
        entry.resize(entsize, 0);
        out.extend_from_slice(&entry);
    }
    out
}

fn section(
    name: &str,
    section_type: SectionType,
    flags: u64,
    data: Vec<u8>,
    link: Option<&str>,
    info: u32,
    entsize: u64,
) -> BuilderSection {
    BuilderSection {
        section_type,
        entsize,
        link_name: link.map(ToString::to_string),
        info,
        addralign: 4,
        ..BuilderSection::progbits(name, flags, data)
    }
}

fn rela_table(indices: &Indices) -> RelocationTable {
    RelocationTable {
        relocations: vec![Relocation::with_addend(0, indices.bar, R_X86_64_PLT32, -4)],
        with_addend: true,
    }
}

fn rel_table(indices: &Indices) -> RelocationTable {
    RelocationTable {
        relocations: vec![Relocation::new(4, indices.absolute, R_X86_64_32)],
        with_addend: false,
    }
}

/// Build the symbol table of the relocatable sample and its extended section indices.
fn symbols(encoding: Encoding) -> (BuiltSymbolTable, Indices, SymbolSectionIndexTable) {
    let mut builder = SymbolTableBuilder::new(encoding);
    let positions = [
        builder.add(
            NewSymbol::new("", SymbolBinding::LOCAL, SymbolType::SECTION)
                .with_shndx(u16::try_from(TEXT).unwrap()),
        ),
        builder.add(
            NewSymbol::new("foo", SymbolBinding::GLOBAL, SymbolType::FUNC)
                .with_shndx(SHN_XINDEX)
                .with_size(4),
        ),
        builder.add(NewSymbol::new(
            "bar",
            SymbolBinding::GLOBAL,
            SymbolType::NOTYPE,
        )),
        builder.add(
            NewSymbol::new("abs", SymbolBinding::GLOBAL, SymbolType::OBJECT)
                .with_shndx(SHN_ABS)
                .with_value(0x1234),
        ),
    ];
    let built = builder.try_build().unwrap();
    let index = |position: usize| built.indices[position];
    let indices = Indices {
        section: index(positions[0]),
        foo: index(positions[1]),
        bar: index(positions[2]),
        absolute: index(positions[3]),
    };
    let mut extended = vec![0; built.indices.len() + 1];
    extended[usize_of(indices.foo)] = TEXT_FOO;
    let extended = SymbolSectionIndexTable { indices: extended };
    (built, indices, extended)
}

/// Build an `ET_REL` file with a COMDAT group, an unnamed group, a `SHT_SYMTAB_SHNDX`
/// section and two relocation sections.
fn relocatable(encoding: Encoding) -> (ElfFile, Indices) {
    let (built, indices, extended) = symbols(encoding);
    let rela = padded(&rela_table(&indices), encoding, RELA_ENTSIZE);
    let rel = rel_table(&indices)
        .write(encoding, Machine::X86_64)
        .unwrap();
    let group = words(encoding, &[GRP_COMDAT, TEXT_FOO, RELA_TEXT_FOO]);
    let unnamed_group = words(encoding, &[0, TEXT]);
    let symtab = Some(".symtab");
    let rela_entsize = u64::try_from(RELA_ENTSIZE).unwrap();
    let sections = [
        (
            ".text",
            SectionType::PROGBITS,
            SHF_EXECINSTR,
            vec![0x90; 8],
            None,
            0,
            0,
        ),
        (
            ".text.foo",
            SectionType::PROGBITS,
            SHF_EXECINSTR | SHF_GROUP,
            vec![0xc3; 4],
            None,
            0,
            0,
        ),
        (
            ".rela.text.foo",
            SectionType::RELA,
            SHF_INFO_LINK | SHF_GROUP,
            rela,
            symtab,
            TEXT_FOO,
            rela_entsize,
        ),
        (
            ".group",
            SectionType::GROUP,
            0,
            group,
            symtab,
            indices.foo,
            4,
        ),
        (
            ".group",
            SectionType::GROUP,
            0,
            unnamed_group,
            symtab,
            indices.section,
            4,
        ),
        (
            ".symtab",
            SectionType::SYMTAB,
            0,
            built.symbols,
            Some(".strtab"),
            built.first_non_local,
            24,
        ),
        (".strtab", SectionType::STRTAB, 0, built.strings, None, 0, 0),
        (
            ".symtab_shndx",
            SectionType::SYMTAB_SHNDX,
            0,
            extended.write(encoding),
            symtab,
            0,
            4,
        ),
        (".rel.text", SectionType::REL, 0, rel, symtab, TEXT, 16),
    ];
    let builder = ElfBuilder::new(encoding)
        .file_type(FileType::REL)
        .machine(Machine::X86_64);
    let elf = sections
        .into_iter()
        .fold(
            builder,
            |builder, (name, kind, flags, data, link, info, entsize)| {
                builder.add_section(section(name, kind, flags, data, link, info, entsize))
            },
        )
        .try_build()
        .unwrap();
    for (index, name) in [
        (TEXT, ".text"),
        (TEXT_FOO, ".text.foo"),
        (SYMTAB, ".symtab"),
        (SYMTAB_SHNDX, ".symtab_shndx"),
        (REL_TEXT, ".rel.text"),
    ] {
        assert_eq!(elf.section_names()[usize_of(index)], name);
    }
    (elf, indices)
}

#[test]
fn static_symbol_list_resolves_extended_indices() {
    let (elf, indices) = relocatable(Encoding::ELF64_LE);
    let list = elf.symbol_list().unwrap();
    let summary: Vec<(u32, &str, Option<u32>)> = list
        .iter()
        .map(|symbol| (symbol.index, symbol.name.as_str(), symbol.section_index))
        .collect();
    assert_eq!(
        summary,
        [
            (indices.section, "", Some(TEXT)),
            (indices.foo, "foo", Some(TEXT_FOO)),
            (indices.bar, "bar", None),
            (indices.absolute, "abs", Some(u32::from(SHN_ABS))),
        ]
    );
    assert!(list.iter().all(|symbol| symbol.version.is_none()));
    assert_eq!(list.len() + 1, elf.symbols().unwrap().unwrap().len());

    // The SHN_XINDEX symbol has no section without the SHT_SYMTAB_SHNDX section.
    let mut stripped = elf.clone();
    stripped.section_headers_mut()[usize_of(SYMTAB_SHNDX)].section_type = SectionType::PROGBITS;
    let foo = stripped.lookup_symbol("foo").unwrap().unwrap();
    assert_eq!(foo.section_index, None);
}

#[test]
fn lookup_symbol_prefers_the_static_table() {
    let (elf, indices) = relocatable(Encoding::ELF64_LE);
    let foo = elf.lookup_symbol("foo").unwrap().unwrap();
    assert_eq!(
        (foo.index, foo.section_index),
        (indices.foo, Some(TEXT_FOO))
    );
    assert_eq!(foo.symbol.size, 4);
    let absolute = elf.lookup_symbol("abs").unwrap().unwrap();
    assert_eq!(absolute.symbol.value, 0x1234);
    assert_eq!(elf.lookup_symbol("missing").unwrap(), None);
    // The empty name does not find the null symbol or the section symbol.
    assert_eq!(elf.lookup_symbol("").unwrap(), None);
}

#[test]
fn relocation_sections_give_targets_and_entries() {
    let (mut elf, indices) = relocatable(Encoding::ELF64_LE);
    let expected = |target_rel: Option<usize>| {
        vec![
            RelocationSection {
                index: usize_of(RELA_TEXT_FOO),
                name: ".rela.text.foo".to_string(),
                target_section: Some(usize_of(TEXT_FOO)),
                symbol_table: Some(usize_of(SYMTAB)),
                table: rela_table(&indices),
            },
            RelocationSection {
                index: usize_of(REL_TEXT),
                name: ".rel.text".to_string(),
                target_section: target_rel,
                symbol_table: Some(usize_of(SYMTAB)),
                table: rel_table(&indices),
            },
        ]
    };
    let sections = elf.relocation_sections().unwrap();
    assert_eq!(sections, expected(Some(usize_of(TEXT))));
    let plt32 = &sections[0].table.relocations[0];
    assert_eq!(plt32.type_name(Machine::X86_64), Some("R_X86_64_PLT32"));
    assert_eq!(
        elf.section_relocations(usize_of(RELA_TEXT_FOO)).unwrap(),
        rela_table(&indices)
    );

    // Outside a relocatable file, only SHF_INFO_LINK makes sh_info a section index.
    elf.header_mut().file_type = FileType::EXEC;
    assert_eq!(elf.relocation_sections().unwrap(), expected(None));
}

#[test]
fn section_groups_give_flags_signatures_and_members() {
    let (elf, _) = relocatable(Encoding::ELF64_LE);
    let groups = elf.section_groups().unwrap();
    assert_eq!(
        groups,
        [
            SectionGroup {
                index: usize_of(GROUP),
                flags: GRP_COMDAT,
                signature: Some("foo".to_string()),
                members: vec![TEXT_FOO, RELA_TEXT_FOO],
            },
            // An unnamed STT_SECTION symbol gives the name of its section.
            SectionGroup {
                index: usize_of(SECTION_GROUP),
                flags: 0,
                signature: Some(".text".to_string()),
                members: vec![TEXT],
            },
        ]
    );

    // A group without a symbol table link has no signature. An empty group is an error.
    let mut edited = elf.clone();
    edited.section_headers_mut()[usize_of(GROUP)].link = 0;
    assert_eq!(edited.section_groups().unwrap()[0].signature, None);
    edited.section_headers_mut()[usize_of(GROUP)].size = 0;
    assert!(edited.section_groups().is_err());
}

#[test]
fn section_data_by_name_finds_the_first_section() {
    let (elf, _) = relocatable(Encoding::ELF64_LE);
    assert_eq!(
        elf.section_data_by_name(".text.foo").unwrap(),
        Some(&[0xc3; 4][..])
    );
    assert_eq!(elf.section_data_by_name(".missing").unwrap(), None);
    let mut broken = elf.clone();
    broken.section_headers_mut()[usize_of(TEXT)].offset = u64::MAX - 1;
    assert!(broken.section_data_by_name(".text").is_err());
}

#[test]
fn to_image_includes_header_edits() {
    let mut elf = ElfBuilder::new(Encoding::ELF32_BE)
        .machine(Machine::PPC)
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0x60; 8],
        ))
        .try_build()
        .unwrap();
    elf.set_entry_point(0x1234);
    let image = elf.to_image().unwrap();
    assert_eq!(image.header.entry, 0x1234);
    assert_eq!(
        image.load_segments().count(),
        elf.headers().load_segments().count()
    );
}

fn structure(error: &crate::Error) -> Option<&str> {
    error.context()?.structure.as_deref()
}

#[test]
fn symbol_accessors_are_empty_without_tables() {
    let elf = ElfBuilder::new(Encoding::ELF32_LE)
        .machine(Machine::I386)
        .add_section(BuilderSection::progbits(".text", SHF_EXECINSTR, vec![0x90]))
        .try_build()
        .unwrap();
    assert_eq!(elf.symbols().unwrap(), None);
    assert_eq!(elf.symbol_strings().unwrap(), None);
    assert_eq!(elf.symbol_list().unwrap(), []);
    assert_eq!(elf.lookup_symbol("foo").unwrap(), None);
    assert_eq!(elf.relocation_sections().unwrap(), []);
    assert_eq!(elf.section_groups().unwrap(), []);
}

#[test]
fn symbol_strings_follow_the_symtab_link() {
    let (elf, indices) = relocatable(Encoding::ELF64_BE);
    let strings = elf.symbol_strings().unwrap().unwrap();
    let symbols = elf.symbols().unwrap().unwrap();
    let foo = symbols.get(usize_of(indices.foo)).unwrap();
    assert_eq!(strings.get_bytes(foo.name).unwrap(), b"foo");
}

#[test]
fn malformed_symbol_sections_are_errors() {
    let (elf, _) = relocatable(Encoding::ELF64_LE);
    let edited = |edit: fn(&mut crate::section::SectionHeader)| {
        let mut copy = elf.clone();
        edit(&mut copy.section_headers_mut()[usize_of(SYMTAB)]);
        copy
    };

    let error = edited(|symtab| symtab.size -= 1).symbol_list().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("SHT_SYMTAB"));

    let unlinked = edited(|symtab| symtab.link = 99);
    for error in [
        unlinked.symbol_strings().unwrap_err(),
        unlinked.lookup_symbol("foo").unwrap_err(),
    ] {
        assert!(
            matches!(error.kind(), ErrorKind::InvalidSection(_)),
            "{error}"
        );
        assert_eq!(structure(&error), Some("SHT_SYMTAB sh_link"));
    }

    let mut short_indices = elf.clone();
    short_indices.section_headers_mut()[usize_of(SYMTAB_SHNDX)].size = 3;
    let error = short_indices.symbol_list().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("SHT_SYMTAB_SHNDX"));
}

#[test]
fn section_relocations_check_the_section_type() {
    let (mut elf, indices) = relocatable(Encoding::ELF64_BE);
    let error = elf.section_relocations(usize_of(TEXT)).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidSection(_)),
        "{error}"
    );
    assert!(elf.section_relocations(99).is_err());
    // An `sh_entsize` of 0 selects the standard entry size.
    elf.section_headers_mut()[usize_of(REL_TEXT)].entsize = 0;
    assert_eq!(
        elf.section_relocations(usize_of(REL_TEXT)).unwrap(),
        rel_table(&indices)
    );
}
