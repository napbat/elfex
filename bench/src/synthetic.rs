//! Build a large synthetic x86-64 shared object with `ElfBuilder` and the table builders.
//!
//! The table data depends on the section addresses, but the layout depends only on the
//! section sizes. Thus [`shared_object`] plans the layout with placeholder addresses
//! (`ElfBuilder::try_layout`), and then builds the file with the final data.

use std::collections::BTreeMap;

use elfex::reloc::x86_64::{R_X86_64_64, R_X86_64_RELATIVE};
use elfex::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use elfex::version::VER_FLG_BASE;
use elfex::{
    BuilderSection, DynamicEntry, DynamicTable, DynamicTag, ElfBuilder, Encoding, Error, FileType,
    GnuHashTable, Machine, NewSymbol, Note, NoteTable, Relocation, RelocationTable, Result,
    SectionPlacement, SectionType, SegmentType, Symbol, SymbolBinding, SymbolTableBuilder,
    SymbolType, VersionDefinition, VersionDefinitionTable, VersionNeedEntry, VersionRequirement,
    VersionRequirementTable, VersymTable,
};

/// The number of defined dynamic symbols. The GNU hash table contains them.
pub const DEFINED: usize = 50_000;

/// The number of undefined dynamic symbols. They come before the defined symbols.
pub const IMPORTS: usize = 1_000;

/// The number of `R_X86_64_*` relocations in `.rela.dyn`.
pub const RELOCATIONS: usize = 50_000;

/// The number of symbols in `.symtab`, without the null symbol.
pub const STATIC_SYMBOLS: usize = 50_000;

/// The build ID in `.note.gnu.build-id`.
pub const BUILD_ID: [u8; 20] = [
    0x5e, 0x1f, 0xe0, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10,
];

/// The encoding of the synthetic file.
const ENCODING: Encoding = Encoding::ELF64_LE;

/// The size of `.text`. The defined symbols point into it.
const TEXT_SIZE: usize = 0x1_0000;

/// The size of an `Elf64_Rela` entry.
const RELA_SIZE: u64 = 24;

/// Return the name of the defined dynamic symbol `index`.
#[must_use]
pub fn defined_name(index: usize) -> String {
    format!("elfex_bench_exported_function_{index:05}")
}

/// Return the name of the undefined dynamic symbol `index`.
fn import_name(index: usize) -> String {
    format!("elfex_bench_imported_function_{index:04}")
}

/// Return the name of the static symbol `index`.
fn static_name(index: usize) -> String {
    format!("elfex_bench_static_function_{index:05}")
}

/// Build the synthetic shared object and return its bytes.
///
/// # Errors
///
/// Return an error if a table builder or `ElfBuilder` fails.
pub fn shared_object() -> Result<Vec<u8>> {
    let planned = builder(&Layout::default())?.try_layout()?;
    let layout = Layout {
        sections: planned
            .sections()
            .map(|(name, placement)| (name.to_string(), placement))
            .collect(),
    };
    builder(&layout)?.try_build()?.try_build()
}

/// The section placements of the planned layout.
#[derive(Debug, Default)]
struct Layout {
    sections: BTreeMap<String, SectionPlacement>,
}

impl Layout {
    /// Return the virtual address of the section `name`, or a placeholder address before the
    /// layout is known.
    fn address(&self, name: &str) -> u64 {
        self.sections
            .get(name)
            .map_or(0x1000, |placement| placement.addr)
    }

    /// Return the section index of `name`, or 1 before the layout is known.
    fn index(&self, name: &str) -> Result<u16> {
        self.sections.get(name).map_or(Ok(1), |placement| {
            u16::try_from(placement.index).map_err(|_| Error::generic("section index overflow"))
        })
    }
}

/// Convert a count or an offset to `u64`.
fn to_u64(value: usize) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::generic("value does not fit in u64"))
}

/// Convert a count or an offset to `u32`.
fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::generic("value does not fit in u32"))
}

/// Convert a count to `u16`.
fn to_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::generic("value does not fit in u16"))
}

/// Append `string` to a string table and return its offset.
fn append(strings: &mut Vec<u8>, string: &str) -> Result<u32> {
    let offset = to_u32(strings.len())?;
    strings.extend_from_slice(string.as_bytes());
    strings.push(0);
    Ok(offset)
}

/// The dynamic linking tables of the synthetic file, serialized.
struct DynamicTables {
    gnu_hash: Vec<u8>,
    symbols: Vec<u8>,
    strings: Vec<u8>,
    versym: Vec<u8>,
    definitions: Vec<u8>,
    requirements: Vec<u8>,
    relocations: Vec<u8>,
    dynamic: Vec<u8>,
}

/// Make the dynamic symbol table, the GNU hash table, the version tables and the dynamic
/// string table. Return the tables and the version symbol table entries.
fn symbols(layout: &Layout) -> Result<(DynamicTables, Vec<u16>)> {
    let names: Vec<String> = (0..DEFINED).map(defined_name).collect();
    let name_bytes: Vec<&[u8]> = names.iter().map(String::as_bytes).collect();
    let symoffset = to_u32(IMPORTS.saturating_add(1))?;
    let (gnu_hash, order) = GnuHashTable::try_build(&name_bytes, symoffset, ENCODING, 0)?;
    let text = layout.address(".text");
    let text_index = layout.index(".text")?;
    let mut builder = SymbolTableBuilder::new(ENCODING);
    // Version 4 and 5 are the two requirements, version 2 and 3 are the definitions.
    let mut versym = vec![0_u16];
    for index in 0..IMPORTS {
        builder.add(NewSymbol::new(
            import_name(index),
            SymbolBinding::GLOBAL,
            SymbolType::FUNC,
        ));
        versym.push(if index % 2 == 0 { 4 } else { 5 });
    }
    for &position in &order {
        let offset = to_u64(position.saturating_mul(16) % TEXT_SIZE)?;
        let name = names
            .get(position)
            .ok_or_else(|| Error::generic("bad GNU hash order"))?;
        builder.add(
            NewSymbol::new(name.as_str(), SymbolBinding::GLOBAL, SymbolType::FUNC)
                .with_value(text.saturating_add(offset))
                .with_size(16)
                .with_shndx(text_index),
        );
        versym.push(if position % 2 == 0 { 2 } else { 3 });
    }
    let built = builder.try_build()?;
    let tables = DynamicTables {
        gnu_hash: gnu_hash.write(ENCODING)?,
        symbols: built.symbols,
        strings: built.strings,
        versym: Vec::new(),
        definitions: Vec::new(),
        requirements: Vec::new(),
        relocations: Vec::new(),
        dynamic: Vec::new(),
    };
    Ok((tables, versym))
}

/// Make the version definition and requirement tables. Add their strings to `strings`.
fn versions(strings: &mut Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
    let soname = append(strings, "libelfex-bench.so")?;
    let one = append(strings, "BENCH_1.0")?;
    let two = append(strings, "BENCH_2.0")?;
    let definitions = VersionDefinitionTable {
        definitions: vec![
            VersionDefinition::from_name(1, VER_FLG_BASE, soname, b"libelfex-bench.so"),
            VersionDefinition::from_name(2, 0, one, b"BENCH_1.0"),
            VersionDefinition::from_name(3, 0, two, b"BENCH_2.0").with_parent(one),
        ],
    };
    let mut requirements = VersionRequirementTable::default();
    let needs = [("libc.so.6", "GLIBC_2.2.5"), ("libm.so.6", "GLIBC_2.29")];
    for (position, (file, name)) in needs.into_iter().enumerate() {
        let file = append(strings, file)?;
        let offset = append(strings, name)?;
        let index = to_u16(position.saturating_add(4))?;
        requirements
            .requirements
            .push(
                VersionRequirement::new(file).with_entry(VersionNeedEntry::from_name(
                    index,
                    0,
                    offset,
                    name.as_bytes(),
                )),
            );
    }
    Ok((definitions.write(ENCODING)?, requirements.write(ENCODING)?))
}

/// Make the `.rela.dyn` table: one relative relocation in four, and absolute relocations
/// against the dynamic symbols.
fn relocations(layout: &Layout) -> Result<Vec<u8>> {
    let data = layout.address(".data");
    let text = i64::try_from(layout.address(".text"))
        .map_err(|_| Error::generic("text address overflow"))?;
    let symbol_count = IMPORTS.saturating_add(DEFINED);
    let mut table = RelocationTable {
        relocations: Vec::with_capacity(RELOCATIONS),
        with_addend: true,
    };
    for index in 0..RELOCATIONS {
        let offset = data.saturating_add(to_u64(index.saturating_mul(8))?);
        let relocation = if index % 4 == 0 {
            Relocation::with_addend(offset, 0, R_X86_64_RELATIVE, text)
        } else {
            let symbol = to_u32(index % symbol_count + 1)?;
            Relocation::with_addend(offset, symbol, R_X86_64_64, 0)
        };
        table.relocations.push(relocation);
    }
    table.write(ENCODING, Machine::X86_64)
}

/// Make the dynamic table. Add its strings to `strings`.
fn dynamic(layout: &Layout, strings: &mut Vec<u8>, relocations: usize) -> Result<Vec<u8>> {
    let mut entries = vec![
        (DynamicTag::NEEDED, u64::from(append(strings, "libc.so.6")?)),
        (DynamicTag::NEEDED, u64::from(append(strings, "libm.so.6")?)),
        (
            DynamicTag::SONAME,
            u64::from(append(strings, "libelfex-bench.so")?),
        ),
    ];
    entries.extend([
        (DynamicTag::GNU_HASH, layout.address(".gnu.hash")),
        (DynamicTag::STRTAB, layout.address(".dynstr")),
        (DynamicTag::SYMTAB, layout.address(".dynsym")),
        (DynamicTag::STRSZ, to_u64(strings.len())?),
        (DynamicTag::SYMENT, to_u64(Symbol::size(ENCODING.class))?),
        (DynamicTag::VERSYM, layout.address(".gnu.version")),
        (DynamicTag::VERDEF, layout.address(".gnu.version_d")),
        (DynamicTag::VERDEFNUM, 3),
        (DynamicTag::VERNEED, layout.address(".gnu.version_r")),
        (DynamicTag::VERNEEDNUM, 2),
        (DynamicTag::RELA, layout.address(".rela.dyn")),
        (DynamicTag::RELASZ, to_u64(relocations)?),
        (DynamicTag::RELAENT, RELA_SIZE),
    ]);
    DynamicTable {
        entries: entries
            .into_iter()
            .map(|(tag, value)| DynamicEntry::new(tag, value))
            .collect(),
    }
    .write(ENCODING)
}

/// Make all dynamic linking tables for the section addresses of `layout`.
fn dynamic_tables(layout: &Layout) -> Result<DynamicTables> {
    let (mut tables, versym) = symbols(layout)?;
    (tables.definitions, tables.requirements) = versions(&mut tables.strings)?;
    tables.versym = VersymTable { entries: versym }.write(ENCODING);
    tables.relocations = relocations(layout)?;
    tables.dynamic = dynamic(layout, &mut tables.strings, tables.relocations.len())?;
    Ok(tables)
}

/// Make the static symbol table and its string table. Half of the symbols are local.
fn static_symbols(layout: &Layout) -> Result<(Vec<u8>, Vec<u8>, u32)> {
    let text = layout.address(".text");
    let text_index = layout.index(".text")?;
    let mut builder = SymbolTableBuilder::new(ENCODING);
    for index in 0..STATIC_SYMBOLS {
        let binding = if index % 2 == 0 {
            SymbolBinding::LOCAL
        } else {
            SymbolBinding::GLOBAL
        };
        let offset = to_u64(index.saturating_mul(16) % TEXT_SIZE)?;
        builder.add(
            NewSymbol::new(static_name(index), binding, SymbolType::FUNC)
                .with_value(text.saturating_add(offset))
                .with_size(16)
                .with_shndx(text_index),
        );
    }
    let built = builder.try_build()?;
    Ok((built.symbols, built.strings, built.first_non_local))
}

/// Make a section with a type, an alignment, an entry size, a link and `sh_info`.
fn section(
    (name, section_type, flags): (&str, SectionType, u64),
    data: Vec<u8>,
    (addralign, entsize): (u64, u64),
    (link, info): (Option<&str>, u32),
) -> BuilderSection {
    BuilderSection {
        section_type,
        addralign,
        entsize,
        link_name: link.map(ToString::to_string),
        info,
        ..BuilderSection::progbits(name, flags, data)
    }
}

/// Make the builder for the section addresses of `layout`.
fn builder(layout: &Layout) -> Result<ElfBuilder> {
    let tables = dynamic_tables(layout)?;
    let (symtab, strtab, first_non_local) = static_symbols(layout)?;
    let build_id = NoteTable {
        notes: vec![Note::gnu_build_id(BUILD_ID.to_vec())],
    }
    .write(ENCODING, 4)?;
    let symbol_size = to_u64(Symbol::size(ENCODING.class))?;
    let dynsym = Some(".dynsym");
    let dynstr = Some(".dynstr");
    let writable = SHF_ALLOC | SHF_WRITE;
    let sections = [
        BuilderSection::note(".note.gnu.build-id", build_id),
        section(
            (".gnu.hash", SectionType::GNU_HASH, SHF_ALLOC),
            tables.gnu_hash,
            (8, 0),
            (dynsym, 0),
        ),
        section(
            (".dynsym", SectionType::DYNSYM, SHF_ALLOC),
            tables.symbols,
            (8, symbol_size),
            (dynstr, 1),
        ),
        section(
            (".dynstr", SectionType::STRTAB, SHF_ALLOC),
            tables.strings,
            (1, 0),
            (None, 0),
        ),
        section(
            (".gnu.version", SectionType::GNU_VERSYM, SHF_ALLOC),
            tables.versym,
            (2, 2),
            (dynsym, 0),
        ),
        section(
            (".gnu.version_d", SectionType::GNU_VERDEF, SHF_ALLOC),
            tables.definitions,
            (4, 0),
            (dynstr, 3),
        ),
        section(
            (".gnu.version_r", SectionType::GNU_VERNEED, SHF_ALLOC),
            tables.requirements,
            (4, 0),
            (dynstr, 2),
        ),
        section(
            (".rela.dyn", SectionType::RELA, SHF_ALLOC),
            tables.relocations,
            (8, RELA_SIZE),
            (dynsym, 0),
        ),
        section(
            (".text", SectionType::PROGBITS, SHF_ALLOC | SHF_EXECINSTR),
            vec![0xc3; TEXT_SIZE],
            (16, 0),
            (None, 0),
        ),
        section(
            (".data", SectionType::PROGBITS, writable),
            vec![0; RELOCATIONS.saturating_mul(8)],
            (8, 0),
            (None, 0),
        ),
        section(
            (".dynamic", SectionType::DYNAMIC, writable),
            tables.dynamic,
            (8, 16),
            (dynstr, 0),
        ),
        section(
            (".symtab", SectionType::SYMTAB, 0),
            symtab,
            (8, symbol_size),
            (Some(".strtab"), first_non_local),
        ),
        section(
            (".strtab", SectionType::STRTAB, 0),
            strtab,
            (1, 0),
            (None, 0),
        ),
    ];
    Ok(sections
        .into_iter()
        .fold(
            ElfBuilder::new(ENCODING)
                .file_type(FileType::DYN)
                .machine(Machine::X86_64),
            ElfBuilder::add_section,
        )
        .add_segment_for_section(SegmentType::DYNAMIC, ".dynamic")
        .add_segment_for_section(SegmentType::NOTE, ".note.gnu.build-id"))
}
