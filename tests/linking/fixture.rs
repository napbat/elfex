//! Build a small shared object with all dynamic linking tables.
//!
//! The table data depends on the section addresses, but the layout depends only on the section
//! sizes and flags. Thus [`build`] builds the file one time with placeholder addresses, reads
//! the section addresses, and builds the file again with the final data.

use std::collections::BTreeMap;

use elfex::reloc::{ppc, x86_64};
use elfex::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use elfex::symbol::{NewSymbol, SymbolTableBuilder};
use elfex::version::{
    VER_FLG_BASE, VersionDefinition, VersionDefinitionTable, VersionNeedEntry, VersionRequirement,
    VersionRequirementTable, VersymTable,
};
use elfex::{
    BuilderSection, DynamicEntry, DynamicTable, DynamicTag, ElfBuilder, ElfFile, Encoding,
    FileType, GnuHashTable, Machine, Note, NoteTable, Relocation, RelocationTable, RelrTable,
    SectionType, SegmentType, Symbol, SymbolBinding, SymbolTable, SymbolType, SymbolVisibility,
    SysvHashTable,
};

/// The build ID of the fixture.
pub const BUILD_ID: [u8; 8] = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04];

/// The undefined symbols, in dynamic symbol order (index 1 and 2).
pub const IMPORTS: [&str; 2] = ["malloc", "cos"];

/// The defined symbols, before the GNU hash order. `demo_hidden` has `STV_HIDDEN`.
pub const DEFINED: [&str; 4] = ["demo_init", "demo_value", "demo_old", "demo_hidden"];

/// The properties of one fixture file.
#[derive(Debug, Clone, Copy)]
pub struct Spec {
    /// The class and the byte order.
    pub encoding: Encoding,
    /// The target architecture.
    pub machine: Machine,
    /// `true` for `.rela.dyn`, `.relr.dyn` and `.gnu.version_d`. `false` for `.rel.dyn` and a
    /// `.hash` section.
    pub elf64_style: bool,
    /// The relative relocation type.
    pub relative: u32,
    /// The `GLOB_DAT` relocation type.
    pub glob_dat: u32,
    /// The runtime base for the mapped tests.
    pub runtime_base: u64,
}

/// An ELF64 little-endian x86-64 shared object.
pub const ELF64: Spec = Spec {
    encoding: Encoding::ELF64_LE,
    machine: Machine::X86_64,
    elf64_style: true,
    relative: x86_64::R_X86_64_RELATIVE,
    glob_dat: x86_64::R_X86_64_GLOB_DAT,
    runtime_base: 0x7f3a_5000_0000,
};

/// An ELF32 big-endian `PowerPC` shared object.
pub const ELF32: Spec = Spec {
    encoding: Encoding::ELF32_BE,
    machine: Machine::PPC,
    elf64_style: false,
    relative: ppc::R_PPC_RELATIVE,
    glob_dat: ppc::R_PPC_GLOB_DAT,
    runtime_base: 0x4000_0000,
};

/// The section addresses and indices of the first build.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    addresses: BTreeMap<String, u64>,
    indices: BTreeMap<String, u16>,
}

impl Layout {
    /// Return the virtual address of the section `name`, or a placeholder address before the
    /// first build.
    pub fn address(&self, name: &str) -> u64 {
        self.addresses.get(name).copied().unwrap_or(0x1000)
    }

    /// Return the section index of `name`, or 1 before the first build.
    fn index(&self, name: &str) -> u16 {
        self.indices.get(name).copied().unwrap_or(1)
    }
}

/// A built fixture and the tables in it.
#[derive(Debug, Clone)]
pub struct Fixture {
    pub spec: Spec,
    pub elf: ElfFile,
    pub layout: Layout,
    pub tables: Tables,
}

/// The tables of the fixture, as the test wrote them.
#[derive(Debug, Clone)]
pub struct Tables {
    pub symbols: SymbolTable,
    pub gnu_hash: GnuHashTable,
    pub sysv_hash: Option<SysvHashTable>,
    pub versym: VersymTable,
    pub definitions: Option<VersionDefinitionTable>,
    pub requirements: VersionRequirementTable,
    pub relocations: RelocationTable,
    pub relr: Option<RelrTable>,
    /// The words that `to_mapped_image_at` changes: the virtual address and the value
    /// without the load bias.
    pub relocated: Vec<(u64, u64)>,
    /// The word of `.init_array` in the file.
    pub init_array_word: u64,
    /// The dynamic string table.
    pub strings: Vec<u8>,
    /// The dynamic table as the file holds it.
    pub dynamic: DynamicTable,
    data: Vec<u8>,
    init_array: Vec<u8>,
}

/// Build the fixture for `spec`.
pub fn build(spec: Spec) -> Fixture {
    let first = builder(spec, &Layout::default()).0.build();
    let layout = Layout {
        addresses: first
            .sections()
            .map(|section| (section.name.to_string(), section.header.addr))
            .collect(),
        indices: first
            .sections()
            .map(|section| {
                (
                    section.name.to_string(),
                    u16::try_from(section.index).unwrap(),
                )
            })
            .collect(),
    };
    let (builder, tables) = builder(spec, &layout);
    let elf = builder.build();
    for section in elf.sections() {
        assert_eq!(
            layout.addresses.get(section.name),
            Some(&section.header.addr),
            "the layout of {} changed",
            section.name
        );
    }
    Fixture {
        spec,
        elf,
        layout,
        tables,
    }
}

/// Append `string` to a string table and return its offset.
fn append(strings: &mut Vec<u8>, string: &str) -> u32 {
    let offset = u32::try_from(strings.len()).unwrap();
    strings.extend_from_slice(string.as_bytes());
    strings.push(0);
    offset
}

/// Append a class-sized word.
fn word(spec: Spec, out: &mut Vec<u8>, value: u64) {
    spec.encoding.write_addr(out, value).unwrap();
}

/// Make the dynamic symbol table, the hash tables and the string table.
fn symbols(spec: Spec, layout: &Layout) -> (SymbolTable, GnuHashTable, Vec<u32>, Vec<u8>) {
    let text = layout.address(".text");
    let data = layout.address(".data");
    let values = [text, data + 0x30, text + 8, text + 4];
    let defined_names: Vec<&[u8]> = DEFINED.iter().map(|name| name.as_bytes()).collect();
    let (gnu_hash, order) = GnuHashTable::build(&defined_names, 3, spec.encoding, 0).unwrap();
    let mut builder = SymbolTableBuilder::new(spec.encoding);
    for name in IMPORTS {
        builder.add(NewSymbol::new(
            name,
            SymbolBinding::GLOBAL,
            SymbolType::FUNC,
        ));
    }
    for &position in &order {
        let (symbol_type, section) = if position == 1 {
            (SymbolType::OBJECT, ".data")
        } else {
            (SymbolType::FUNC, ".text")
        };
        let visibility = if position == 3 {
            SymbolVisibility::HIDDEN
        } else {
            SymbolVisibility::DEFAULT
        };
        let binding = if position == 2 {
            SymbolBinding::WEAK
        } else {
            SymbolBinding::GLOBAL
        };
        builder.add(
            NewSymbol::new(DEFINED[position], binding, symbol_type)
                .with_value(values[position])
                .with_size(4)
                .with_shndx(layout.index(section))
                .with_visibility(visibility),
        );
    }
    let built = builder.build();
    let table = SymbolTable::parse(&built.symbols, spec.encoding).unwrap();
    let order = order
        .iter()
        .map(|&position| u32::try_from(position).unwrap())
        .collect();
    (table, gnu_hash, order, built.strings)
}

/// Make the version tables. `order` is the GNU hash order of [`DEFINED`].
fn versions(
    spec: Spec,
    strings: &mut Vec<u8>,
    order: &[u32],
) -> (
    VersymTable,
    Option<VersionDefinitionTable>,
    VersionRequirementTable,
) {
    let files = [append(strings, "libc.so.6"), append(strings, "libm.so.6")];
    let (definitions, first_need, defined_versions) = if spec.elf64_style {
        let soname = append(strings, "libdemo.so");
        let one = append(strings, "DEMO_1.0");
        let two = append(strings, "DEMO_2.0");
        let table = VersionDefinitionTable {
            definitions: vec![
                VersionDefinition::from_name(1, VER_FLG_BASE, soname, b"libdemo.so"),
                VersionDefinition::from_name(2, 0, one, b"DEMO_1.0"),
                VersionDefinition::from_name(3, 0, two, b"DEMO_2.0").with_parent(one),
            ],
        };
        // demo_init, demo_value, demo_old (hidden), demo_hidden.
        (Some(table), 4, [3, 2, 0x8002, 1])
    } else {
        (None, 2, [1, 1, 1, 1])
    };
    let names = if spec.elf64_style {
        ["GLIBC_2.2.5", "GLIBC_2.29"]
    } else {
        ["GLIBC_2.0", "GLIBC_2.1"]
    };
    let mut requirements = VersionRequirementTable::default();
    for (position, (file, name)) in files.into_iter().zip(names).enumerate() {
        let offset = append(strings, name);
        let index = first_need + u16::try_from(position).unwrap();
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
    let mut entries = vec![0, first_need, first_need + 1];
    entries.extend(
        order
            .iter()
            .map(|&position| defined_versions[usize::try_from(position).unwrap()]),
    );
    (VersymTable { entries }, definitions, requirements)
}

/// The relocation data of the fixture.
struct RelocationData {
    table: RelocationTable,
    relr: Option<RelrTable>,
    relocated: Vec<(u64, u64)>,
    data: Vec<u8>,
    init_array: Vec<u8>,
}

/// Make the relocations, the `.data` and `.init_array` bytes, and the expected relocated
/// words.
fn relocations(spec: Spec, layout: &Layout) -> RelocationData {
    let text = layout.address(".text");
    let data = layout.address(".data");
    let init = layout.address(".init_array");
    let size = u64::try_from(spec.encoding.addr_size()).unwrap();
    let mut data_bytes = Vec::new();
    let mut init_bytes = Vec::new();
    let mut relocated = vec![(init, text), (data, data + 0x30)];
    let (table, relr) = if spec.elf64_style {
        // `Rela`: the words are 0 in the file.
        word(spec, &mut init_bytes, 0);
        for value in [0, 0, text, text + 8, data + 0x30] {
            word(spec, &mut data_bytes, value);
        }
        let addend = |value: u64| i64::try_from(value).unwrap();
        let table = RelocationTable {
            relocations: vec![
                Relocation::with_addend(init, 0, spec.relative, addend(text)),
                Relocation::with_addend(data, 0, spec.relative, addend(data + 0x30)),
                Relocation::with_addend(data + size, 1, spec.glob_dat, 0),
            ],
            with_addend: true,
        };
        let addresses = vec![data + 2 * size, data + 3 * size, data + 4 * size];
        relocated.extend([
            (data + 2 * size, text),
            (data + 3 * size, text + 8),
            (data + 4 * size, data + 0x30),
        ]);
        let relr = RelrTable::from_addresses(addresses, spec.encoding).unwrap();
        (table, Some(relr))
    } else {
        // `Rel`: the words hold the addends.
        word(spec, &mut init_bytes, text);
        for value in [data + 0x30, 0] {
            word(spec, &mut data_bytes, value);
        }
        let table = RelocationTable {
            relocations: vec![
                Relocation::new(init, 0, spec.relative),
                Relocation::new(data, 0, spec.relative),
                Relocation::new(data + size, 1, spec.glob_dat),
            ],
            with_addend: false,
        };
        (table, None)
    };
    data_bytes.resize(0x40, 0);
    RelocationData {
        table,
        relr,
        relocated,
        data: data_bytes,
        init_array: init_bytes,
    }
}

/// Make the dynamic table. Add its strings to `strings`.
fn dynamic(
    spec: Spec,
    layout: &Layout,
    strings: &mut Vec<u8>,
    relocations: &RelocationData,
) -> DynamicTable {
    let needed = [append(strings, "libc.so.6"), append(strings, "libm.so.6")];
    let soname = append(strings, "libdemo.so");
    let runpath = append(strings, "$ORIGIN/lib");
    let mut entries: Vec<(DynamicTag, u64)> = needed
        .iter()
        .map(|&offset| (DynamicTag::NEEDED, u64::from(offset)))
        .collect();
    let size = |bytes: usize| u64::try_from(bytes).unwrap();
    let word = size(spec.encoding.addr_size());
    let relocation_bytes = relocations
        .table
        .write(spec.encoding, spec.machine)
        .unwrap();
    entries.extend([
        (DynamicTag::SONAME, u64::from(soname)),
        (DynamicTag::RUNPATH, u64::from(runpath)),
        (DynamicTag::INIT_ARRAY, layout.address(".init_array")),
        (DynamicTag::INIT_ARRAYSZ, word),
        (DynamicTag::GNU_HASH, layout.address(".gnu.hash")),
        (DynamicTag::STRTAB, layout.address(".dynstr")),
        (DynamicTag::SYMTAB, layout.address(".dynsym")),
        (DynamicTag::STRSZ, size(strings.len())),
        (DynamicTag::SYMENT, size(Symbol::size(spec.encoding.class))),
        (DynamicTag::VERSYM, layout.address(".gnu.version")),
        (DynamicTag::VERNEED, layout.address(".gnu.version_r")),
        (DynamicTag::VERNEEDNUM, 2),
    ]);
    if let Some(relr) = &relocations.relr {
        let relr = relr.write(spec.encoding).unwrap();
        entries.extend([
            (DynamicTag::RELA, layout.address(".rela.dyn")),
            (DynamicTag::RELASZ, size(relocation_bytes.len())),
            (DynamicTag::RELAENT, 3 * word),
            (DynamicTag::RELR, layout.address(".relr.dyn")),
            (DynamicTag::RELRSZ, size(relr.len())),
            (DynamicTag::RELRENT, word),
            (DynamicTag::VERDEF, layout.address(".gnu.version_d")),
            (DynamicTag::VERDEFNUM, 3),
        ]);
    } else {
        entries.extend([
            (DynamicTag::HASH, layout.address(".hash")),
            (DynamicTag::REL, layout.address(".rel.dyn")),
            (DynamicTag::RELSZ, size(relocation_bytes.len())),
            (DynamicTag::RELENT, 2 * word),
        ]);
    }
    DynamicTable {
        entries: entries
            .into_iter()
            .map(|(tag, value)| DynamicEntry::new(tag, value))
            .collect(),
    }
}

/// Make the tables and the builder for `spec` with the section addresses of `layout`.
fn builder(spec: Spec, layout: &Layout) -> (ElfBuilder, Tables) {
    let (symbols, gnu_hash, order, mut strings) = symbols(spec, layout);
    let (versym, definitions, requirements) = versions(spec, &mut strings, &order);
    let relocation_data = relocations(spec, layout);
    let sysv_hash = (!spec.elf64_style).then(|| {
        let mut names: Vec<&[u8]> = vec![b""];
        names.extend(IMPORTS.iter().map(|name| name.as_bytes()));
        names.extend(
            order
                .iter()
                .map(|&p| DEFINED[usize::try_from(p).unwrap()].as_bytes()),
        );
        SysvHashTable::build(&names, 0).unwrap()
    });
    let dynamic = dynamic(spec, layout, &mut strings, &relocation_data);
    let tables = Tables {
        symbols,
        gnu_hash,
        sysv_hash,
        versym,
        definitions,
        requirements,
        relocations: relocation_data.table,
        relr: relocation_data.relr,
        relocated: relocation_data.relocated,
        init_array_word: spec
            .encoding
            .read_addr(&relocation_data.init_array, 0)
            .unwrap(),
        strings,
        dynamic,
        data: relocation_data.data,
        init_array: relocation_data.init_array,
    };
    let builder = sections(spec, &tables)
        .into_iter()
        .fold(
            ElfBuilder::new(spec.encoding)
                .file_type(FileType::DYN)
                .machine(spec.machine),
            ElfBuilder::add_section,
        )
        .add_segment_for_section(SegmentType::DYNAMIC, ".dynamic")
        .add_segment_for_section(SegmentType::NOTE, ".note.gnu.build-id");
    (builder, tables)
}

/// Make a section with a type, an alignment, an entry size, a link and `sh_info`.
fn section(
    name: &str,
    section_type: SectionType,
    flags: u64,
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

/// A section of [`table_sections`]: the name, the type, the data, the alignment and entry
/// size, and the link and `sh_info`.
type TableSection = (
    &'static str,
    SectionType,
    Vec<u8>,
    (u64, u64),
    (Option<&'static str>, u32),
);

/// Make the read-only sections of the dynamic linking tables.
fn table_sections(spec: Spec, tables: &Tables) -> Vec<BuilderSection> {
    let encoding = spec.encoding;
    let word = u64::try_from(encoding.addr_size()).unwrap();
    let symbol_size = u64::try_from(Symbol::size(encoding.class)).unwrap();
    let dynsym = Some(".dynsym");
    let dynstr = Some(".dynstr");
    let (relocation_name, relocation_type, relocation_size) = if spec.elf64_style {
        (".rela.dyn", SectionType::RELA, 3 * word)
    } else {
        (".rel.dyn", SectionType::REL, 2 * word)
    };
    let relocations = tables.relocations.write(encoding, spec.machine).unwrap();
    let list: [Option<TableSection>; 9] = [
        tables.sysv_hash.as_ref().map(|hash| {
            let data = hash.write(encoding, 4).unwrap();
            (".hash", SectionType::HASH, data, (4, 4), (dynsym, 0))
        }),
        Some((
            ".gnu.hash",
            SectionType::GNU_HASH,
            tables.gnu_hash.write(encoding).unwrap(),
            (word, 0),
            (dynsym, 0),
        )),
        Some((
            ".dynsym",
            SectionType::DYNSYM,
            tables.symbols.write(encoding).unwrap(),
            (word, symbol_size),
            (dynstr, 1),
        )),
        Some((
            ".dynstr",
            SectionType::STRTAB,
            tables.strings.clone(),
            (1, 0),
            (None, 0),
        )),
        Some((
            ".gnu.version",
            SectionType::GNU_VERSYM,
            tables.versym.write(encoding),
            (2, 2),
            (dynsym, 0),
        )),
        tables.definitions.as_ref().map(|definitions| {
            let data = definitions.write(encoding).unwrap();
            (
                ".gnu.version_d",
                SectionType::GNU_VERDEF,
                data,
                (4, 0),
                (dynstr, 3),
            )
        }),
        Some((
            ".gnu.version_r",
            SectionType::GNU_VERNEED,
            tables.requirements.write(encoding).unwrap(),
            (4, 0),
            (dynstr, 2),
        )),
        Some((
            relocation_name,
            relocation_type,
            relocations,
            (word, relocation_size),
            (dynsym, 0),
        )),
        tables.relr.as_ref().map(|relr| {
            let data = relr.write(encoding).unwrap();
            (
                ".relr.dyn",
                SectionType::RELR,
                data,
                (word, word),
                (None, 0),
            )
        }),
    ];
    list.into_iter()
        .flatten()
        .map(|(name, section_type, data, shape, link)| {
            section(name, section_type, SHF_ALLOC, data, shape, link)
        })
        .collect()
}

/// Make the sections of the fixture.
fn sections(spec: Spec, tables: &Tables) -> Vec<BuilderSection> {
    let encoding = spec.encoding;
    let word = u64::try_from(encoding.addr_size()).unwrap();
    let build_id = NoteTable {
        notes: vec![Note::gnu_build_id(BUILD_ID.to_vec())],
    };
    let writable = SHF_ALLOC | SHF_WRITE;
    let none = (None, 0);
    let mut list = vec![BuilderSection::note(
        ".note.gnu.build-id",
        build_id.write(encoding, 4).unwrap(),
    )];
    list.extend(table_sections(spec, tables));
    list.extend([
        section(
            ".text",
            SectionType::PROGBITS,
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0x90; 16],
            (16, 0),
            none,
        ),
        section(
            ".init_array",
            SectionType::INIT_ARRAY,
            writable,
            tables.init_array.clone(),
            (word, word),
            none,
        ),
        section(
            ".data",
            SectionType::PROGBITS,
            writable,
            tables.data.clone(),
            (8, 0),
            none,
        ),
        section(
            ".dynamic",
            SectionType::DYNAMIC,
            writable,
            tables.dynamic.write(encoding).unwrap(),
            (word, 2 * word),
            (Some(".dynstr"), 0),
        ),
    ]);
    list
}
