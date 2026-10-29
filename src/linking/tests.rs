//! Tests of the linking readers with a flat address space.

use super::*;
use crate::ErrorKind;
use crate::dynamic::DynamicEntry;
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::reloc::x86_64::{R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE};
use crate::section::{SHN_ABS, SHN_UNDEF, SHN_XINDEX};
use crate::strtab::StringTableBuilder;
use crate::symbol::{
    NamedSymbol, Symbol, SymbolBinding, SymbolSectionIndexTable, SymbolTable, SymbolType,
    SymbolVisibility,
};
use crate::version::{
    VER_FLG_BASE, VersionDefinition, VersionNeedEntry, VersionRequirement, VersymTable,
};

mod packed;
mod sections;
mod view;

/// One contiguous memory range at `base`, a dynamic table and note tables.
struct Flat {
    encoding: Encoding,
    machine: Machine,
    base: u64,
    memory: Vec<u8>,
    dynamic: Option<Vec<u8>>,
    /// A value that `resolve_pointer` subtracts from each value.
    pointer_bias: u64,
    notes: Vec<(Vec<u8>, u64)>,
    /// The virtual address and the bytes of a `PT_GNU_EH_FRAME` segment.
    eh_frame_hdr: Option<(u64, Vec<u8>)>,
    /// Table sections: the table, the bytes, `sh_entsize` and `sh_info`.
    tables: Vec<(TableSection, Vec<u8>, u64, u32)>,
}

impl Flat {
    fn new(encoding: Encoding, machine: Machine) -> Self {
        Self {
            encoding,
            machine,
            base: 0x1000,
            memory: Vec::new(),
            dynamic: None,
            pointer_bias: 0,
            notes: Vec::new(),
            eh_frame_hdr: None,
            tables: Vec::new(),
        }
    }

    /// Append `data` at the next 8-byte boundary and return its virtual address.
    fn place(&mut self, data: &[u8]) -> u64 {
        while !self.memory.len().is_multiple_of(8) {
            self.memory.push(0);
        }
        let address = self.base + u64::try_from(self.memory.len()).unwrap();
        self.memory.extend_from_slice(data);
        address
    }

    fn set_dynamic(&mut self, entries: &[(DynamicTag, u64)]) {
        let table = DynamicTable {
            entries: entries
                .iter()
                .map(|&(tag, value)| DynamicEntry::new(tag, value))
                .collect(),
        };
        self.dynamic = Some(table.write(self.encoding).unwrap());
    }
}

impl<'a> AddressSpace<'a> for &'a Flat {
    fn encoding(&self) -> Encoding {
        self.encoding
    }

    fn machine(&self) -> Machine {
        self.machine
    }

    fn slice_from_vaddr(&self, vaddr: u64) -> Result<&'a [u8]> {
        let flat: &'a Flat = self;
        vaddr
            .checked_sub(flat.base)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| flat.memory.get(offset..))
            .ok_or_else(|| Error::invalid_address(vaddr))
    }

    fn resolve_pointer(&self, value: u64) -> u64 {
        value.wrapping_sub(self.pointer_bias)
    }

    fn dynamic_bytes(&self) -> Result<Option<&'a [u8]>> {
        let flat: &'a Flat = self;
        Ok(flat.dynamic.as_deref())
    }

    fn segments(&self, segment_type: SegmentType) -> Result<Vec<SegmentBytes<'a>>> {
        let flat: &'a Flat = self;
        let hdr = flat
            .eh_frame_hdr
            .as_ref()
            .filter(|_| segment_type == SegmentType::GNU_EH_FRAME);
        Ok(hdr
            .map(|(vaddr, data)| SegmentBytes {
                header: ProgramHeader {
                    segment_type,
                    vaddr: *vaddr,
                    filesz: len(data),
                    memsz: len(data),
                    ..ProgramHeader::default()
                },
                data,
            })
            .into_iter()
            .collect())
    }

    fn note_sources(&self) -> Result<Vec<NoteSource<'a>>> {
        let flat: &'a Flat = self;
        Ok(flat
            .notes
            .iter()
            .map(|(data, address)| NoteSource {
                data,
                align: 4,
                address: *address,
            })
            .collect())
    }

    fn table_section(&self, table: TableSection) -> Result<Option<SectionTable<'a>>> {
        let flat: &'a Flat = self;
        Ok(flat
            .tables
            .iter()
            .find(|(kind, ..)| *kind == table)
            .map(|(_, data, entsize, info)| SectionTable {
                data,
                entsize: *entsize,
                info: *info,
            }))
    }
}

fn symbol(name: u32, value: u64, binding: SymbolBinding, shndx: u16) -> Symbol {
    Symbol {
        name,
        value,
        size: 8,
        info: Symbol::make_info(binding, SymbolType::FUNC),
        other: 0,
        shndx,
    }
}

fn len(bytes: &[u8]) -> u64 {
    u64::try_from(bytes.len()).unwrap()
}

fn names<'a>(symbols: &'a [NamedSymbol<'_>]) -> Vec<&'a str> {
    symbols.iter().map(|symbol| &*symbol.name).collect()
}

/// The list accessors of `ElfFile` and `ElfImage`, on a [`Linker`].
impl<'a> Linker<'a> {
    fn exports(&self) -> Result<Vec<NamedSymbol<'a>>> {
        self.symbol_list(symbols::is_export)
    }

    fn imports(&self) -> Result<Vec<NamedSymbol<'a>>> {
        self.symbol_list(symbols::is_import)
    }

    fn all_symbols(&self) -> Result<Vec<NamedSymbol<'a>>> {
        self.symbol_list(symbols::is_any)
    }

    fn version_tables(&self) -> Result<VersionTables> {
        self.versions(&|| Ok(self.symbols()?.map(|table| table.len())))
    }
}

fn structure(error: &Error) -> Option<&str> {
    error.context()?.structure.as_deref()
}

#[test]
fn elf32_symbols_with_sysv_hash() {
    let encoding = Encoding::ELF32_BE;
    let mut strings = StringTableBuilder::new();
    let libc = strings.add("libc.so.6").unwrap();
    let soname = strings.add("libtest.so").unwrap();
    let foo = strings.add("foo").unwrap();
    let bar = strings.add("bar").unwrap();
    let mut hidden = symbol(
        strings.add("hidden").unwrap(),
        0x1200,
        SymbolBinding::GLOBAL,
        1,
    );
    hidden.other = SymbolVisibility::HIDDEN.0;
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(foo, 0x1100, SymbolBinding::GLOBAL, 1),
            symbol(bar, 0, SymbolBinding::GLOBAL, SHN_UNDEF),
            hidden,
        ],
    };
    let hash_names: [&[u8]; 4] = [b"", b"foo", b"bar", b"hidden"];
    let hash = SysvHashTable::try_build(&hash_names, 0).unwrap();
    let mut flat = Flat::new(encoding, Machine::PPC);
    let strtab = flat.place(strings.as_bytes());
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let hash_address = flat.place(&hash.write(encoding, 4).unwrap());
    flat.set_dynamic(&[
        (DynamicTag::NEEDED, u64::from(libc)),
        (DynamicTag::SONAME, u64::from(soname)),
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::STRSZ, len(strings.as_bytes())),
        (DynamicTag::SYMTAB, symtab),
        (DynamicTag::HASH, hash_address),
    ]);

    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.needed_libraries().unwrap(), ["libc.so.6"]);
    let soname = linker.string_entry(DynamicTag::SONAME).unwrap();
    assert_eq!(soname.as_deref(), Some("libtest.so"));
    assert_eq!(linker.string_entry(DynamicTag::RUNPATH).unwrap(), None);
    assert_eq!(linker.symbols().unwrap().as_ref(), Some(&symbols));
    assert_eq!(linker.sysv_hash().unwrap().as_ref(), Some(&hash));
    assert_eq!(linker.gnu_hash().unwrap(), None);
    let found = linker.lookup("bar").unwrap().unwrap();
    assert_eq!((found.index, &*found.name), (2, "bar"));
    assert_eq!((found.version, found.hidden), (None, false));
    assert_eq!(linker.lookup("missing").unwrap(), None);
    assert_eq!(names(&linker.exports().unwrap()), ["foo"]);
    assert_eq!(names(&linker.imports().unwrap()), ["bar"]);
    assert_eq!(
        names(&linker.all_symbols().unwrap()),
        ["foo", "bar", "hidden"]
    );
}

#[test]
fn elf64_symbol_count_from_gnu_hash_and_relocations() {
    let encoding = Encoding::ELF64_LE;
    let mut strings = StringTableBuilder::new();
    let bar = strings.add("bar").unwrap();
    let qux = strings.add("qux").unwrap();
    let hashed_names: [&[u8]; 2] = [b"foo", b"baz"];
    let hashed = [
        symbol(
            strings.add("foo").unwrap(),
            0x1100,
            SymbolBinding::GLOBAL,
            1,
        ),
        symbol(strings.add("baz").unwrap(), 0x1108, SymbolBinding::WEAK, 1),
    ];
    let (gnu, order) = GnuHashTable::try_build(&hashed_names, 2, encoding, 0).unwrap();
    let mut symbols = vec![
        Symbol::default(),
        symbol(bar, 0, SymbolBinding::GLOBAL, SHN_UNDEF),
    ];
    symbols.extend(order.iter().map(|&position| hashed[position]));
    // Symbol 4 is not in the hash table. Only a relocation refers to it.
    symbols.push(symbol(qux, 0, SymbolBinding::GLOBAL, SHN_UNDEF));
    let symbols = SymbolTable { symbols };
    let rela = RelocationTable {
        relocations: vec![
            Relocation::with_addend(0x2000, 0, R_X86_64_RELATIVE, 0x1100),
            Relocation::with_addend(0x2008, 4, R_X86_64_JUMP_SLOT, 0),
        ],
        with_addend: true,
    };
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let strtab = flat.place(strings.as_bytes());
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let gnu_address = flat.place(&gnu.write(encoding).unwrap());
    let rela_bytes = rela.write(encoding, Machine::X86_64).unwrap();
    let rela_address = flat.place(&rela_bytes);
    flat.set_dynamic(&[
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::SYMTAB, symtab),
        (DynamicTag::GNU_HASH, gnu_address),
        (DynamicTag::RELA, rela_address),
        (DynamicTag::RELASZ, len(&rela_bytes)),
        (DynamicTag::RELAENT, 24),
    ]);

    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.symbols().unwrap().as_ref(), Some(&symbols));
    let relocations = linker.relocations().unwrap();
    assert_eq!(relocations.rela, Some(rela));
    assert_eq!(
        (&relocations.rel, &relocations.plt, &relocations.relr),
        (&None, &None, &None)
    );
    for name in ["foo", "baz"] {
        let found = linker.lookup(name).unwrap().unwrap();
        let index = usize::try_from(found.index).unwrap();
        assert_eq!(found.symbol, symbols.symbols[index]);
        assert_eq!(found.name, name);
    }
    // The GNU hash table does not hold undefined symbols.
    assert_eq!(linker.lookup("qux").unwrap(), None);
    assert_eq!(names(&linker.imports().unwrap()), ["bar", "qux"]);
}

#[test]
fn symbol_count_from_string_table_distance() {
    let encoding = Encoding::ELF64_BE;
    let symbols = SymbolTable {
        symbols: vec![Symbol::default(), symbol(1, 0x10, SymbolBinding::GLOBAL, 1)],
    };
    let mut flat = Flat::new(encoding, Machine::PPC64);
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let strtab = flat.place(b"\0abc\0");
    flat.set_dynamic(&[
        (DynamicTag::SYMTAB, symtab),
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::SYMENT, 24),
    ]);
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.symbols().unwrap().as_ref(), Some(&symbols));
    // A linear search finds the symbol without a hash table.
    let found = linker.lookup("abc").unwrap().unwrap();
    assert_eq!(found.index, 1);

    // The string table before the symbol table gives no count.
    drop((linker, found));
    flat.set_dynamic(&[(DynamicTag::SYMTAB, strtab), (DynamicTag::STRTAB, symtab)]);
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.symbols().unwrap(), None);
    assert_eq!(linker.all_symbols().unwrap(), Vec::<NamedSymbol<'_>>::new());
}

#[test]
fn mips_symbol_count_from_symtabno() {
    let encoding = Encoding::ELF32_BE;
    let mut strings = StringTableBuilder::new();
    let foo = strings.add("foo").unwrap();
    let bar = strings.add("bar").unwrap();
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(foo, 0x1100, SymbolBinding::GLOBAL, 1),
            symbol(bar, 0x1108, SymbolBinding::GLOBAL, 1),
        ],
    };
    // The hash table covers only the first two symbols.
    let hash_names: [&[u8]; 2] = [b"", b"foo"];
    let hash = SysvHashTable::try_build(&hash_names, 1).unwrap();
    let mut flat = Flat::new(encoding, Machine::MIPS);
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let hash_address = flat.place(&hash.write(encoding, 4).unwrap());
    let strtab = flat.place(strings.as_bytes());
    flat.set_dynamic(&[
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::STRSZ, len(strings.as_bytes())),
        (DynamicTag::SYMTAB, symtab),
        (DynamicTag::HASH, hash_address),
        (DynamicTag::MIPS_SYMTABNO, 3),
    ]);
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.symbols().unwrap().as_ref(), Some(&symbols));
    assert_eq!(names(&linker.all_symbols().unwrap()), ["foo", "bar"]);

    // On other machines, the tag value is not a symbol count. The hash table gives it.
    drop(linker);
    flat.machine = Machine::PPC;
    let linker = Linker::load(&flat).unwrap();
    let table = linker.symbols().unwrap().unwrap();
    assert_eq!(table.symbols, symbols.symbols[..2]);
}

#[test]
fn dynamic_section_indices_through_symtab_shndx() {
    let encoding = Encoding::ELF64_LE;
    let mut strings = StringTableBuilder::new();
    let names_list = ["big", "absolute", "undefined"];
    let offsets: Vec<u32> = names_list
        .iter()
        .map(|name| strings.add(name).unwrap())
        .collect();
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(offsets[0], 0x10, SymbolBinding::GLOBAL, SHN_XINDEX),
            symbol(offsets[1], 0x20, SymbolBinding::GLOBAL, SHN_ABS),
            symbol(offsets[2], 0, SymbolBinding::GLOBAL, SHN_UNDEF),
        ],
    };
    let indices = SymbolSectionIndexTable {
        indices: vec![0, 0x1_0005, 0, 0],
    };
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let strtab = flat.place(strings.as_bytes());
    let shndx = flat.place(&indices.write(encoding));
    flat.set_dynamic(&[
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::SYMTAB, symtab),
        (DynamicTag::SYMTAB_SHNDX, shndx),
    ]);
    let linker = Linker::load(&flat).unwrap();
    let list = linker.all_symbols().unwrap();
    let sections: Vec<Option<u32>> = list.iter().map(|symbol| symbol.section_index).collect();
    assert_eq!(names(&list), names_list);
    assert_eq!(sections, [Some(0x1_0005), Some(u32::from(SHN_ABS)), None]);
    let found = linker.lookup("big").unwrap().unwrap();
    assert_eq!(found.section_index, Some(0x1_0005));

    // Without DT_SYMTAB_SHNDX, the extended index is unknown.
    drop((linker, list, found));
    flat.set_dynamic(&[(DynamicTag::STRTAB, strtab), (DynamicTag::SYMTAB, symtab)]);
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.lookup("big").unwrap().unwrap().section_index, None);
}

#[test]
fn versions_through_the_dynamic_table() {
    let encoding = Encoding::ELF64_LE;
    let mut strings = StringTableBuilder::new();
    let libc = strings.add("libc.so.6").unwrap();
    let soname = strings.add("libv.so").unwrap();
    let vers = strings.add("VERS_1").unwrap();
    let glibc = strings.add("GLIBC_2.2.5").unwrap();
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(strings.add("foo").unwrap(), 0x10, SymbolBinding::GLOBAL, 1),
            symbol(
                strings.add("bar").unwrap(),
                0,
                SymbolBinding::GLOBAL,
                SHN_UNDEF,
            ),
            symbol(strings.add("old").unwrap(), 0x20, SymbolBinding::GLOBAL, 1),
        ],
    };
    let hash_names: [&[u8]; 4] = [b"", b"foo", b"bar", b"old"];
    let definitions = VersionDefinitionTable {
        definitions: vec![
            VersionDefinition::from_name(1, VER_FLG_BASE, soname, b"libv.so"),
            VersionDefinition::from_name(2, 0, vers, b"VERS_1"),
        ],
    };
    let requirements = VersionRequirementTable {
        requirements: vec![
            VersionRequirement::new(libc).with_entry(VersionNeedEntry::from_name(
                3,
                0,
                glibc,
                b"GLIBC_2.2.5",
            )),
        ],
    };
    let versym = VersymTable {
        entries: vec![0, 2, 3, 0x8002],
    };
    let mut flat = Flat::new(encoding, Machine::X86_64);
    // `resolve_pointer` subtracts the bias. Only the pointer tags get the bias.
    flat.pointer_bias = 0x7f00_0000_0000;
    let bias = flat.pointer_bias;
    let strtab = flat.place(strings.as_bytes()) + bias;
    let symtab = flat.place(&symbols.write(encoding).unwrap()) + bias;
    let hash = SysvHashTable::try_build(&hash_names, 1).unwrap();
    let hash_address = flat.place(&hash.write(encoding, 4).unwrap()) + bias;
    let versym_address = flat.place(&versym.write(encoding)) + bias;
    let verdef = flat.place(&definitions.write(encoding).unwrap()) + bias;
    let verneed = flat.place(&requirements.write(encoding).unwrap()) + bias;
    flat.set_dynamic(&[
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::STRSZ, len(strings.as_bytes())),
        (DynamicTag::SYMTAB, symtab),
        (DynamicTag::HASH, hash_address),
        (DynamicTag::VERSYM, versym_address),
        (DynamicTag::VERDEF, verdef),
        (DynamicTag::VERDEFNUM, 2),
        (DynamicTag::VERNEED, verneed),
        (DynamicTag::VERNEEDNUM, 1),
    ]);

    let linker = Linker::load(&flat).unwrap();
    let tables = linker.version_tables().unwrap();
    assert_eq!(tables.versym, Some(versym));
    assert_eq!(tables.definitions, Some(definitions));
    assert_eq!(tables.requirements, Some(requirements));
    let list = linker.all_symbols().unwrap();
    let versions: Vec<_> = list
        .iter()
        .map(|symbol| {
            (
                &*symbol.name,
                symbol.version.as_deref(),
                symbol.version_file.as_deref(),
                symbol.hidden,
            )
        })
        .collect();
    assert_eq!(
        versions,
        [
            ("foo", Some("VERS_1"), None, false),
            ("bar", Some("GLIBC_2.2.5"), Some("libc.so.6"), false),
            ("old", Some("VERS_1"), None, true),
        ]
    );
    let found = linker.lookup("bar").unwrap().unwrap();
    assert_eq!(found.version_file.as_deref(), Some("libc.so.6"));
}

#[test]
fn missing_tables_give_empty_results() {
    let flat = Flat::new(Encoding::ELF32_LE, Machine::I386);
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.needed_libraries().unwrap(), Vec::<String>::new());
    assert_eq!(linker.string_entry(DynamicTag::SONAME).unwrap(), None);
    assert_eq!(linker.strings().unwrap(), None);
    assert_eq!(linker.symbols().unwrap(), None);
    assert_eq!(linker.relocations().unwrap(), DynamicRelocations::default());
    assert_eq!(linker.version_tables().unwrap(), VersionTables::default());
    assert_eq!(linker.lookup("foo").unwrap(), None);
    let empty: Vec<u64> = Vec::new();
    let init = linker.array(DynamicTag::INIT_ARRAY, DynamicTag::INIT_ARRAYSZ);
    assert_eq!(init.unwrap(), empty);
    assert_eq!(notes(&&flat).unwrap(), Vec::<Note>::new());
    assert_eq!(build_id(&&flat).unwrap(), None);
    assert!(eh_frame_hdr(&&flat).unwrap().is_none());
}

#[test]
fn arrays_and_relr() {
    let encoding = Encoding::ELF32_LE;
    let mut flat = Flat::new(encoding, Machine::I386);
    let mut words = Vec::new();
    for value in [0x1100_u32, 0x1200] {
        encoding.write_u32(&mut words, value);
    }
    let array = flat.place(&words);
    let relr = RelrTable::from_addresses(vec![0x1000, 0x1004, 0x1010], encoding).unwrap();
    let relr_bytes = relr.write(encoding).unwrap();
    let relr_address = flat.place(&relr_bytes);
    flat.set_dynamic(&[
        (DynamicTag::FINI_ARRAY, array),
        (DynamicTag::FINI_ARRAYSZ, 8),
        (DynamicTag::ANDROID_RELR, relr_address),
        (DynamicTag::ANDROID_RELRSZ, len(&relr_bytes)),
        (DynamicTag::ANDROID_RELRENT, 4),
    ]);
    let linker = Linker::load(&flat).unwrap();
    let fini = linker.array(DynamicTag::FINI_ARRAY, DynamicTag::FINI_ARRAYSZ);
    assert_eq!(fini.unwrap(), [0x1100, 0x1200]);
    assert_eq!(linker.relocations().unwrap().relr, Some(relr));
}

#[test]
fn malformed_tables_are_errors() {
    let encoding = Encoding::ELF64_LE;
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let address = flat.place(&[0; 32]);
    let invalid_table = |entries: &[(DynamicTag, u64)], expected: &str| {
        let mut flat = Flat::new(encoding, Machine::X86_64);
        flat.memory = vec![0; 32];
        flat.set_dynamic(entries);
        let linker = Linker::load(&flat).unwrap();
        let error = linker
            .needed_libraries()
            .map(|_| ())
            .and_then(|()| linker.symbols().map(|_| ()))
            .and_then(|()| linker.relocations().map(|_| ()))
            .and_then(|()| {
                linker
                    .array(DynamicTag::INIT_ARRAY, DynamicTag::INIT_ARRAYSZ)
                    .map(|_| ())
            })
            .unwrap_err();
        assert!(
            matches!(error.kind(), ErrorKind::InvalidTable(_)),
            "{error}"
        );
        assert_eq!(structure(&error), Some(expected), "{error}");
    };
    invalid_table(&[(DynamicTag::NEEDED, 1)], "dynamic table");
    invalid_table(
        &[(DynamicTag::SYMTAB, address), (DynamicTag::SYMENT, 8)],
        "DT_SYMTAB",
    );
    invalid_table(&[(DynamicTag::RELA, address)], "DT_RELA");
    invalid_table(
        &[
            (DynamicTag::RELA, address),
            (DynamicTag::RELASZ, 16),
            (DynamicTag::RELAENT, 24),
        ],
        "DT_RELA",
    );
    invalid_table(
        &[
            (DynamicTag::JMPREL, address),
            (DynamicTag::PLTRELSZ, 0),
            (DynamicTag::PLTREL, 5),
        ],
        "DT_JMPREL",
    );
    invalid_table(
        &[
            (DynamicTag::RELR, address),
            (DynamicTag::RELRSZ, 8),
            (DynamicTag::RELRENT, 4),
        ],
        "DT_RELR",
    );
    invalid_table(
        &[
            (DynamicTag::INIT_ARRAY, address),
            (DynamicTag::INIT_ARRAYSZ, 12),
        ],
        "DT_INIT_ARRAY",
    );
    invalid_table(
        &[
            (DynamicTag::INIT_ARRAY, address),
            (DynamicTag::INIT_ARRAYSZ, 64),
        ],
        "DT_INIT_ARRAY",
    );
}

#[test]
fn malformed_hash_tables_have_context() {
    let encoding = Encoding::ELF64_LE;
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let mut header = Vec::new();
    for word in [0xffff_u32, 1, 1, 6] {
        encoding.write_u32(&mut header, word);
    }
    let address = flat.place(&header);
    flat.set_dynamic(&[
        (DynamicTag::GNU_HASH, address),
        (DynamicTag::HASH, address),
        (DynamicTag::SYMTAB, address),
    ]);
    let linker = Linker::load(&flat).unwrap();
    for error in [
        linker.gnu_hash().unwrap_err(),
        linker.sysv_hash().unwrap_err(),
        linker.symbols().unwrap_err(),
    ] {
        assert!(
            matches!(error.kind(), ErrorKind::InvalidTable(_)),
            "{error}"
        );
        assert_eq!(error.context().unwrap().address, Some(address));
    }
    assert_eq!(
        structure(&linker.gnu_hash().unwrap_err()),
        Some("DT_GNU_HASH")
    );
    assert_eq!(structure(&linker.sysv_hash().unwrap_err()), Some("DT_HASH"));
    drop(linker);

    // An address outside the memory is an `InvalidAddress` error.
    flat.set_dynamic(&[(DynamicTag::STRTAB, 0x10), (DynamicTag::NEEDED, 1)]);
    let error = Linker::load(&flat).unwrap().needed_libraries().unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidAddress(0x10)));
    assert_eq!(structure(&error), Some("DT_STRTAB"));
}

#[test]
fn notes_and_build_id() {
    let encoding = Encoding::ELF32_BE;
    let mut flat = Flat::new(encoding, Machine::PPC);
    let first = NoteTable {
        notes: vec![Note::new(b"Go".to_vec(), 4, b"go-id".to_vec())],
    };
    let second = NoteTable {
        notes: vec![Note::gnu_build_id(vec![1, 2, 3, 4])],
    };
    flat.notes = vec![
        (first.write(encoding, 4).unwrap(), 0x100),
        (second.write(encoding, 4).unwrap(), 0x200),
    ];
    let all = notes(&&flat).unwrap();
    assert_eq!(all.len(), 2);
    assert_eq!(all[0], first.notes[0]);
    assert_eq!(build_id(&&flat).unwrap(), Some(vec![1, 2, 3, 4]));

    flat.notes.push((vec![1, 0, 0], 0x300));
    let error = notes(&&flat).unwrap_err();
    assert_eq!(error.context().unwrap().address, Some(0x300));
}

#[test]
fn interpreter_paths() {
    assert_eq!(
        interpreter_path(b"/lib/ld.so.1\0junk").unwrap(),
        "/lib/ld.so.1"
    );
    assert_eq!(interpreter_path(b"/no/nul").unwrap(), "/no/nul");
    let error = interpreter_path(b"\xff\0").unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidUtf8));
    assert_eq!(structure(&error), Some("PT_INTERP"));
}

#[test]
fn relocation_iterator_covers_all_tables() {
    let table = |offset: u64, with_addend: bool| RelocationTable {
        relocations: vec![Relocation {
            offset,
            symbol: 0,
            r_type: 8,
            addend: with_addend.then_some(0),
        }],
        with_addend,
    };
    let relocations = DynamicRelocations {
        rela: Some(table(1, true)),
        rel: Some(table(2, false)),
        plt: Some(table(5, true)),
        relr: None,
        android: Some(table(3, true)),
        crel: Some(table(4, false)),
    };
    let offsets: Vec<u64> = relocations.iter().map(|r| r.offset).collect();
    assert_eq!(offsets, [1, 2, 3, 4, 5]);
}

#[test]
fn plt_relocations_follow_dt_pltrel() {
    let cases = [
        (Encoding::ELF64_LE, Machine::X86_64, true),
        (Encoding::ELF32_BE, Machine::PPC, false),
    ];
    for (encoding, machine, with_addend) in cases {
        let relocation = Relocation::new(0x2000, 1, 7);
        let table = RelocationTable {
            relocations: vec![Relocation {
                addend: with_addend.then_some(-8),
                ..relocation
            }],
            with_addend,
        };
        let bytes = table.write(encoding, machine).unwrap();
        let mut flat = Flat::new(encoding, machine);
        let address = flat.place(&bytes);
        let (kind, table_tag, size_tag) = if with_addend {
            (DynamicTag::RELA, DynamicTag::RELA, DynamicTag::RELASZ)
        } else {
            (DynamicTag::REL, DynamicTag::REL, DynamicTag::RELSZ)
        };
        // The Rel or Rela table has no entry size tag: the parser uses the standard size.
        flat.set_dynamic(&[
            (DynamicTag::JMPREL, address),
            (DynamicTag::PLTRELSZ, len(&bytes)),
            (DynamicTag::PLTREL, u64::try_from(kind.0).unwrap()),
            (table_tag, address),
            (size_tag, len(&bytes)),
        ]);
        let relocations = Linker::load(&flat).unwrap().relocations().unwrap();
        assert_eq!(relocations.plt.as_ref(), Some(&table));
        let other = if with_addend {
            relocations.rela
        } else {
            relocations.rel
        };
        assert_eq!(other, Some(table));
    }
}

#[test]
fn zero_size_tables_do_not_read_memory() {
    let mut flat = Flat::new(Encoding::ELF64_LE, Machine::X86_64);
    flat.set_dynamic(&[(DynamicTag::RELA, 0x10), (DynamicTag::RELASZ, 0)]);
    let relocations = Linker::load(&flat).unwrap().relocations().unwrap();
    assert_eq!(relocations.rela, Some(RelocationTable::new(true)));
}

#[test]
fn symbol_table_size_overflow_is_an_error() {
    let mut flat = Flat::new(Encoding::ELF64_BE, Machine::MIPS);
    let symtab = flat.place(&[0; 24]);
    flat.set_dynamic(&[
        (DynamicTag::SYMTAB, symtab),
        (DynamicTag::MIPS_SYMTABNO, u64::MAX),
    ]);
    let error = Linker::load(&flat).unwrap().symbols().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("DT_SYMTAB"));
}

#[test]
fn versym_size_comes_from_the_symbol_count() {
    let encoding = Encoding::ELF32_LE;
    let mut flat = Flat::new(encoding, Machine::MIPS);
    let symbols = SymbolTable {
        symbols: vec![Symbol::default(); 3],
    };
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let versym = flat.place(&[1, 0, 2, 0]);
    flat.set_dynamic(&[(DynamicTag::VERSYM, versym)]);
    // Without a symbol table, the size of the table is unknown.
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.version_tables().unwrap().versym, None);
    let with_count = |count: u64| {
        [
            (DynamicTag::VERSYM, versym),
            (DynamicTag::SYMTAB, symtab),
            (DynamicTag::MIPS_SYMTABNO, count),
        ]
    };
    drop(linker);
    flat.set_dynamic(&with_count(2));
    assert_eq!(
        Linker::load(&flat)
            .unwrap()
            .version_tables()
            .unwrap()
            .versym,
        Some(VersymTable {
            entries: vec![1, 2]
        })
    );
    flat.set_dynamic(&with_count(3));
    let error = Linker::load(&flat).unwrap().version_tables().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("DT_VERSYM"));
    assert_eq!(error.context().unwrap().address, Some(versym));
}

#[test]
fn dynamic_string_offsets_have_32_bits() {
    let mut flat = Flat::new(Encoding::ELF64_LE, Machine::X86_64);
    let strtab = flat.place(b"\0libc.so.6\0");
    flat.set_dynamic(&[
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::SONAME, 1),
        (DynamicTag::NEEDED, 1 << 32),
    ]);
    let linker = Linker::load(&flat).unwrap();
    let soname = linker.string_entry(DynamicTag::SONAME).unwrap();
    assert_eq!(soname.as_deref(), Some("libc.so.6"));
    let error = linker.needed_libraries().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("DT_STRTAB"));
}

#[test]
fn eh_frame_hdr_comes_from_the_segment() {
    let encoding = Encoding::ELF32_BE;
    let address = 0x2000;
    let hdr = EhFrameHdr {
        eh_frame_ptr: 0x3000,
        entries: vec![crate::eh_frame::EhFrameHdrEntry {
            initial_location: 0x1000,
            fde_address: 0x3010,
        }],
        ..EhFrameHdr::default()
    };
    let bytes = hdr.write(encoding, address).unwrap();
    let mut flat = Flat::new(encoding, Machine::PPC);
    flat.eh_frame_hdr = Some((address, bytes.clone()));
    let parsed = eh_frame_hdr(&&flat).unwrap().unwrap();
    assert_eq!(parsed.eh_frame_ptr, 0x3000);
    assert_eq!(parsed.find_fde(0x1004), Some(0x3010));

    let mut unsupported = bytes;
    unsupported[0] = 2;
    flat.eh_frame_hdr = Some((address, unsupported));
    let error = eh_frame_hdr(&&flat).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("PT_GNU_EH_FRAME"));
    assert_eq!(error.context().unwrap().address, Some(address));
}
