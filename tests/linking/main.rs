//! Test the dynamic linking accessors of `ElfFile` and `ElfImage` with built shared objects.
//!
//! Each fixture is a shared object with `.dynsym`, `.dynstr`, hash tables, version tables,
//! relocations, a build ID note, `.init_array` and `.dynamic`. The tests read it as a raw
//! `ElfFile`, as a raw `ElfImage`, and as a loader-mapped `ElfImage` at a runtime base.
//!
//! - `packed.rs` encodes the relocations of a fixture in the Android packed and CREL formats.
//! - `view.rs` checks that `LinkingView` gives the same results as the accessors.

mod fixture;
mod packed;
mod view;

use elfex::{
    AuxvEntry, DynamicRelocations, DynamicTable, DynamicTag, EhFrameHdr, ElfFile, ElfImage,
    FileMapping, GnuHashTable, NamedSymbol, Note, Result, StringTable, SymbolTable, SysvHashTable,
    VersionTables,
};
use fixture::{BUILD_ID, DEFINED, ELF32, ELF64, Fixture, IMPORTS, Spec};

/// Declare the [`Linking`] trait with the shared accessors, and implement it for `ElfFile`
/// and `ElfImage`.
macro_rules! linking_trait {
    ($($name:ident($($arg:ident: $arg_type:ty),*) -> $ret:ty;)*) => {
        /// The linking accessors that `ElfFile` and `ElfImage` share.
        trait Linking {
            $(fn $name(&self, $($arg: $arg_type),*) -> Result<$ret>;)*
        }

        impl Linking for ElfFile {
            $(fn $name(&self, $($arg: $arg_type),*) -> Result<$ret> {
                ElfFile::$name(self, $($arg),*)
            })*
        }

        impl Linking for ElfImage {
            $(fn $name(&self, $($arg: $arg_type),*) -> Result<$ret> {
                ElfImage::$name(self, $($arg),*)
            })*
        }
    };
}

linking_trait! {
    dynamic() -> Option<DynamicTable>;
    dynamic_strings() -> Option<StringTable>;
    dynamic_symbols() -> Option<SymbolTable>;
    needed_libraries() -> Vec<String>;
    soname() -> Option<String>;
    rpath() -> Option<String>;
    runpath() -> Option<String>;
    interpreter() -> Option<String>;
    notes() -> Vec<Note>;
    build_id() -> Option<Vec<u8>>;
    core_file_mappings() -> Option<(u64, Vec<FileMapping>)>;
    auxv() -> Option<Vec<AuxvEntry>>;
    dynamic_relocations() -> DynamicRelocations;
    sysv_hash_table() -> Option<SysvHashTable>;
    gnu_hash_table() -> Option<GnuHashTable>;
    version_tables() -> VersionTables;
    dynamic_symbol_list() -> Vec<NamedSymbol>;
    exports() -> Vec<NamedSymbol>;
    imports() -> Vec<NamedSymbol>;
    lookup_dynamic_symbol(name: &str) -> Option<NamedSymbol>;
    init_array() -> Vec<u64>;
    fini_array() -> Vec<u64>;
    preinit_array() -> Vec<u64>;
    eh_frame_hdr() -> Option<EhFrameHdr>;
}

/// A symbol name, its version, its version file and the hidden flag.
type Versioned = (String, Option<String>, Option<String>, bool);

/// Return the name and version values of `symbols`, sorted by name.
fn versioned(symbols: &[NamedSymbol]) -> Vec<Versioned> {
    let mut list: Vec<Versioned> = symbols
        .iter()
        .map(|symbol| {
            (
                symbol.name.clone(),
                symbol.version.clone(),
                symbol.version_file.clone(),
                symbol.hidden,
            )
        })
        .collect();
    list.sort();
    list
}

/// Make a [`Versioned`] value.
fn entry(name: &str, version: Option<&str>, file: Option<&str>, hidden: bool) -> Versioned {
    (
        name.to_string(),
        version.map(ToString::to_string),
        file.map(ToString::to_string),
        hidden,
    )
}

/// Return the expected exports, sorted by name. `demo_hidden` has `STV_HIDDEN`.
fn expected_exports(spec: Spec) -> Vec<Versioned> {
    if spec.elf64_style {
        vec![
            entry("demo_init", Some("DEMO_2.0"), None, false),
            entry("demo_old", Some("DEMO_1.0"), None, true),
            entry("demo_value", Some("DEMO_1.0"), None, false),
        ]
    } else {
        vec![
            entry("demo_init", None, None, false),
            entry("demo_old", None, None, false),
            entry("demo_value", None, None, false),
        ]
    }
}

/// Return the expected imports, sorted by name.
fn expected_imports(spec: Spec) -> Vec<Versioned> {
    let (c_version, math_version) = if spec.elf64_style {
        ("GLIBC_2.2.5", "GLIBC_2.29")
    } else {
        ("GLIBC_2.0", "GLIBC_2.1")
    };
    vec![
        entry("cos", Some(math_version), Some("libm.so.6"), false),
        entry("malloc", Some(c_version), Some("libc.so.6"), false),
    ]
}

/// Cut `value` to the class size of `spec`.
fn wrap(spec: Spec, value: u64) -> u64 {
    if spec.encoding.is_64bit() {
        value
    } else {
        value & u64::from(u32::MAX)
    }
}

/// Convert a `u64` to `usize` in a test.
fn to_usize(value: u64) -> usize {
    usize::try_from(value).expect("the value should fit in usize")
}

/// Check the symbols, the hash tables and the versions of `view`.
fn check_symbols(view: &impl Linking, fixture: &Fixture) {
    let tables = &fixture.tables;
    let symbols = view.dynamic_symbols().unwrap().expect("dynamic symbols");
    assert_eq!(symbols, tables.symbols);
    let strings = view.dynamic_strings().unwrap().expect("dynamic strings");
    assert_eq!(strings.as_bytes(), tables.strings);
    assert_eq!(
        versioned(&view.exports().unwrap()),
        expected_exports(fixture.spec)
    );
    assert_eq!(
        versioned(&view.imports().unwrap()),
        expected_imports(fixture.spec)
    );
    let list = view.dynamic_symbol_list().unwrap();
    assert_eq!(list.len(), IMPORTS.len() + DEFINED.len());
    let hidden = list.iter().find(|symbol| symbol.name == "demo_hidden");
    assert!(hidden.is_some_and(|symbol| !symbol.symbol.is_undefined()));

    // The GNU hash table finds each defined symbol, but no undefined symbol.
    assert_eq!(
        view.gnu_hash_table().unwrap().as_ref(),
        Some(&tables.gnu_hash)
    );
    for name in DEFINED {
        let found = view.lookup_dynamic_symbol(name).unwrap().expect(name);
        assert_eq!(found.name, name);
        assert_eq!(
            tables.symbols.get(to_usize(u64::from(found.index))),
            Some(&found.symbol)
        );
    }
    for name in [IMPORTS[0], "missing"] {
        assert_eq!(view.lookup_dynamic_symbol(name).unwrap(), None);
    }

    // The System V hash table finds all symbols.
    assert_eq!(view.sysv_hash_table().unwrap(), tables.sysv_hash);
    if let Some(table) = &tables.sysv_hash {
        for (index, symbol) in symbols.iter().enumerate().skip(1) {
            let name = strings.get_bytes(symbol.name).unwrap();
            let found = table.lookup(name, |candidate| {
                let candidate = symbols.get(usize::try_from(candidate).ok()?)?;
                strings.get_bytes(candidate.name).ok()
            });
            assert_eq!(found, Some(u32::try_from(index).unwrap()));
        }
    }

    let versions = view.version_tables().unwrap();
    assert_eq!(versions.versym.as_ref(), Some(&tables.versym));
    assert_eq!(versions.definitions, tables.definitions);
    assert_eq!(versions.requirements.as_ref(), Some(&tables.requirements));
}

/// Check all linking accessors of `view`. `init_array` is the expected `.init_array` word.
fn check_linking(view: &impl Linking, fixture: &Fixture, init_array: u64) {
    let tables = &fixture.tables;
    assert!(view.dynamic().unwrap().is_some());
    assert_eq!(view.needed_libraries().unwrap(), ["libc.so.6", "libm.so.6"]);
    assert_eq!(view.soname().unwrap().as_deref(), Some("libdemo.so"));
    assert_eq!(view.runpath().unwrap().as_deref(), Some("$ORIGIN/lib"));
    assert_eq!(view.rpath().unwrap(), None);
    assert_eq!(view.interpreter().unwrap(), None);
    check_symbols(view, fixture);

    let relocations = view.dynamic_relocations().unwrap();
    let (rela, rel) = if fixture.spec.elf64_style {
        (Some(&tables.relocations), None)
    } else {
        (None, Some(&tables.relocations))
    };
    assert_eq!(relocations.rela.as_ref(), rela);
    assert_eq!(relocations.rel.as_ref(), rel);
    assert_eq!(relocations.plt, None);
    assert_eq!(relocations.relr, tables.relr);

    assert_eq!(view.build_id().unwrap(), Some(BUILD_ID.to_vec()));
    assert_eq!(view.notes().unwrap().len(), 1);
    assert_eq!(view.core_file_mappings().unwrap(), None);
    assert_eq!(view.auxv().unwrap(), None);
    assert_eq!(view.init_array().unwrap(), [init_array]);
    assert_eq!(view.fini_array().unwrap(), Vec::<u64>::new());
    assert_eq!(view.preinit_array().unwrap(), Vec::<u64>::new());
    assert_eq!(view.eh_frame_hdr().unwrap(), None);
}

/// Write runtime addresses into the `d_ptr` entries of the dynamic table in `mapped`, as
/// glibc does in a loaded process.
fn glibc_rewrite(fixture: &Fixture, mapped: &mut [u8], origin: u64, bias: u64) {
    let spec = fixture.spec;
    let mut table = fixture.tables.dynamic.clone();
    for entry in &mut table.entries {
        if entry.tag.is_pointer(spec.machine) {
            entry.value = wrap(spec, entry.value.wrapping_add(bias));
        }
    }
    let bytes = table.write(spec.encoding).unwrap();
    let start = to_usize(fixture.layout.address(".dynamic") - origin);
    mapped[start..start + bytes.len()].copy_from_slice(&bytes);
}

/// Check the accessors of the raw file, the raw image and the mapped image of `spec`.
fn check_all_views(spec: Spec) {
    let fixture = fixture::build(spec);
    assert!(!fixture.elf.validate().has_errors());
    let file_word = fixture.tables.init_array_word;
    check_linking(&fixture.elf, &fixture, file_word);

    let raw = ElfImage::parse(fixture.elf.as_bytes()).unwrap();
    check_linking(&raw, &fixture, file_word);

    let base = spec.runtime_base;
    let origin = raw.image_origin().unwrap();
    let bias = wrap(spec, base.wrapping_sub(origin));
    let mut mapped = raw.to_mapped_image_at(base).unwrap();
    glibc_rewrite(&fixture, &mut mapped, origin, bias);
    let image = ElfImage::parse_mapped_at(&mapped, base).unwrap();
    assert_eq!(image.load_bias(), Some(bias));

    // The dynamic table holds runtime addresses. The accessors translate them.
    let strtab = fixture.layout.address(".dynstr");
    let dynamic = image.dynamic().unwrap().unwrap();
    assert_eq!(dynamic.get(DynamicTag::STRTAB), Some(strtab + bias));
    assert_eq!(
        dynamic.get(DynamicTag::STRSZ),
        fixture.tables.dynamic.get(DynamicTag::STRSZ)
    );
    assert_eq!(image.resolve_pointer(strtab + bias), strtab);
    assert_eq!(image.resolve_pointer(strtab), strtab);
    assert_eq!(raw.resolve_pointer(strtab + bias), strtab + bias);

    // The dynamic linker relocated the `.init_array` word.
    let (init_address, init_value) = fixture.tables.relocated[0];
    assert_eq!(init_address, fixture.layout.address(".init_array"));
    check_linking(&image, &fixture, wrap(spec, init_value + bias));

    // Restore the file addresses, as for a dump of the process.
    let mut restored = image.clone();
    let pointers = fixture
        .tables
        .dynamic
        .entries
        .iter()
        .filter(|entry| entry.tag.is_pointer(spec.machine))
        .count();
    assert_eq!(restored.restore_dynamic_pointers().unwrap(), pointers);
    assert_eq!(restored.dynamic().unwrap().unwrap(), fixture.tables.dynamic);
    assert_eq!(restored.restore_dynamic_pointers().unwrap(), 0);
    let dump = ElfImage::parse(&restored.try_build().unwrap()).unwrap();
    assert_eq!(dump.dynamic().unwrap().unwrap(), fixture.tables.dynamic);
    // Only the `d_ptr` fields change.
    let start = to_usize(fixture.layout.address(".dynamic") - origin);
    let mut expected = mapped.clone();
    let table = fixture.tables.dynamic.write(spec.encoding).unwrap();
    expected[start..start + table.len()].copy_from_slice(&table);
    assert_eq!(restored.to_mapped_image().unwrap(), expected);
}

/// Return `plain` with each relocated word of `fixture` set to its value plus `bias`.
fn expected_mapped(fixture: &Fixture, plain: &[u8], origin: u64, bias: u64) -> Vec<u8> {
    let spec = fixture.spec;
    let mut expected = plain.to_vec();
    for &(vaddr, value) in &fixture.tables.relocated {
        let offset = to_usize(vaddr - origin);
        let value = wrap(spec, value.wrapping_add(bias));
        spec.encoding
            .put_addr(&mut expected, offset, value)
            .unwrap();
    }
    expected
}

/// Check that `to_mapped_image_at` changes exactly the relocated words.
fn check_relocation(spec: Spec, other_base: u64) {
    let fixture = fixture::build(spec);
    let raw = ElfImage::parse(fixture.elf.as_bytes()).unwrap();
    let origin = raw.image_origin().unwrap();
    let plain = raw.to_mapped_image().unwrap();
    let base = spec.runtime_base;
    let bias = wrap(spec, base.wrapping_sub(origin));
    let relocated = raw.to_mapped_image_at(base).unwrap();
    let expected = expected_mapped(&fixture, &plain, origin, bias);
    assert_eq!(relocated, expected);
    assert_ne!(relocated, plain);

    // Relocate the mapped image again: the words already hold the old load bias.
    let mapped = ElfImage::parse_mapped_at(&relocated, base).unwrap();
    let other_bias = wrap(spec, other_base.wrapping_sub(origin));
    let again = mapped.to_mapped_image_at(other_base).unwrap();
    assert_eq!(again, expected_mapped(&fixture, &plain, origin, other_bias));

    // A mapped image without a runtime base has the current load bias 0. Thus `Rel` and
    // `RELR` add the full new load bias to words that already hold the old load bias.
    let unknown = ElfImage::parse_mapped(&relocated).unwrap();
    let from_unknown = unknown.to_mapped_image_at(other_base).unwrap();
    assert_ne!(from_unknown, again);
    if !spec.elf64_style {
        let doubled = wrap(spec, bias.wrapping_add(other_bias));
        assert_eq!(
            from_unknown,
            expected_mapped(&fixture, &plain, origin, doubled)
        );
    }
}

#[test]
fn elf64_little_endian_x86_64_views() {
    check_all_views(ELF64);
}

#[test]
fn elf32_big_endian_ppc_views() {
    check_all_views(ELF32);
}

#[test]
fn elf64_to_mapped_image_at_patches_the_relocated_words() {
    check_relocation(ELF64, 0x5555_0000_0000);
    // The address arithmetic wraps.
    check_relocation(ELF64, 0xffff_ffff_ffff_0000);
}

#[test]
fn elf32_to_mapped_image_at_patches_the_relocated_words() {
    check_relocation(ELF32, 0x1000_0000);
    // ELF32 address arithmetic wraps at 32 bits.
    check_relocation(ELF32, 0xffff_f000);
}

#[test]
fn file_and_image_without_dynamic_table_give_empty_results() {
    let elf = elfex::ElfBuilder::new(elfex::Encoding::ELF64_LE)
        .add_section(elfex::BuilderSection::progbits(
            ".text",
            elfex::section::SHF_ALLOC | elfex::section::SHF_EXECINSTR,
            vec![0xc3],
        ))
        .build();
    let image = ElfImage::parse(elf.as_bytes()).unwrap();
    check_empty(&elf);
    check_empty(&image);
    assert_eq!(elf.symbols().unwrap(), None);
    assert_eq!(elf.symbol_strings().unwrap(), None);
    assert_eq!(
        image.to_mapped_image_at(0x1000_0000).unwrap(),
        image.to_mapped_image().unwrap()
    );

    // An image without a `PT_LOAD` segment has no origin.
    let empty = ElfImage::new(image.header, Vec::new());
    assert!(matches!(
        empty.to_mapped_image_at(0x1000_0000).unwrap_err().kind(),
        elfex::ErrorKind::InvalidSegment(_)
    ));
}

/// Check that a file without a dynamic table gives empty results.
fn check_empty(view: &impl Linking) {
    assert_eq!(view.dynamic().unwrap(), None);
    assert_eq!(view.needed_libraries().unwrap(), Vec::<String>::new());
    assert_eq!(view.soname().unwrap(), None);
    assert_eq!(view.dynamic_symbols().unwrap(), None);
    assert_eq!(
        view.dynamic_relocations().unwrap(),
        DynamicRelocations::default()
    );
    assert_eq!(view.version_tables().unwrap(), VersionTables::default());
    assert_eq!(view.exports().unwrap(), Vec::<NamedSymbol>::new());
    assert_eq!(view.lookup_dynamic_symbol("main").unwrap(), None);
    assert_eq!(view.build_id().unwrap(), None);
    assert_eq!(view.init_array().unwrap(), Vec::<u64>::new());
}
