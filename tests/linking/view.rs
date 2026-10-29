//! Test that `LinkingView` gives the same results as the linking accessors.

use elfex::{DynamicTag, ElfFile, ElfImage, LinkingView};

use crate::Linking;
use crate::fixture::{self, ELF32, ELF64, Spec};

/// Check each method of `view` against the accessor of `accessors`. Do the checks two times:
/// the second time, the view uses the tables that it keeps.
fn check_view(view: &LinkingView<'_>, accessors: &impl Linking) {
    assert_eq!(view.dynamic().cloned(), accessors.dynamic().unwrap());
    assert!(format!("{view:?}").starts_with("LinkingView { dynamic: "));
    for _ in 0..2 {
        assert_eq!(
            view.string_table().unwrap(),
            accessors.dynamic_strings().unwrap()
        );
        assert_eq!(
            view.symbol_table().unwrap().cloned(),
            accessors.dynamic_symbols().unwrap()
        );
        assert_eq!(
            view.needed_libraries().unwrap(),
            accessors.needed_libraries().unwrap()
        );
        assert_eq!(view.soname().unwrap(), accessors.soname().unwrap());
        assert_eq!(view.rpath().unwrap(), accessors.rpath().unwrap());
        assert_eq!(view.runpath().unwrap(), accessors.runpath().unwrap());
        assert_eq!(
            view.relocations().unwrap(),
            accessors.dynamic_relocations().unwrap()
        );
        assert_eq!(
            view.sysv_hash_table().unwrap().cloned(),
            accessors.sysv_hash_table().unwrap()
        );
        assert_eq!(
            view.gnu_hash_table().unwrap().cloned(),
            accessors.gnu_hash_table().unwrap()
        );
        let versions = view.version_tables().unwrap();
        assert_eq!(versions, &accessors.version_tables().unwrap());
        assert_eq!(view.version_map().unwrap(), &versions.map());
        let list = accessors.dynamic_symbol_list().unwrap();
        assert_eq!(view.symbols().unwrap(), list);
        assert_eq!(view.exports().unwrap(), accessors.exports().unwrap());
        assert_eq!(view.imports().unwrap(), accessors.imports().unwrap());
        let names = list.iter().map(|symbol| &*symbol.name);
        for name in names.chain(["missing", ""]) {
            assert_eq!(
                view.lookup(name).unwrap(),
                accessors.lookup_dynamic_symbol(name).unwrap(),
                "{name}"
            );
        }
        assert_eq!(view.init_array().unwrap(), accessors.init_array().unwrap());
        assert_eq!(view.fini_array().unwrap(), accessors.fini_array().unwrap());
        assert_eq!(
            view.preinit_array().unwrap(),
            accessors.preinit_array().unwrap()
        );
    }
}

/// Check the views of the raw file, the raw image and the mapped image of `spec`.
fn check_all(spec: Spec) {
    let fixture = fixture::build(spec);
    check_view(&fixture.elf.linking().unwrap(), &fixture.elf);
    let raw = ElfImage::parse(fixture.elf.as_bytes()).unwrap();
    check_view(&raw.linking().unwrap(), &raw);
    let base = spec.runtime_base;
    let mapped = raw.to_mapped_image_at(base).unwrap();
    let image = ElfImage::parse_mapped_at(&mapped, base).unwrap();
    check_view(&image.linking().unwrap(), &image);
}

#[test]
fn elf64_view_gives_the_accessor_results() {
    check_all(ELF64);
}

#[test]
fn elf32_view_gives_the_accessor_results() {
    check_all(ELF32);
}

/// Return the fixture file of `spec` without the hash tables in the dynamic table.
fn without_hash_tables(spec: Spec) -> ElfFile {
    let fixture = fixture::build(spec);
    let mut elf = fixture.elf.clone();
    let mut dynamic = fixture.tables.dynamic.clone();
    for entry in &mut dynamic.entries {
        if entry.tag == DynamicTag::HASH || entry.tag == DynamicTag::GNU_HASH {
            entry.tag = DynamicTag::DEBUG;
            entry.value = 0;
        }
    }
    let index = elf.section_by_name(".dynamic").unwrap().index;
    elf.set_section_data(index, dynamic.write(spec.encoding).unwrap())
        .unwrap();
    elf
}

#[test]
fn view_without_hash_tables_finds_each_symbol() {
    for spec in [ELF64, ELF32] {
        let elf = without_hash_tables(spec);
        let view = elf.linking().unwrap();
        assert_eq!(view.gnu_hash_table().unwrap(), None);
        assert_eq!(view.sysv_hash_table().unwrap(), None);
        // The search also finds the undefined symbols, which a GNU hash table does not hold.
        for symbol in elf.dynamic_symbol_list().unwrap() {
            let found = view.lookup(&symbol.name).unwrap();
            assert_eq!(found.as_ref(), Some(&symbol));
            assert_eq!(found, elf.lookup_dynamic_symbol(&symbol.name).unwrap());
        }
        assert_eq!(view.lookup("missing").unwrap(), None);
        assert_eq!(view.lookup("").unwrap(), None);
        check_view(&view, &elf);
    }
}
