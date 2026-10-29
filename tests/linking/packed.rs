//! Test the Android packed (`APS2`) and CREL relocation formats in the built shared objects.
//!
//! Each test encodes the `.rela.dyn` or `.rel.dyn` table of a fixture in a compressed format.
//! The compressed table is smaller, so it fits in the old section range, and the layout does
//! not change.

use elfex::{DynamicTag, ElfFile, ElfImage, SectionType};

use crate::fixture::{self, ELF32, ELF64, Fixture, Spec};
use crate::{expected_mapped, wrap};

/// A compressed relocation format.
#[derive(Debug, Clone, Copy)]
enum Format {
    /// The Android packed format `APS2`.
    Android,
    /// The CREL format.
    Crel,
}

/// Return the index of the section `name` of `elf`.
fn index_of(elf: &ElfFile, name: &str) -> usize {
    elf.section_by_name(name).expect(name).index
}

/// Return the fixture of `spec`, and a copy of its file with the relocation table in `format`.
fn packed(spec: Spec, format: Format) -> (Fixture, ElfFile) {
    let fixture = fixture::build(spec);
    let mut elf = fixture.elf.clone();
    let table = &fixture.tables.relocations;
    let (name, old) = if table.with_addend {
        (
            ".rela.dyn",
            [DynamicTag::RELA, DynamicTag::RELASZ, DynamicTag::RELAENT],
        )
    } else {
        (
            ".rel.dyn",
            [DynamicTag::REL, DynamicTag::RELSZ, DynamicTag::RELENT],
        )
    };
    let (bytes, section_type, address_tag, size_tag) = match (format, table.with_addend) {
        (Format::Android, true) => (
            table.write_android_packed(spec.encoding, spec.machine),
            SectionType::ANDROID_RELA,
            DynamicTag::ANDROID_RELA,
            Some(DynamicTag::ANDROID_RELASZ),
        ),
        (Format::Android, false) => (
            table.write_android_packed(spec.encoding, spec.machine),
            SectionType::ANDROID_REL,
            DynamicTag::ANDROID_REL,
            Some(DynamicTag::ANDROID_RELSZ),
        ),
        (Format::Crel, _) => (
            table.write_crel(spec.encoding),
            SectionType::CREL,
            DynamicTag::CREL,
            None,
        ),
    };
    let bytes = bytes.unwrap();
    let size = u64::try_from(bytes.len()).unwrap();
    let index = index_of(&elf, name);
    elf.set_section_data(index, bytes).unwrap();
    let header = &mut elf.section_headers_mut()[index];
    header.section_type = section_type;
    header.entsize = 1;

    // The compressed tags replace the tags of the table. `DT_DEBUG` replaces the tags that
    // the format does not have, so that the dynamic table keeps its size.
    let [old_address, old_size, old_entsize] = old;
    let mut dynamic = fixture.tables.dynamic.clone();
    for entry in &mut dynamic.entries {
        let (tag, value) = if entry.tag == old_address {
            (address_tag, entry.value)
        } else if entry.tag == old_size {
            size_tag.map_or((DynamicTag::DEBUG, 0), |tag| (tag, size))
        } else if entry.tag == old_entsize {
            (DynamicTag::DEBUG, 0)
        } else {
            continue;
        };
        entry.tag = tag;
        entry.value = value;
    }
    let dynamic_index = index_of(&elf, ".dynamic");
    elf.set_section_data(dynamic_index, dynamic.write(spec.encoding).unwrap())
        .unwrap();
    (fixture, elf)
}

/// Check the relocation accessors and `to_mapped_image_at` for `spec` and `format`.
fn check(spec: Spec, format: Format) {
    let (fixture, elf) = packed(spec, format);
    let expected = &fixture.tables.relocations;
    let sections = elf.relocation_sections().unwrap();
    assert_eq!(sections.len(), 1, "{format:?}");
    assert_eq!(&sections[0].table, expected, "{format:?}");

    let image = ElfImage::parse(elf.as_bytes()).unwrap();
    for relocations in [
        elf.dynamic_relocations().unwrap(),
        image.dynamic_relocations().unwrap(),
    ] {
        let table = match format {
            Format::Android => &relocations.android,
            Format::Crel => &relocations.crel,
        };
        assert_eq!(table.as_ref(), Some(expected), "{format:?}");
        assert_eq!((&relocations.rela, &relocations.rel), (&None, &None));
        assert_eq!(relocations.relr, fixture.tables.relr);
    }
    // Without `.dynsym`, the symbol count comes from the hash tables and the relocations.
    assert_eq!(
        image.dynamic_symbols().unwrap(),
        Some(fixture.tables.symbols.clone())
    );

    // The compressed relocations change the same words as the plain ones.
    let origin = image.image_origin().unwrap();
    let plain = image.to_mapped_image().unwrap();
    let base = spec.runtime_base;
    let bias = wrap(spec, base.wrapping_sub(origin));
    assert_eq!(
        image.to_mapped_image_at(base).unwrap(),
        expected_mapped(&fixture, &plain, origin, bias),
        "{format:?}"
    );
}

#[test]
fn elf64_android_packed_relocations() {
    check(ELF64, Format::Android);
}

#[test]
fn elf32_android_packed_relocations() {
    check(ELF32, Format::Android);
}

#[test]
fn elf64_crel_relocations() {
    check(ELF64, Format::Crel);
}

#[test]
fn elf32_crel_relocations() {
    check(ELF32, Format::Crel);
}
