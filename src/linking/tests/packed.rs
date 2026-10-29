//! Tests of the Android packed and CREL relocation tables that the dynamic table names.

use super::*;
use crate::reloc::arm::{R_ARM_ABS32, R_ARM_RELATIVE};

/// Return a table of two relative entries and a jump slot entry.
fn table(with_addend: bool) -> RelocationTable {
    let addend = |value: i64| with_addend.then_some(value);
    let entry = |offset: u64, symbol: u32, r_type: u32, value: i64| Relocation {
        offset,
        symbol,
        r_type,
        addend: addend(value),
    };
    RelocationTable {
        relocations: vec![
            entry(0x2000, 0, R_X86_64_RELATIVE, 0x100),
            entry(0x2008, 0, R_X86_64_RELATIVE, 0x108),
            entry(0x3000, 1, R_X86_64_JUMP_SLOT, 0),
        ],
        with_addend,
    }
}

#[test]
fn android_rela_and_crel_through_the_dynamic_table() {
    let encoding = Encoding::ELF64_LE;
    let android = table(true);
    let crel = table(false);
    let android_bytes = android
        .write_android_packed(encoding, Machine::X86_64)
        .unwrap();
    let crel_bytes = crel.write_crel(encoding).unwrap();
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let android_address = flat.place(&android_bytes);
    let crel_address = flat.place(&crel_bytes);
    flat.set_dynamic(&[
        (DynamicTag::ANDROID_RELA, android_address),
        (DynamicTag::ANDROID_RELASZ, len(&android_bytes)),
        (DynamicTag::CREL, crel_address),
    ]);
    let relocations = Linker::load(&flat).unwrap().relocations().unwrap();
    assert_eq!(relocations.android.as_ref(), Some(&android));
    assert_eq!(relocations.crel.as_ref(), Some(&crel));
    assert_eq!((&relocations.rela, &relocations.rel), (&None, &None));
    assert_eq!(relocations.iter().count(), 6);
}

#[test]
fn android_rel_through_the_dynamic_table() {
    let encoding = Encoding::ELF32_LE;
    let android = RelocationTable {
        relocations: vec![
            Relocation::new(0x2000, 0, R_ARM_RELATIVE),
            Relocation::new(0x2004, 2, R_ARM_ABS32),
        ],
        with_addend: false,
    };
    let bytes = android
        .write_android_packed(encoding, Machine::ARM)
        .unwrap();
    let mut flat = Flat::new(encoding, Machine::ARM);
    let address = flat.place(&bytes);
    flat.set_dynamic(&[
        (DynamicTag::ANDROID_REL, address),
        (DynamicTag::ANDROID_RELSZ, len(&bytes)),
    ]);
    let relocations = Linker::load(&flat).unwrap().relocations().unwrap();
    assert_eq!(relocations.android, Some(android));
}

#[test]
fn malformed_packed_tables_have_the_tag_and_the_address() {
    let encoding = Encoding::ELF32_LE;
    let mut flat = Flat::new(encoding, Machine::ARM);
    let address = flat.place(b"APS1\0\0");
    let error_of = |flat: &Flat| Linker::load(flat).unwrap().relocations().unwrap_err();

    flat.set_dynamic(&[(DynamicTag::ANDROID_REL, address)]);
    let error = error_of(&flat);
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("DT_ANDROID_REL"));

    flat.set_dynamic(&[
        (DynamicTag::ANDROID_REL, address),
        (DynamicTag::ANDROID_RELSZ, 6),
    ]);
    let error = error_of(&flat);
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("DT_ANDROID_REL"));
    assert_eq!(error.context().unwrap().address, Some(address));

    // The CREL header declares more entries than the segment holds.
    let crel = flat.place(&[0xff, 0x01]);
    flat.set_dynamic(&[(DynamicTag::CREL, crel)]);
    let error = error_of(&flat);
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("DT_CREL"));
    assert_eq!(error.context().unwrap().address, Some(crel));
}

#[test]
fn the_view_parses_the_relocations_at_each_call() {
    let encoding = Encoding::ELF64_LE;
    let bytes = table(true)
        .write_android_packed(encoding, Machine::X86_64)
        .unwrap();
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let address = flat.place(&bytes);
    flat.set_dynamic(&[
        (DynamicTag::ANDROID_RELA, address),
        (DynamicTag::ANDROID_RELASZ, len(&bytes)),
    ]);
    let view = LinkingView::new(Linker::load(&flat).unwrap());
    let first = view.relocations().unwrap();
    assert_eq!(first.android, Some(table(true)));
    assert_eq!(view.relocations().unwrap(), first);
}
