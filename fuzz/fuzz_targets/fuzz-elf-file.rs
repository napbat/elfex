//! Fuzz target that parses arbitrary bytes as a raw ELF file, and then runs the table accessors
//! and the validation on the result.
//!
//! The target also decodes the bytes as Android packed (`APS2`) and CREL relocations, and
//! encodes each decoded table again.
//!
//! The target panics if a file parses, but its round trip is not lossless: `try_build` must
//! return the input bytes.

#![no_main]

use elfex::{ElfFile, Encoding, Machine, RelocationTable};
use libfuzzer_sys::fuzz_target;

/// Decode `data` as compressed relocations, and check that the encoders accept each result.
fn compressed_relocations(data: &[u8]) {
    for (encoding, machine) in [
        (Encoding::ELF64_LE, Machine::X86_64),
        (Encoding::ELF32_LE, Machine::ARM),
    ] {
        for with_addend in [false, true] {
            let packed =
                RelocationTable::parse_android_packed(data, encoding, machine, with_addend);
            if let Ok(table) = packed {
                let bytes = table
                    .write_android_packed(encoding, machine)
                    .expect("a decoded APS2 table must encode");
                let again =
                    RelocationTable::parse_android_packed(&bytes, encoding, machine, with_addend);
                assert_eq!(
                    again.ok(),
                    Some(table),
                    "the APS2 round trip changed the table"
                );
            }
        }
        if let Ok(table) = RelocationTable::parse_crel(data, encoding) {
            let bytes = table
                .write_crel(encoding)
                .expect("a decoded CREL table must encode");
            let again = RelocationTable::parse_crel(&bytes, encoding);
            assert_eq!(
                again.ok(),
                Some(table),
                "the CREL round trip changed the table"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    compressed_relocations(data);
    let Ok(file) = ElfFile::parse(data) else {
        return;
    };
    let rebuilt = file
        .try_build()
        .expect("a parsed file must build without changes");
    assert_eq!(
        rebuilt, data,
        "the round trip of a parsed file is not lossless"
    );
    let _ = file.validate();
    let _ = file.symbols();
    let _ = file.symbol_list();
    let _ = file.lookup_symbol("main");
    let _ = file.relocation_sections();
    let _ = file.section_groups();
    let _ = file.notes();
    let _ = file.core_file_mappings();
    let _ = file.auxv();
    let _ = file.dynamic_relocations();
    let _ = file.exports();
    if let Ok(view) = file.linking() {
        let _ = view.lookup("main");
        let _ = view.lookup("main");
        let _ = view.imports();
    }
});
