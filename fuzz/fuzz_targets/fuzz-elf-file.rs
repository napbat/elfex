//! Fuzz target that parses arbitrary bytes as a raw ELF file, and then runs the table accessors
//! and the validation on the result.
//!
//! The target panics if a file parses, but its round trip is not lossless: `try_build` must
//! return the input bytes.

#![no_main]

use elfex::ElfFile;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
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
    let _ = file.notes();
    let _ = file.dynamic_relocations();
    let _ = file.exports();
});
