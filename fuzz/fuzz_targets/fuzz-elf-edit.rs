//! Fuzz target that applies a sequence of `ElfFile` edits to arbitrary bytes.
//!
//! The first byte gives the number of edit bytes that follow. The rest of the input is the
//! file. The target panics if a file that `try_build` writes does not parse again, or if its
//! round trip is not lossless.

#![no_main]

use elfex::program::{PF_R, PF_W};
use elfex::{ElfFile, NewSection, SectionType};
use libfuzzer_sys::fuzz_target;

/// Apply the edit that `op` selects. Errors are expected for most inputs.
fn apply(file: &mut ElfFile, op: u8, step: usize) {
    let count = file.section_headers().len();
    let index = usize::from(op >> 3) % count.max(1);
    let size = usize::from(op >> 3);
    let _ = match op % 7 {
        0 => file.set_interpreter(&"/lib/elfex".repeat(size / 4 + 1)),
        1 => file
            .add_section(NewSection::new(
                format!(".fuzz{step}"),
                SectionType::PROGBITS,
                vec![op; size],
            ))
            .map(|_| ()),
        2 => file.set_section_data(index, vec![op; size]),
        3 => file.remove_section(index),
        4 => file
            .add_load_segment(PF_R | PF_W, vec![op; size + 1], 0)
            .map(|_| ()),
        5 => {
            file.set_entry_point(u64::from(op) << 4);
            Ok(())
        }
        _ => file.to_image().map(|_| ()),
    };
}

fuzz_target!(|data: &[u8]| {
    let Some((&length, rest)) = data.split_first() else {
        return;
    };
    let length = usize::from(length % 8).min(rest.len());
    let (ops, bytes) = rest.split_at(length);
    let Ok(mut file) = ElfFile::parse(bytes) else {
        return;
    };
    for (step, &op) in ops.iter().enumerate() {
        apply(&mut file, op, step);
    }
    let Ok(built) = file.try_build() else {
        return;
    };
    let reparsed = ElfFile::parse(&built).expect("an edited file must parse again");
    let rebuilt = reparsed
        .try_build()
        .expect("a parsed edited file must build without changes");
    assert_eq!(
        rebuilt, built,
        "the round trip of an edited file is not lossless"
    );
    let _ = reparsed.validate();
});
