//! Tests of the Android packed relocation format (`APS2`).

use super::*;
use crate::eh_frame::write_sleb128;

/// Return `APS2` followed by `values` as SLEB128 values.
fn stream(values: &[i64]) -> Vec<u8> {
    let mut out = ANDROID_PACKED_MAGIC.to_vec();
    for value in values {
        write_sleb128(&mut out, *value);
    }
    out
}

/// Return the ELF64 `r_info` value of `symbol` and `r_type` as a stream value.
fn info64(symbol: u32, r_type: u32) -> i64 {
    (i64::from(symbol) << 32) | i64::from(r_type)
}

const ALL: i64 = 15;

/// A stream that uses each group flag, and the expected entries.
fn all_flags() -> (Vec<u8>, RelocationTable) {
    let relative = i64::from(x86_64::R_X86_64_RELATIVE);
    let bytes = stream(&[
        6,
        0x1000,
        // Three entries that share the offset delta, `r_info` and the addend.
        3,
        ALL,
        8,
        relative,
        0x10,
        // Two entries with their own offset delta, `r_info` and addend delta.
        2,
        8,
        0x10,
        info64(1, x86_64::R_X86_64_GLOB_DAT),
        -0x10,
        8,
        info64(2, x86_64::R_X86_64_64),
        5,
        // One entry without an addend: the addend is 0.
        1,
        0,
        -0x30,
        info64(3, x86_64::R_X86_64_JUMP_SLOT),
    ]);
    let expected = RelocationTable {
        relocations: vec![
            Relocation::with_addend(0x1008, 0, x86_64::R_X86_64_RELATIVE, 0x10),
            Relocation::with_addend(0x1010, 0, x86_64::R_X86_64_RELATIVE, 0x10),
            Relocation::with_addend(0x1018, 0, x86_64::R_X86_64_RELATIVE, 0x10),
            Relocation::with_addend(0x1028, 1, x86_64::R_X86_64_GLOB_DAT, 0),
            Relocation::with_addend(0x1030, 2, x86_64::R_X86_64_64, 5),
            Relocation::with_addend(0x1000, 3, x86_64::R_X86_64_JUMP_SLOT, 0),
        ],
        with_addend: true,
    };
    (bytes, expected)
}

#[test]
fn android_packed_decodes_each_group_flag() {
    let (bytes, expected) = all_flags();
    let table =
        RelocationTable::parse_android_packed(&bytes, Encoding::ELF64_LE, Machine::X86_64, true)
            .unwrap();
    assert_eq!(table, expected);

    // A group can share only the offset delta, only `r_info` or only the addend.
    let rel = i64::from(arm::R_ARM_RELATIVE);
    let shared = [
        (RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG, vec![4, rel, rel]),
        (RELOCATION_GROUPED_BY_INFO_FLAG, vec![rel, 4, 4]),
    ];
    for (flag, values) in shared {
        let mut all = vec![2, 0x100, 2, i64::try_from(flag).unwrap()];
        all.extend(values);
        let table = RelocationTable::parse_android_packed(
            &stream(&all),
            Encoding::ELF32_LE,
            Machine::ARM,
            false,
        )
        .unwrap();
        let expected = [
            Relocation::new(0x104, 0, arm::R_ARM_RELATIVE),
            Relocation::new(0x108, 0, arm::R_ARM_RELATIVE),
        ];
        assert_eq!(table.relocations, expected, "flag {flag}");
    }
    let by_addend = i64::try_from(RELOCATION_GROUPED_BY_ADDEND_FLAG | 8).unwrap();
    let table = RelocationTable::parse_android_packed(
        &stream(&[2, 0, 2, by_addend, -3, 8, 1, 8, 1]),
        Encoding::ELF32_BE,
        Machine::PPC,
        true,
    )
    .unwrap();
    let addends: Vec<_> = table.iter().map(|r| r.addend).collect();
    assert_eq!(addends, [Some(-3), Some(-3)]);
}

#[test]
fn android_packed_elf32_values_wrap_at_32_bits() {
    let bytes = stream(&[1, 0xffff_fff0, 1, 8, 0x20, 0x117, -1]);
    let table =
        RelocationTable::parse_android_packed(&bytes, Encoding::ELF32_LE, Machine::ARM, true)
            .unwrap();
    assert_eq!(
        table.relocations,
        [Relocation::with_addend(0x10, 1, 0x17, -1)]
    );
}

#[test]
fn android_packed_rel_table_rejects_addends() {
    let bytes = stream(&[1, 0, 1, 8, 4, 0x17, 1]);
    let error =
        RelocationTable::parse_android_packed(&bytes, Encoding::ELF32_LE, Machine::ARM, false)
            .unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(error.context().unwrap().file_offset, Some(7));
}

#[test]
fn android_packed_truncated_input_errors() {
    let (bytes, _) = all_flags();
    for end in 0..bytes.len() {
        let result = RelocationTable::parse_android_packed(
            &bytes[..end],
            Encoding::ELF64_LE,
            Machine::X86_64,
            true,
        );
        let error = result.unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::BufferTooSmall { .. } | ErrorKind::InvalidTable(_)
            ),
            "{end}: {error}"
        );
    }
    // The decoder ignores the padding after the last group.
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0; 3]);
    let table =
        RelocationTable::parse_android_packed(&padded, Encoding::ELF64_LE, Machine::X86_64, true)
            .unwrap();
    assert_eq!(table.len(), 6);
}

#[test]
fn android_packed_malformed_input_errors() {
    let parse = |bytes: &[u8]| {
        RelocationTable::parse_android_packed(bytes, Encoding::ELF64_LE, Machine::X86_64, true)
            .unwrap_err()
    };
    let is_table_error = |error: &Error| matches!(error.kind(), ErrorKind::InvalidTable(_));
    // The magic bytes are wrong.
    assert!(is_table_error(&parse(b"APS1\x00\x00")));
    // A value with more than 64 bits.
    let mut overlong = ANDROID_PACKED_MAGIC.to_vec();
    overlong.extend_from_slice(&[0x80; 9]);
    overlong.push(0x01);
    assert!(is_table_error(&parse(&overlong)));
    // A group with more entries than the count leaves.
    assert!(is_table_error(&parse(&stream(&[1, 0, 2, 0, 8, 8, 8, 8]))));
    // A negative count.
    assert!(is_table_error(&parse(&stream(&[-1, 0]))));
}

#[test]
fn android_packed_count_has_a_budget() {
    // A group that shares all values gives each entry from no bytes.
    let shared = |count: i64| stream(&[count, 0, count, 3, 8, 8]);
    let bytes = shared(4096);
    let table =
        RelocationTable::parse_android_packed(&bytes, Encoding::ELF64_LE, Machine::X86_64, false)
            .unwrap();
    assert_eq!(table.len(), 4096);
    assert_eq!(table.relocations[4095].offset, 4096 * 8);

    let huge = shared(1 << 40);
    assert!(1 << 40 > huge.len() * ANDROID_PACKED_MAX_ENTRIES_PER_BYTE);
    let error =
        RelocationTable::parse_android_packed(&huge, Encoding::ELF64_LE, Machine::X86_64, false)
            .unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );

    // With a three-byte count, the stream has 14 bytes.
    let limit = 14 * ANDROID_PACKED_MAX_ENTRIES_PER_BYTE;
    let at_limit = shared(i64::try_from(limit).unwrap());
    assert_eq!(at_limit.len(), 14);
    let table = RelocationTable::parse_android_packed(
        &at_limit,
        Encoding::ELF64_LE,
        Machine::X86_64,
        false,
    )
    .unwrap();
    assert_eq!(table.len(), limit);
    let over = shared(i64::try_from(limit + 1).unwrap());
    assert_eq!(over.len(), 14);
    let error =
        RelocationTable::parse_android_packed(&over, Encoding::ELF64_LE, Machine::X86_64, false)
            .unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
}

#[test]
fn android_packed_round_trip() {
    let relative = x86_64::R_X86_64_RELATIVE;
    let mut relocations: Vec<Relocation> = (0..10)
        .map(|index| Relocation::with_addend(0x4000 + index * 8, 0, relative, 0x100))
        .collect();
    relocations.extend([
        Relocation::with_addend(0x3000, 7, x86_64::R_X86_64_GLOB_DAT, 0),
        Relocation::with_addend(0x9000, 8, x86_64::R_X86_64_64, -0x20),
        Relocation::with_addend(0x9008, 8, x86_64::R_X86_64_64, 0),
        Relocation::with_addend(0x9010, 0, relative, i64::MIN),
        Relocation::with_addend(u64::MAX - 7, 0xffff_ffff, relative, i64::MAX),
    ]);
    let rela = RelocationTable {
        relocations,
        with_addend: true,
    };
    let rel = RelocationTable {
        relocations: vec![
            Relocation::new(0x2000, 0, arm::R_ARM_RELATIVE),
            Relocation::new(0x2004, 0, arm::R_ARM_RELATIVE),
            Relocation::new(0x1000, 0x00ff_ffff, arm::R_ARM_JUMP_SLOT),
            Relocation::new(0xffff_fffc, 3, arm::R_ARM_ABS32),
        ],
        with_addend: false,
    };
    let mips = RelocationTable {
        relocations: vec![Relocation::with_addend(0x10, 4, 0x0302_1203, -1)],
        with_addend: true,
    };
    let cases = [
        (rela, Encoding::ELF64_LE, Machine::X86_64),
        (rel, Encoding::ELF32_LE, Machine::ARM),
        (mips, Encoding::ELF64_LE, Machine::MIPS),
        (
            RelocationTable::new(true),
            Encoding::ELF64_BE,
            Machine::PPC64,
        ),
    ];
    for (table, encoding, machine) in cases {
        let bytes = table.write_android_packed(encoding, machine).unwrap();
        let parsed =
            RelocationTable::parse_android_packed(&bytes, encoding, machine, table.with_addend)
                .unwrap();
        assert_eq!(parsed, table);
    }
}

#[test]
fn android_packed_encoder_shares_runs() {
    let table = RelocationTable {
        relocations: (0..1000)
            .map(|index| Relocation::new(0x4000 + index * 8, 0, 8))
            .collect(),
        with_addend: false,
    };
    let bytes = table
        .write_android_packed(Encoding::ELF64_LE, Machine::X86_64)
        .unwrap();
    // The magic, the header, one plain group of one entry and one shared group.
    assert!(bytes.len() < 20, "{}", bytes.len());
}

#[test]
fn android_packed_encoder_errors() {
    let mixed = RelocationTable {
        relocations: vec![Relocation::new(0x10, 0, 8)],
        with_addend: true,
    };
    let error = mixed
        .write_android_packed(Encoding::ELF64_LE, Machine::X86_64)
        .unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    for relocation in [
        Relocation::with_addend(0x1_0000_0000, 0, 8, 0),
        Relocation::with_addend(0, 0, 8, i64::from(i32::MAX) + 1),
        Relocation::with_addend(0, 0x0100_0000, 8, 0),
    ] {
        let table = RelocationTable {
            relocations: vec![relocation],
            with_addend: true,
        };
        let error = table
            .write_android_packed(Encoding::ELF32_LE, Machine::ARM)
            .unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ValueOutOfRange(_)));
    }
}
