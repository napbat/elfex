//! Tests of the compact relocation format CREL.

use super::*;

/// A CREL table with addends, built by hand, and its entries.
fn with_addends() -> (Vec<u8>, RelocationTable) {
    let bytes = vec![
        // 4 entries, the addend flag and the shift 3.
        (4 << 3) | 4 | 3,
        // Offset delta 2 (0x10), and new symbol, type and addend values.
        (2 << 3) | 7,
        0x01,
        0x08,
        0x7c,
        // Offset delta 1 (0x18), nothing else changes.
        1 << 3,
        // Offset delta 0x1000 (0x8018) in two parts, and a new type.
        0x80 | 2,
        0x80,
        0x02,
        0x7f,
        // Offset delta 0, and a new symbol and addend.
        1 | 4,
        0x7f,
        0x04,
    ];
    let expected = RelocationTable {
        relocations: vec![
            Relocation::with_addend(0x10, 1, 8, -4),
            Relocation::with_addend(0x18, 1, 8, -4),
            Relocation::with_addend(0x8018, 1, 7, -4),
            Relocation::with_addend(0x8018, 0, 7, 0),
        ],
        with_addend: true,
    };
    (bytes, expected)
}

#[test]
fn crel_decodes_and_encodes_the_hand_built_table() {
    let (bytes, expected) = with_addends();
    for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
        assert_eq!(
            RelocationTable::parse_crel(&bytes, encoding).unwrap(),
            expected
        );
        assert_eq!(expected.write_crel(encoding).unwrap(), bytes);
    }
}

#[test]
fn crel_without_addends_uses_two_flag_bits() {
    let bytes = [
        // 2 entries, no addend flag, the shift 0.
        2 << 3,
        // Offset delta 1 and new symbol and type values. Bit 2 is an offset bit.
        (1 << 2) | 3,
        0x02,
        0x03,
        // Offset delta 0x40 in two parts.
        0x80,
        0x02,
    ];
    let table = RelocationTable::parse_crel(&bytes, Encoding::ELF64_LE).unwrap();
    let expected = RelocationTable {
        relocations: vec![Relocation::new(1, 2, 3), Relocation::new(0x41, 2, 3)],
        with_addend: false,
    };
    assert_eq!(table, expected);
    assert_eq!(expected.write_crel(Encoding::ELF64_LE).unwrap(), bytes);
}

#[test]
fn crel_truncated_and_malformed_input_errors() {
    let (bytes, _) = with_addends();
    for end in 0..bytes.len() {
        let error = RelocationTable::parse_crel(&bytes[..end], Encoding::ELF64_LE).unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::BufferTooSmall { .. } | ErrorKind::InvalidTable(_)
            ),
            "{end}: {error}"
        );
    }
    // The decoder ignores the bytes after the last entry.
    let mut padded = bytes.clone();
    padded.push(0);
    assert_eq!(
        RelocationTable::parse_crel(&padded, Encoding::ELF64_LE)
            .unwrap()
            .len(),
        4
    );
    // The count is larger than the number of bytes.
    let error = RelocationTable::parse_crel(&[3 << 3, 0, 0], Encoding::ELF64_LE).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    let mut huge = vec![0xff; 9];
    huge.push(0x01);
    let error = RelocationTable::parse_crel(&huge, Encoding::ELF64_LE).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    // A value with more than 64 bits.
    let mut overlong = vec![1 << 3, 0x83];
    overlong.extend_from_slice(&[0xff; 9]);
    overlong.push(0x7f);
    let error = RelocationTable::parse_crel(&overlong, Encoding::ELF64_LE).unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(error.context().unwrap().file_offset, Some(2));
}

#[test]
fn crel_elf32_values_wrap_at_32_bits() {
    let table = RelocationTable {
        relocations: vec![
            Relocation::with_addend(0xffff_fffc, 0, 0x17, i64::from(i32::MIN)),
            Relocation::with_addend(4, 0, 0x17, i64::from(i32::MAX)),
        ],
        with_addend: true,
    };
    let bytes = table.write_crel(Encoding::ELF32_LE).unwrap();
    // The second offset delta is 8, and the addend delta is -1.
    assert_eq!(bytes[bytes.len() - 2..], [(2 << 3) | 4, 0x7f]);
    assert_eq!(
        RelocationTable::parse_crel(&bytes, Encoding::ELF32_LE).unwrap(),
        table
    );
}

#[test]
fn crel_round_trip() {
    let rela = RelocationTable {
        relocations: vec![
            Relocation::with_addend(0x1001, 3, x86_64::R_X86_64_PC32, -4),
            Relocation::with_addend(0x10, 1, x86_64::R_X86_64_PLT32, -4),
            Relocation::with_addend(u64::MAX, u32::MAX, u32::MAX, i64::MIN),
            Relocation::with_addend(0, 0, 0, i64::MAX),
            Relocation::with_addend(0x7fff_ffff_ffff, 2, 1, 0),
        ],
        with_addend: true,
    };
    let rel = RelocationTable {
        relocations: (0..300)
            .map(|index: u32| Relocation::new(u64::from(index) * 4, index % 7, 2))
            .collect(),
        with_addend: false,
    };
    for (table, encoding) in [
        (rela, Encoding::ELF64_LE),
        (rel.clone(), Encoding::ELF32_BE),
        (rel, Encoding::ELF64_BE),
        (RelocationTable::new(false), Encoding::ELF32_LE),
    ] {
        let bytes = table.write_crel(encoding).unwrap();
        assert_eq!(
            RelocationTable::parse_crel(&bytes, encoding).unwrap(),
            table
        );
    }
}

#[test]
fn crel_encoder_errors() {
    let mixed = RelocationTable {
        relocations: vec![Relocation::with_addend(0x10, 0, 8, 0)],
        with_addend: false,
    };
    let error = mixed.write_crel(Encoding::ELF64_LE).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    let large = RelocationTable {
        relocations: vec![Relocation::new(0x1_0000_0000, 0, 8)],
        with_addend: false,
    };
    let error = large.write_crel(Encoding::ELF32_LE).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::ValueOutOfRange(_)));
}
