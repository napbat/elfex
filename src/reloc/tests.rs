use super::*;
use crate::ErrorKind;

mod android;
mod crel;

#[test]
fn parse_selects_the_standard_entry_size() {
    let encoding = Encoding::ELF32_BE;
    let rela = RelocationTable {
        relocations: vec![Relocation::with_addend(0x10, 1, 2, -3)],
        with_addend: true,
    };
    let bytes = rela.write(encoding, Machine::PPC).unwrap();
    let parsed = RelocationTable::parse(&bytes, encoding, Machine::PPC, true).unwrap();
    assert_eq!(parsed, rela);
    // The same bytes are a `Rel` table with a wrong size.
    let error = RelocationTable::parse(&bytes, encoding, Machine::PPC, false).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
}

#[test]
fn entry_sizes() {
    assert_eq!(Relocation::size(Class::Elf32, false), 8);
    assert_eq!(Relocation::size(Class::Elf32, true), 12);
    assert_eq!(Relocation::size(Class::Elf64, false), 16);
    assert_eq!(Relocation::size(Class::Elf64, true), 24);
}

#[test]
fn elf32_rel_round_trip_both_byte_orders() {
    for encoding in [Encoding::ELF32_LE, Encoding::ELF32_BE] {
        let table = RelocationTable {
            relocations: vec![
                Relocation::new(0x1000, 5, i386::R_386_32),
                Relocation::new(0x2004, 0, i386::R_386_RELATIVE),
                Relocation::new(0x3008, 0x00ff_ffff, i386::R_386_JMP_SLOT),
            ],
            with_addend: false,
        };
        let bytes = table.write(encoding, Machine::I386).unwrap();
        assert_eq!(bytes.len(), 24);
        let parsed = RelocationTable::parse_rel(&bytes, encoding, Machine::I386).unwrap();
        assert_eq!(parsed, table);
        assert!(parsed.relocations[1].is_relative(Machine::I386));
        assert!(!parsed.relocations[0].is_relative(Machine::I386));
    }
}

#[test]
fn elf64_rela_round_trip_both_byte_orders() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF64_BE] {
        let table = RelocationTable {
            relocations: vec![
                Relocation::with_addend(0x4000, 0, x86_64::R_X86_64_RELATIVE, 0x1234),
                Relocation::with_addend(0x4008, 0xdead_beef, x86_64::R_X86_64_64, -8),
                Relocation::with_addend(u64::MAX - 7, 1, x86_64::R_X86_64_IRELATIVE, i64::MIN),
            ],
            with_addend: true,
        };
        let bytes = table.write(encoding, Machine::X86_64).unwrap();
        assert_eq!(bytes.len(), 72);
        let parsed = RelocationTable::parse_rela(&bytes, encoding, Machine::X86_64).unwrap();
        assert_eq!(parsed, table);
        assert_eq!(parsed.len(), 3);
        assert!(parsed.iter().next().unwrap().is_relative(Machine::X86_64));
        assert!(parsed.relocations[2].is_irelative(Machine::X86_64));
    }
}

#[test]
fn elf32_hand_written_bytes() {
    let bytes = [
        0x00, 0x10, 0x00, 0x00, 0x01, 0x05, 0x00, 0x00, // r_offset 0x1000, sym 5, R_386_32
        0x10, 0x20, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, // r_offset 0x2010, R_386_RELATIVE
    ];
    let table = RelocationTable::parse_rel(&bytes, Encoding::ELF32_LE, Machine::I386).unwrap();
    assert_eq!(
        table.relocations,
        [
            Relocation::new(0x1000, 5, i386::R_386_32),
            Relocation::new(0x2010, 0, i386::R_386_RELATIVE),
        ]
    );
    let rela = [
        0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x03, 0x17, 0xff, 0xff, 0xff, 0xfc,
    ];
    let table = RelocationTable::parse_rela(&rela, Encoding::ELF32_BE, Machine::ARM).unwrap();
    assert_eq!(
        table.relocations,
        [Relocation::with_addend(0x1000, 3, arm::R_ARM_RELATIVE, -4)]
    );
    assert_eq!(table.write(Encoding::ELF32_BE, Machine::ARM).unwrap(), rela);
}

#[test]
fn mips64_le_info_round_trip() {
    // r_offset 0x100, r_sym 7, r_ssym 1, r_type3 R_MIPS_NONE, r_type2 R_MIPS_64, r_type R_MIPS_REL32.
    let bytes = [
        0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x07, 0, 0, 0, 0x01, 0x00, 0x12, 0x03,
    ];
    let reloc = Relocation::parse(&bytes, Encoding::ELF64_LE, Machine::MIPS, false).unwrap();
    assert_eq!(reloc.offset, 0x100);
    assert_eq!(reloc.symbol, 7);
    assert_eq!(reloc.r_type, 0x0100_1203);
    assert_eq!(reloc.r_type & 0xff, mips::R_MIPS_REL32);
    let mut out = Vec::new();
    reloc
        .write(&mut out, Encoding::ELF64_LE, Machine::MIPS)
        .unwrap();
    assert_eq!(out, bytes);

    // The same fields in big-endian give the same packed type.
    let mut be = Vec::new();
    reloc
        .write(&mut be, Encoding::ELF64_BE, Machine::MIPS)
        .unwrap();
    assert_eq!(&be[8..], [0, 0, 0, 7, 0x01, 0x00, 0x12, 0x03]);
    assert_eq!(
        Relocation::parse(&be, Encoding::ELF64_BE, Machine::MIPS, false).unwrap(),
        reloc
    );

    // Other machines use the standard layout.
    let x86 = Relocation::parse(&bytes, Encoding::ELF64_LE, Machine::X86_64, false).unwrap();
    assert_eq!(x86.symbol, 0x0312_0001);
    assert_eq!(x86.r_type, 7);
}

#[test]
fn elf32_overflow_errors() {
    let encoding = Encoding::ELF32_LE;
    let cases = [
        Relocation::new(0, 0x0100_0000, 1),
        Relocation::new(0, 1, 0x100),
        Relocation::new(0x1_0000_0000, 1, 1),
        Relocation::with_addend(0, 1, 1, i64::from(i32::MAX) + 1),
    ];
    for reloc in cases {
        let mut out = Vec::new();
        let err = reloc.write(&mut out, encoding, Machine::I386).unwrap_err();
        assert!(
            matches!(err.kind(), ErrorKind::ValueOutOfRange(_)),
            "{reloc:?}"
        );
        assert_eq!(out, []);
    }
    let err = Relocation::with_addend(0, 1, 1, i64::MIN)
        .write(&mut Vec::new(), encoding, Machine::I386)
        .unwrap_err();
    let structure = err
        .context()
        .and_then(|context| context.structure.as_deref());
    assert_eq!(structure, Some("Elf32_Rela"));
    let err = Relocation::new(0, 0x0100_0000, 1)
        .write(&mut Vec::new(), encoding, Machine::I386)
        .unwrap_err();
    let structure = err
        .context()
        .and_then(|context| context.structure.as_deref());
    assert_eq!(structure, Some("Elf32_Rel"));
}

#[test]
fn table_addend_mismatch_and_bad_sizes() {
    let rel = RelocationTable {
        relocations: vec![Relocation::with_addend(0, 0, 8, 1)],
        with_addend: false,
    };
    assert!(matches!(
        rel.write(Encoding::ELF64_LE, Machine::X86_64)
            .unwrap_err()
            .kind(),
        ErrorKind::InvalidTable(_)
    ));
    let rela = RelocationTable {
        relocations: vec![Relocation::new(0, 0, 8)],
        with_addend: true,
    };
    assert!(rela.write(Encoding::ELF64_LE, Machine::X86_64).is_err());

    let err =
        RelocationTable::parse_rela(&[0; 25], Encoding::ELF64_LE, Machine::X86_64).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    assert!(
        RelocationTable::parse_with_entsize(&[0; 16], Encoding::ELF32_LE, Machine::I386, false, 4)
            .is_err()
    );
    assert!(
        RelocationTable::parse_with_entsize(&[0; 16], Encoding::ELF32_LE, Machine::I386, false, 0)
            .is_err()
    );

    // A larger entry size skips the padding.
    let table = RelocationTable::parse_with_entsize(
        &[1, 0, 0, 0, 8, 0, 0, 0, 0xaa, 0xbb],
        Encoding::ELF32_LE,
        Machine::I386,
        false,
        10,
    )
    .unwrap();
    assert_eq!(table.relocations, [Relocation::new(1, 0, 8)]);
    assert_eq!(
        RelocationTable::parse_rel(&[], Encoding::ELF32_LE, Machine::I386)
            .unwrap()
            .relocations,
        []
    );
}

#[test]
fn empty_tables() {
    let table = RelocationTable::new(true);
    assert!(table.is_empty() && table.with_addend);
    assert_eq!(table.iter().count(), 0);
    assert_eq!(
        table.write(Encoding::ELF64_LE, Machine::X86_64).unwrap(),
        []
    );
    let parsed = RelocationTable::parse_rela(&[], Encoding::ELF64_BE, Machine::X86_64).unwrap();
    assert_eq!(parsed, table);

    let relr = RelrTable::default();
    assert!(relr.is_empty());
    assert_eq!(relr.write(Encoding::ELF32_LE).unwrap(), []);
    let relr = RelrTable::from_addresses(vec![0x18, 0x10], Encoding::ELF64_LE).unwrap();
    assert!(!relr.is_empty());
    assert_eq!(relr.iter().copied().collect::<Vec<_>>(), [0x10, 0x18]);
}

#[test]
fn relr_round_trip_both_classes() {
    for encoding in [
        Encoding::ELF32_LE,
        Encoding::ELF32_BE,
        Encoding::ELF64_LE,
        Encoding::ELF64_BE,
    ] {
        let w = word_size(encoding);
        let a = 0x1_0000;
        let input = vec![
            a + 200 * w,
            a,
            a + w,
            a + 2 * w,
            a + 10 * w,
            a + 70 * w,
            a + 2 * w,
            a + 71 * w,
            0x80_0000,
        ];
        let table = RelrTable::from_addresses(input, encoding).unwrap();
        assert_eq!(table.len(), 8);
        let bytes = table.write(encoding).unwrap();
        let size = encoding.addr_size();
        let words: Vec<u64> = (0..bytes.len() / size)
            .map(|i| encoding.read_addr(&bytes, i * size).unwrap())
            .collect();
        assert!(words.iter().filter(|word| **word & 1 == 1).count() >= 1);
        assert!(words.iter().filter(|word| **word & 1 == 0).count() >= 2);
        assert_eq!(words[0], a);
        let parsed = RelrTable::parse(&bytes, encoding).unwrap();
        assert_eq!(parsed, table);
    }
}

#[test]
fn relr_elf64_exact_encoding() {
    let encoding = Encoding::ELF64_LE;
    let table = RelrTable::from_addresses(vec![0x1000, 0x1008, 0x1018, 0x2000], encoding).unwrap();
    let bytes = table.write(encoding).unwrap();
    let mut expected = Vec::new();
    encoding.write_u64(&mut expected, 0x1000);
    encoding.write_u64(&mut expected, 0b1011);
    encoding.write_u64(&mut expected, 0x2000);
    assert_eq!(bytes, expected);
}

#[test]
fn relr_malformed_input() {
    // A bitmap first is invalid: a bitmap needs a preceding address.
    let err = RelrTable::parse(&[3, 0, 0, 0], Encoding::ELF32_LE).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    assert!(RelrTable::parse(&[0; 5], Encoding::ELF32_LE).is_err());
    assert_eq!(
        RelrTable::parse(&[], Encoding::ELF64_LE).unwrap().addresses,
        []
    );

    // Overflow of the bitmap base.
    let mut bytes = Vec::new();
    Encoding::ELF64_LE.write_u64(&mut bytes, u64::MAX - 15);
    Encoding::ELF64_LE.write_u64(&mut bytes, u64::MAX);
    assert!(RelrTable::parse(&bytes, Encoding::ELF64_LE).is_err());

    assert!(RelrTable::from_addresses(vec![0x1001], Encoding::ELF64_LE).is_err());
    let unsorted = RelrTable {
        addresses: vec![0x2000, 0x1000],
    };
    assert!(unsorted.write(Encoding::ELF64_LE).is_err());
    let wide = RelrTable {
        addresses: vec![0x1_0000_0000],
    };
    assert!(matches!(
        wide.write(Encoding::ELF32_LE).unwrap_err().kind(),
        ErrorKind::ValueOutOfRange(_)
    ));
    let unaligned = RelrTable {
        addresses: vec![0x1004],
    };
    assert!(unaligned.write(Encoding::ELF32_LE).is_ok());
    assert!(matches!(
        unaligned.write(Encoding::ELF64_LE).unwrap_err().kind(),
        ErrorKind::InvalidTable(_)
    ));
}

#[test]
fn relr_addresses_stay_in_class() {
    let parse = |encoding: Encoding, words: &[u64]| {
        let mut bytes = Vec::new();
        for word in words {
            if encoding.is_64bit() {
                encoding.write_u64(&mut bytes, *word);
            } else {
                encoding.write_u32(&mut bytes, u32::try_from(*word).unwrap());
            }
        }
        RelrTable::parse(&bytes, encoding)
    };
    let elf32 = Encoding::ELF32_LE;
    // The last words of the ELF32 address space.
    assert_eq!(
        parse(elf32, &[0xffff_fff0, 0b1001]).unwrap().addresses,
        [0xffff_fff0, 0xffff_fffc]
    );
    // Bit 4 of the bitmap is the word at 2^32: past the end of the ELF32 address space.
    let err = parse(elf32, &[0xffff_fff0, 0b1_0001]).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");
    // A bitmap after the last ELF32 word.
    let err = parse(elf32, &[0xffff_fffc, 0b11]).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");

    let elf64 = Encoding::ELF64_LE;
    // A bitmap after the last ELF64 word.
    let err = parse(elf64, &[u64::MAX - 7, 0b11]).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");
    // A bitmap that reaches the last ELF64 word is valid, if no bitmap follows it.
    assert_eq!(
        parse(elf64, &[u64::MAX - 15, 0b11]).unwrap().addresses,
        [u64::MAX - 15, u64::MAX - 7]
    );
    let err = parse(elf64, &[u64::MAX - 15, 0b11, 0b11]).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");
}

#[test]
fn type_names_and_helpers() {
    assert_eq!(
        relocation_type_name(Machine::X86_64, 8),
        Some("R_X86_64_RELATIVE")
    );
    assert_eq!(
        relocation_type_name(Machine::I386, 7),
        Some("R_386_JMP_SLOT")
    );
    assert_eq!(
        relocation_type_name(Machine::AARCH64, 1027),
        Some("R_AARCH64_RELATIVE")
    );
    assert_eq!(
        relocation_type_name(Machine::ARM, 23),
        Some("R_ARM_RELATIVE")
    );
    assert_eq!(
        relocation_type_name(Machine::RISCV, 58),
        Some("R_RISCV_IRELATIVE")
    );
    assert_eq!(
        relocation_type_name(Machine::LOONGARCH, 3),
        Some("R_LARCH_RELATIVE")
    );
    assert_eq!(relocation_type_name(Machine::MIPS, 3), Some("R_MIPS_REL32"));
    assert_eq!(relocation_type_name(Machine::X86_64, 9999), None);
    assert_eq!(relocation_type_name(Machine::NONE, 0), None);
    assert_eq!(relative_type(Machine::S390), Some(12));
    assert_eq!(relative_type(Machine::PPC64), Some(22));
    assert_eq!(relative_type(Machine::MIPS), None);
    assert_eq!(irelative_type(Machine::AARCH64), Some(1032));
    assert!(!Relocation::new(0, 0, 3).is_relative(Machine::MIPS));
    // The relative and indirect relative types of each machine have names that end in
    // RELATIVE and IRELATIVE.
    for machine in [
        Machine::X86_64,
        Machine::I386,
        Machine::AARCH64,
        Machine::ARM,
        Machine::RISCV,
        Machine::PPC,
        Machine::PPC64,
        Machine::S390,
        Machine::LOONGARCH,
        Machine::SPARC,
        Machine::SPARC32PLUS,
        Machine::SPARCV9,
    ] {
        let relative = relocation_type_name(machine, relative_type(machine).unwrap()).unwrap();
        assert!(relative.ends_with("_RELATIVE"), "{relative}");
        let irelative = relocation_type_name(machine, irelative_type(machine).unwrap()).unwrap();
        assert!(irelative.ends_with("_IRELATIVE"), "{irelative}");
    }
    assert_eq!(irelative_type(Machine::MIPS), None);
    assert_eq!(
        relocation_type_name(Machine::HEXAGON, relative_type(Machine::HEXAGON).unwrap()),
        Some("R_HEX_RELATIVE")
    );
    assert_eq!(irelative_type(Machine::HEXAGON), None);
}

#[test]
fn s390_types_have_the_abi_values() {
    // Regression: R_390_PC16DBL and R_390_PLT16DBL had the values of R_390_PC16 and
    // R_390_PC16DBL.
    assert_eq!(s390::R_390_PC16, 16);
    assert_eq!(s390::R_390_PC16DBL, 17);
    assert_eq!(s390::R_390_PLT16DBL, 18);
    assert_eq!(relocation_type_name(Machine::S390, 16), Some("R_390_PC16"));
    assert_eq!(
        relocation_type_name(Machine::S390, 17),
        Some("R_390_PC16DBL")
    );
    assert_eq!(
        relocation_type_name(Machine::S390, 18),
        Some("R_390_PLT16DBL")
    );
    assert_eq!(
        relocation_type_name(Machine::S390, 13),
        Some("R_390_GOTOFF32")
    );
}

#[test]
fn toolchain_relocation_types_have_names() {
    // Regression: these types occur in clang output, and had no names.
    let types = [
        (Machine::MIPS, 42, "R_MIPS_TLS_GD"),
        (Machine::PPC, 79, "R_PPC_GOT_TLSGD16"),
        (Machine::PPC, 95, "R_PPC_TLSGD"),
        (Machine::PPC64, 48, "R_PPC64_TOC16_LO"),
        (Machine::PPC64, 50, "R_PPC64_TOC16_HA"),
        (Machine::PPC64, 252, "R_PPC64_REL16_HA"),
        (Machine::S390, 38, "R_390_TLS_GDCALL"),
        (Machine::S390, 41, "R_390_TLS_GD64"),
        (Machine::S390, 53, "R_390_TLS_LDO64"),
        (Machine::LOONGARCH, 97, "R_LARCH_TLS_GD_PC_HI20"),
        (Machine::SPARCV9, 17, "R_SPARC_PC22"),
        (Machine::SPARC, 22, "R_SPARC_RELATIVE"),
        (Machine::HEXAGON, 35, "R_HEX_RELATIVE"),
        (Machine::HEXAGON, 16, "R_HEX_B32_PCREL_X"),
        (Machine::AARCH64, 0xe201, "R_AARCH64_AUTH_GLOB_DAT"),
        (Machine::ARM, 163, "R_ARM_FUNCDESC"),
    ];
    for (machine, r_type, name) in types {
        assert_eq!(
            relocation_type_name(machine, r_type),
            Some(name),
            "{machine} {r_type}"
        );
    }
    // ELF64 SPARC keeps additional data in the upper 24 bits of the type.
    let olo10 = Relocation::with_addend(0, 1, (0x123 << 8) | sparc::R_SPARC_OLO10, 0);
    assert_eq!(olo10.type_name(Machine::SPARCV9), Some("R_SPARC_OLO10"));
    assert!(Relocation::new(0, 0, 22).is_relative(Machine::SPARCV9));
    assert!(Relocation::new(0, 0, 35).is_relative(Machine::HEXAGON));
}

#[test]
fn relocation_type_name_method() {
    let relative = Relocation::with_addend(0x2000, 0, x86_64::R_X86_64_RELATIVE, 0x10);
    assert_eq!(
        relative.type_name(Machine::X86_64),
        Some("R_X86_64_RELATIVE")
    );
    assert_eq!(relative.type_name(Machine::NONE), None);
    // ELF64 MIPS packs three types: R_MIPS_GPREL32, R_MIPS_64 and R_MIPS_NONE.
    let packed = mips::R_MIPS_GPREL32 | (mips::R_MIPS_64 << 8);
    let mips64 = Relocation::new(0x1000, 1, packed);
    assert_eq!(mips64.type_name(Machine::MIPS), Some("R_MIPS_GPREL32"));
    // Other machines use all bits of the type.
    assert_eq!(
        Relocation::new(0, 0, 0x108).type_name(Machine::X86_64),
        None
    );
}

/// Return the word size of `encoding` as a `u64`.
fn word_size(encoding: Encoding) -> u64 {
    u64::try_from(encoding.addr_size()).unwrap()
}
