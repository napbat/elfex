use super::*;
use crate::ErrorKind;
use crate::prelude::*;
use crate::section::{SHN_ABS, SHN_COMMON};

const ENCODINGS: [Encoding; 4] = [
    Encoding::ELF32_LE,
    Encoding::ELF32_BE,
    Encoding::ELF64_LE,
    Encoding::ELF64_BE,
];

fn sample_symbol() -> Symbol {
    Symbol {
        name: 1,
        value: 0x1000,
        size: 0x20,
        info: 0x12,
        other: 0x02,
        shndx: 5,
    }
}

#[test]
fn elf32_little_endian_field_order() {
    let bytes = [
        1, 0, 0, 0, // st_name
        0x00, 0x10, 0, 0, // st_value
        0x20, 0, 0, 0,    // st_size
        0x12, // st_info
        0x02, // st_other
        5, 0, // st_shndx
    ];
    let symbol = Symbol::parse(&bytes, Encoding::ELF32_LE).unwrap();
    assert_eq!(symbol, sample_symbol());
    let mut out = Vec::new();
    symbol.write(&mut out, Encoding::ELF32_LE).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn elf64_big_endian_field_order() {
    let bytes = [
        0, 0, 0, 1,    // st_name
        0x12, // st_info
        0x02, // st_other
        0, 5, // st_shndx
        0, 0, 0, 0, 0, 0, 0x10, 0x00, // st_value
        0, 0, 0, 0, 0, 0, 0, 0x20, // st_size
    ];
    let symbol = Symbol::parse(&bytes, Encoding::ELF64_BE).unwrap();
    assert_eq!(symbol, sample_symbol());
    let mut out = Vec::new();
    symbol.write(&mut out, Encoding::ELF64_BE).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn table_round_trip_all_encodings() {
    let table = SymbolTable {
        symbols: vec![
            Symbol::default(),
            sample_symbol(),
            Symbol {
                name: 7,
                value: 0xffff_fff0,
                size: 4,
                info: Symbol::make_info(SymbolBinding::WEAK, SymbolType::OBJECT),
                other: 3,
                shndx: SHN_COMMON,
            },
        ],
    };
    for encoding in ENCODINGS {
        let bytes = table.write(encoding).unwrap();
        assert_eq!(bytes.len(), 3 * Symbol::size(encoding.class));
        assert_eq!(SymbolTable::parse(&bytes, encoding).unwrap(), table);
    }
}

#[test]
fn elf32_write_rejects_large_value() {
    let symbol = Symbol {
        value: 0x1_0000_0000,
        ..Symbol::default()
    };
    let mut out = Vec::new();
    let err = symbol.write(&mut out, Encoding::ELF32_LE).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::ValueOutOfRange(_)));
    assert_eq!(out, []);
    symbol.write(&mut out, Encoding::ELF64_LE).unwrap();
    assert_eq!(out.len(), 24);
}

#[test]
fn info_and_other_accessors() {
    let mut symbol = Symbol {
        info: Symbol::make_info(SymbolBinding::GLOBAL, SymbolType::FUNC),
        other: 0xf0 | SymbolVisibility::HIDDEN.0,
        ..Symbol::default()
    };
    assert_eq!(symbol.info, 0x12);
    assert_eq!(symbol.binding(), SymbolBinding::GLOBAL);
    assert_eq!(symbol.symbol_type(), SymbolType::FUNC);
    assert_eq!(symbol.visibility(), SymbolVisibility::HIDDEN);
    assert!(symbol.is_global_or_weak());
    assert!(!symbol.is_local());
    assert!(symbol.is_undefined());
    assert!(!symbol.is_defined());

    symbol.set_binding(SymbolBinding::LOCAL);
    symbol.set_symbol_type(SymbolType::TLS);
    symbol.set_visibility(SymbolVisibility::PROTECTED);
    symbol.shndx = 3;
    assert_eq!(symbol.info, 0x06);
    assert_eq!(symbol.other, 0xf3);
    assert!(symbol.is_local());
    assert!(!symbol.is_global_or_weak());
    assert!(symbol.is_defined());

    assert_eq!(SymbolBinding::GNU_UNIQUE.name(), Some("STB_GNU_UNIQUE"));
    assert_eq!(SymbolType::GNU_IFUNC.to_string(), "STT_GNU_IFUNC");
    assert_eq!(SymbolType(0x0e).to_string(), "0xe");
    assert_eq!(SymbolVisibility::DEFAULT.name(), Some("STV_DEFAULT"));
}

#[test]
fn parse_rejects_bad_lengths() {
    let err = SymbolTable::parse(&[0; 20], Encoding::ELF32_LE).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    let err = SymbolTable::parse(&[0; 16], Encoding::ELF64_BE).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    let empty = SymbolTable::parse(&[], Encoding::ELF64_LE).unwrap();
    assert!(empty.is_empty());
}

#[test]
fn parse_with_entsize_skips_padding() {
    let encoding = Encoding::ELF64_LE;
    let mut bytes = Vec::new();
    for symbol in [Symbol::default(), sample_symbol()] {
        symbol.write(&mut bytes, encoding).unwrap();
        bytes.extend_from_slice(&[0xaa; 8]);
    }
    let table = SymbolTable::parse_with_entsize(&bytes, encoding, 32).unwrap();
    assert_eq!(table.symbols, [Symbol::default(), sample_symbol()]);

    let err = SymbolTable::parse_with_entsize(&bytes, encoding, 8).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    let err = SymbolTable::parse_with_entsize(&bytes, encoding, 24).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    let err = SymbolTable::parse_with_entsize(&bytes, encoding, u64::MAX).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
}

#[test]
fn parse_count_reads_a_prefix() {
    for encoding in ENCODINGS {
        let table = SymbolTable {
            symbols: vec![Symbol::default(), sample_symbol()],
        };
        let mut bytes = table.write(encoding).unwrap();
        bytes.extend_from_slice(&[0xff; 5]);

        assert_eq!(
            SymbolTable::parse_count(&bytes, encoding, 2).unwrap(),
            table
        );
        let one = SymbolTable::parse_count(&bytes, encoding, 1).unwrap();
        assert_eq!(one.symbols, [Symbol::default()]);

        let short = &bytes[..Symbol::size(encoding.class) + 4];
        let err = SymbolTable::parse_count(short, encoding, 2).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::BufferTooSmall { .. }));
        let err = SymbolTable::parse_count(&bytes, encoding, 3).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::BufferTooSmall { .. }));
        let err = SymbolTable::parse_count(&bytes, encoding, u64::MAX).unwrap_err();
        assert!(matches!(
            err.kind(),
            ErrorKind::InvalidTable(_) | ErrorKind::BufferTooSmall { .. }
        ));
    }
}

#[test]
fn table_queries() {
    let strings = StringTable::parse(b"\0start\0data\0");
    let mut global = sample_symbol();
    global.name = 7;
    let table = SymbolTable {
        symbols: vec![
            Symbol::default(),
            Symbol {
                name: 1,
                info: Symbol::make_info(SymbolBinding::LOCAL, SymbolType::FUNC),
                shndx: 1,
                ..Symbol::default()
            },
            global,
            Symbol {
                name: 0x100,
                ..Symbol::default()
            },
        ],
    };
    let mut locals = 0;
    for symbol in &table {
        if symbol.is_local() {
            locals += 1;
        }
    }
    assert_eq!(locals, 3);
    assert_eq!(table.first_non_local(), 2);
    assert_eq!(table.get(2), Some(&global));
    assert_eq!(table.get(4), None);
    assert_eq!(table.iter().count(), 4);
    assert_eq!(table.len(), 4);
    assert_eq!(table.find_by_name(&strings, b"data"), Some((2, &global)));
    assert_eq!(
        table.find_by_name(&strings, b"start").map(|(i, _)| i),
        Some(1)
    );
    assert_eq!(table.find_by_name(&strings, b"missing"), None);

    let all_local = SymbolTable {
        symbols: vec![Symbol::default(); 3],
    };
    assert_eq!(all_local.first_non_local(), 3);
}

#[test]
fn section_index_resolves_xindex() {
    let table = SymbolSectionIndexTable {
        indices: vec![0, 0x0001_2345, 0],
    };
    let extended = Symbol {
        shndx: SHN_XINDEX,
        ..Symbol::default()
    };
    assert_eq!(extended.section_index(1, Some(&table)), Some(0x0001_2345));
    assert_eq!(extended.section_index(5, Some(&table)), None);
    assert_eq!(extended.section_index(1, None), None);

    let absolute = Symbol {
        shndx: SHN_ABS,
        ..Symbol::default()
    };
    assert_eq!(
        absolute.section_index(1, Some(&table)),
        Some(u32::from(SHN_ABS))
    );
    assert_eq!(sample_symbol().section_index(0, None), Some(5));
    assert_eq!(Symbol::default().section_index(0, None), Some(0));
}

#[test]
fn section_index_table_round_trip() {
    let table = SymbolSectionIndexTable {
        indices: vec![0, 0x0001_2345, 7],
    };
    let little = table.write(Encoding::ELF64_LE);
    assert_eq!(little[4..8], [0x45, 0x23, 0x01, 0x00]);
    let big = table.write(Encoding::ELF32_BE);
    assert_eq!(big[4..8], [0x00, 0x01, 0x23, 0x45]);
    assert_eq!(
        SymbolSectionIndexTable::parse(&little, Encoding::ELF64_LE).unwrap(),
        table
    );
    assert_eq!(
        SymbolSectionIndexTable::parse(&big, Encoding::ELF32_BE).unwrap(),
        table
    );
    assert_eq!(table.len(), 3);
    assert_eq!(table.get(2), Some(7));
    assert!(!table.is_empty());

    let err = SymbolSectionIndexTable::parse(&[0; 6], Encoding::ELF32_LE).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
}

#[test]
fn builder_orders_locals_first_and_shares_names() {
    for encoding in ENCODINGS {
        let mut builder = SymbolTableBuilder::new(encoding);
        let main = NewSymbol::new("main", SymbolBinding::GLOBAL, SymbolType::FUNC)
            .with_value(0x1000)
            .with_size(0x10)
            .with_shndx(1);
        assert_eq!(builder.add(main), 0);
        let file =
            NewSymbol::new("a.c", SymbolBinding::LOCAL, SymbolType::FILE).with_shndx(SHN_ABS);
        assert_eq!(builder.add(file), 1);
        let data = NewSymbol::new(b"data".to_vec(), SymbolBinding::WEAK, SymbolType::OBJECT)
            .with_shndx(2)
            .with_visibility(SymbolVisibility::HIDDEN);
        assert_eq!(builder.add(data), 2);
        let local_main = NewSymbol::new("main", SymbolBinding::LOCAL, SymbolType::FUNC);
        assert_eq!(builder.add(local_main), 3);
        assert_eq!(builder.len(), 4);

        let built = builder.build();
        assert_eq!(built.indices, [3, 1, 4, 2]);
        assert_eq!(built.first_non_local, 3);
        assert_eq!(built.strings, b"\0a.c\0main\0data\0");

        let table = SymbolTable::parse(&built.symbols, encoding).unwrap();
        let strings = StringTable::new(built.strings.clone());
        assert_eq!(table.len(), 5);
        assert_eq!(table.symbols[0], Symbol::default());
        assert_eq!(table.first_non_local(), 3);
        assert_eq!(table.symbols[2].name, table.symbols[3].name);
        assert_eq!(strings.get(table.symbols[1].name).unwrap(), "a.c");
        assert_eq!(table.symbols[1].shndx, SHN_ABS);
        assert_eq!(table.symbols[2].binding(), SymbolBinding::LOCAL);
        assert_eq!(
            table.symbols[3],
            Symbol {
                name: 5,
                value: 0x1000,
                size: 0x10,
                info: 0x12,
                other: 0,
                shndx: 1,
            }
        );
        let (index, data) = table.find_by_name(&strings, b"data").unwrap();
        assert_eq!(index, 4);
        assert_eq!(data.binding(), SymbolBinding::WEAK);
        assert_eq!(data.symbol_type(), SymbolType::OBJECT);
        assert_eq!(data.visibility(), SymbolVisibility::HIDDEN);
    }
}

#[test]
fn builder_without_symbols_writes_null_symbol() {
    let builder = SymbolTableBuilder::new(Encoding::ELF32_LE);
    assert!(builder.is_empty());
    let built = builder.try_build().unwrap();
    assert_eq!(built.symbols, [0; 16]);
    assert_eq!(built.strings, b"\0");
    assert_eq!(built.first_non_local, 1);
    assert_eq!(built.indices, []);
}

#[test]
fn builder_rejects_invalid_input() {
    let mut builder = SymbolTableBuilder::new(Encoding::ELF32_BE);
    builder.add(NewSymbol::new(
        "bad\0name",
        SymbolBinding::GLOBAL,
        SymbolType::FUNC,
    ));
    let err = builder.try_build().unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));

    let mut builder = SymbolTableBuilder::new(Encoding::ELF32_LE);
    builder.add(
        NewSymbol::new("big", SymbolBinding::GLOBAL, SymbolType::OBJECT).with_value(0x1_0000_0000),
    );
    let err = builder.try_build().unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::ValueOutOfRange(_)));
}

#[test]
#[should_panic(expected = "use try_build() to handle invalid input")]
fn builder_build_panics_on_invalid_input() {
    let mut builder = SymbolTableBuilder::new(Encoding::ELF64_LE);
    builder.add(NewSymbol::new(
        "a\0",
        SymbolBinding::LOCAL,
        SymbolType::NOTYPE,
    ));
    let _ = builder.build();
}
