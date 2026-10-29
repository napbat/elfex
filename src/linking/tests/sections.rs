//! Tests of the linking readers with table sections, as an `ElfFile` gives them, and of
//! malformed tables that the dynamic table names.

use super::*;

/// Return a dynamic symbol table with the null symbol and a defined symbol `foo` with
/// `st_shndx` `shndx`, and its string table.
fn dynamic_symbols(encoding: Encoding, shndx: u16) -> (Vec<u8>, Vec<u8>) {
    let mut strings = StringTableBuilder::new();
    let foo = strings.add("foo").unwrap();
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(foo, 0x10, SymbolBinding::GLOBAL, shndx),
        ],
    };
    (
        symbols.write(encoding).unwrap(),
        strings.as_bytes().to_vec(),
    )
}

/// Return `true` for the error kinds of a malformed table: a bad value, or an entry that is
/// not fully in the data.
fn is_table_error(error: &Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::InvalidTable(_)
            | ErrorKind::BufferTooSmall { .. }
            | ErrorKind::OffsetOutOfBounds { .. }
    )
}

#[test]
fn table_sections_replace_the_dynamic_tables() {
    let encoding = Encoding::ELF32_LE;
    let (symbols, strings) = dynamic_symbols(encoding, SHN_XINDEX);
    let indices = SymbolSectionIndexTable {
        indices: vec![0, 0x1_0002],
    };
    let versym = VersymTable {
        entries: vec![0, 1],
    };
    let mut flat = Flat::new(encoding, Machine::I386);
    flat.tables = vec![
        (TableSection::DynamicSymbols, symbols, 16, 0),
        (TableSection::DynamicStrings, strings, 0, 0),
        (
            TableSection::DynamicSymbolIndices,
            indices.write(encoding),
            4,
            0,
        ),
        (TableSection::Versym, versym.write(encoding), 2, 0),
    ];
    let linker = Linker::load(&flat).unwrap();
    let list = linker.all_symbols().unwrap();
    assert_eq!(names(&list), ["foo"]);
    assert_eq!(list[0].section_index, Some(0x1_0002));
    assert_eq!(linker.version_tables().unwrap().versym, Some(versym));
}

#[test]
fn malformed_table_sections_name_the_section_type() {
    let encoding = Encoding::ELF64_BE;
    let (symbols, strings) = dynamic_symbols(encoding, SHN_XINDEX);
    let cases = [
        (TableSection::DynamicSymbols, "SHT_DYNSYM"),
        (TableSection::DynamicSymbolIndices, "SHT_SYMTAB_SHNDX"),
        (TableSection::Versym, "SHT_GNU_versym"),
        (TableSection::Verdef, "SHT_GNU_verdef"),
        (TableSection::Verneed, "SHT_GNU_verneed"),
    ];
    for (table, expected) in cases {
        let mut flat = Flat::new(encoding, Machine::PPC64);
        // The first section of a table type wins.
        flat.tables = vec![
            (table, vec![0; 3], 24, 1),
            (TableSection::DynamicSymbols, symbols.clone(), 24, 0),
            (TableSection::DynamicStrings, strings.clone(), 0, 0),
        ];
        let error = Linker::load(&flat).unwrap().all_symbols().unwrap_err();
        assert!(is_table_error(&error), "{error}");
        assert_eq!(structure(&error), Some(expected), "{error}");
    }
}

#[test]
fn malformed_version_tables_have_the_tag_and_the_address() {
    for (tag, expected) in [
        (DynamicTag::VERDEF, "DT_VERDEF"),
        (DynamicTag::VERNEED, "DT_VERNEED"),
    ] {
        let mut flat = Flat::new(Encoding::ELF32_BE, Machine::PPC);
        let address = flat.place(&[0; 3]);
        flat.set_dynamic(&[(tag, address)]);
        let error = Linker::load(&flat).unwrap().version_tables().unwrap_err();
        assert!(is_table_error(&error), "{error}");
        assert_eq!(structure(&error), Some(expected), "{error}");
        assert_eq!(error.context().unwrap().address, Some(address));
    }
}

#[test]
fn malformed_relr_table_has_the_tag_and_the_address() {
    let encoding = Encoding::ELF64_LE;
    let mut flat = Flat::new(encoding, Machine::AARCH64);
    // A bitmap word needs an address word before it.
    let mut bitmap = Vec::new();
    encoding.write_u64(&mut bitmap, 0b11);
    let address = flat.place(&bitmap);
    flat.set_dynamic(&[
        (DynamicTag::RELR, address),
        (DynamicTag::RELRSZ, len(&bitmap)),
    ]);
    let error = Linker::load(&flat).unwrap().relocations().unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "{error}"
    );
    assert_eq!(structure(&error), Some("DT_RELR"));
    assert_eq!(error.context().unwrap().address, Some(address));
}

#[test]
fn string_offset_past_the_string_table_is_an_error() {
    let mut flat = Flat::new(Encoding::ELF32_LE, Machine::ARM);
    let strtab = flat.place(b"\0libm.so.6\0");
    flat.set_dynamic(&[
        (DynamicTag::STRTAB, strtab),
        (DynamicTag::STRSZ, 11),
        (DynamicTag::NEEDED, 1),
        (DynamicTag::NEEDED, 11),
    ]);
    let error = Linker::load(&flat).unwrap().needed_libraries().unwrap_err();
    assert_eq!(structure(&error), Some("DT_STRTAB"), "{error}");
}
