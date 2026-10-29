//! Tests of the [`LinkingView`] that keeps the parsed tables.

use super::*;

#[test]
fn view_sorts_the_names_without_a_hash_table() {
    let encoding = Encoding::ELF64_LE;
    let mut strings = StringTableBuilder::new();
    let zed = strings.add("zed").unwrap();
    let abc = strings.add("abc").unwrap();
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(zed, 0x10, SymbolBinding::GLOBAL, 1),
            symbol(abc, 0x20, SymbolBinding::GLOBAL, 1),
            symbol(abc, 0x30, SymbolBinding::WEAK, 1),
        ],
    };
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let strtab = flat.place(strings.as_bytes());
    flat.set_dynamic(&[(DynamicTag::SYMTAB, symtab), (DynamicTag::STRTAB, strtab)]);

    let view = LinkingView::new(Linker::load(&flat).unwrap());
    assert_eq!(view.symbol_table().unwrap(), Some(&symbols));
    // If more than one symbol has the name, the lookup finds the first one.
    assert_eq!(view.lookup("abc").unwrap().unwrap().index, 2);
    assert_eq!(view.lookup("zed").unwrap().unwrap().symbol.value, 0x10);
    assert_eq!(view.lookup("missing").unwrap(), None);
    assert_eq!(names(&view.exports().unwrap()), ["zed", "abc", "abc"]);

    // The linker finds the same symbols with a linear search.
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.lookup("abc").unwrap().unwrap().index, 2);
    assert_eq!(linker.lookup("missing").unwrap(), None);
}

#[test]
fn view_returns_a_table_error_at_each_call() {
    let encoding = Encoding::ELF64_LE;
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let mut header = Vec::new();
    for word in [0xffff_u32, 1, 1, 6] {
        encoding.write_u32(&mut header, word);
    }
    let address = flat.place(&header);
    flat.set_dynamic(&[
        (DynamicTag::GNU_HASH, address),
        (DynamicTag::SYMTAB, address),
    ]);

    let view = LinkingView::new(Linker::load(&flat).unwrap());
    for _ in 0..2 {
        let error = view.gnu_hash_table().unwrap_err();
        assert_eq!(structure(&error), Some("DT_GNU_HASH"));
        assert_eq!(error.context().unwrap().address, Some(address));
        // The symbol count comes from the hash table, so the symbol accessors fail too.
        assert!(view.symbol_table().is_err());
        assert!(view.exports().is_err());
        assert!(view.lookup("foo").is_err());
    }
    // An accessor that does not need the hash table still works.
    assert_eq!(view.needed_libraries().unwrap(), Vec::<String>::new());
    assert_eq!(view.sysv_hash_table().unwrap(), None);
}

#[test]
fn bad_relocations_give_no_symbol_count() {
    let encoding = Encoding::ELF64_LE;
    let mut strings = StringTableBuilder::new();
    let foo = strings.add("foo").unwrap();
    let hashed_names: [&[u8]; 1] = [b"foo"];
    let (gnu, _) = GnuHashTable::try_build(&hashed_names, 1, encoding, 0).unwrap();
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            symbol(foo, 0x1100, SymbolBinding::GLOBAL, 1),
        ],
    };
    let mut flat = Flat::new(encoding, Machine::X86_64);
    let strtab = flat.place(strings.as_bytes());
    let symtab = flat.place(&symbols.write(encoding).unwrap());
    let gnu_address = flat.place(&gnu.write(encoding).unwrap());
    let rela = RelocationTable {
        relocations: vec![Relocation::with_addend(0x2000, 7, R_X86_64_JUMP_SLOT, 0)],
        with_addend: true,
    };
    let rela_bytes = rela.write(encoding, Machine::X86_64).unwrap();
    let rela_address = flat.place(&rela_bytes);
    let dynamic = |size: u64| {
        [
            (DynamicTag::STRTAB, strtab),
            (DynamicTag::SYMTAB, symtab),
            (DynamicTag::GNU_HASH, gnu_address),
            (DynamicTag::RELA, rela_address),
            (DynamicTag::RELASZ, size),
        ]
    };

    // A relocation that refers to symbol 7 makes the table larger than the hash table.
    flat.set_dynamic(&dynamic(len(&rela_bytes)));
    let linker = Linker::load(&flat).unwrap();
    assert_eq!(linker.max_relocation_symbol().unwrap(), Some(7));
    drop(linker);

    // A relocation table that does not parse gives no count: the hash table gives it.
    flat.set_dynamic(&dynamic(len(&rela_bytes) - 1));
    let linker = Linker::load(&flat).unwrap();
    assert!(linker.relocations().is_err());
    assert!(linker.max_relocation_symbol().is_err());
    assert_eq!(linker.symbols().unwrap().as_ref(), Some(&symbols));
}
