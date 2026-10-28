use super::*;
use crate::ErrorKind;

const ENCODINGS: [Encoding; 4] = [
    Encoding::ELF32_LE,
    Encoding::ELF32_BE,
    Encoding::ELF64_LE,
    Encoding::ELF64_BE,
];

/// The dynamic symbol names. Index 0 is the null symbol.
const NAMES: [&[u8]; 9] = [
    b"", b"printf", b"puts", b"malloc", b"free", b"exit", b"_start", b"memcpy", b"strlen",
];

/// Return a lookup callback that gets the symbol names from `names`.
fn name_of<'a>(names: &'a [&'a [u8]]) -> impl FnMut(u32) -> Option<&'a [u8]> + 'a {
    move |index| {
        usize::try_from(index)
            .ok()
            .and_then(|index| names.get(index))
            .copied()
    }
}

fn index_u32(index: usize) -> u32 {
    u32::try_from(index).unwrap()
}

fn assert_invalid_table(result: Result<impl core::fmt::Debug>) {
    let error = result.unwrap_err();
    assert!(
        matches!(error.kind(), ErrorKind::InvalidTable(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn known_hash_values() {
    assert_eq!(sysv_hash(b"printf"), 0x0779_05a6);
    assert_eq!(sysv_hash(b""), 0);
    assert_eq!(sysv_hash(b"exit"), 0x0006_cf04);
    assert_eq!(gnu_hash(b"printf"), 0x156b_2bb8);
    assert_eq!(gnu_hash(b""), 5381);
    assert_eq!(gnu_hash(b"puts"), 0x7c9c_7b11);
}

#[test]
fn sysv_hash_clears_top_bits() {
    let name = [b'z'; 64];
    assert_eq!(sysv_hash(&name) & 0xf000_0000, 0);
}

#[test]
fn sysv_entry_size_by_machine() {
    assert_eq!(sysv_hash_entry_size(Machine::NONE, Class::Elf64), 4);
    assert_eq!(sysv_hash_entry_size(Machine::S390, Class::Elf32), 4);
    assert_eq!(sysv_hash_entry_size(Machine::S390, Class::Elf64), 8);
    assert_eq!(sysv_hash_entry_size(Machine::ALPHA, Class::Elf64), 8);
}

#[test]
fn default_bucket_count_matches_gnu_ld() {
    assert_eq!(default_bucket_count(0), 1);
    assert_eq!(default_bucket_count(2), 1);
    assert_eq!(default_bucket_count(9), 3);
    assert_eq!(default_bucket_count(17), 17);
    assert_eq!(default_bucket_count(1_000_000), 262_147);
}

#[test]
fn sysv_round_trip() {
    for encoding in ENCODINGS {
        for nbucket in [0, 1, 3, 20] {
            let table = SysvHashTable::build(&NAMES, nbucket).unwrap();
            assert_eq!(table.symbol_count(), 9);
            let bytes = table.write(encoding, 4).unwrap();
            assert_eq!(bytes.len(), (2 + table.buckets.len() + 9) * 4);
            let parsed = SysvHashTable::parse(&bytes, encoding, 4).unwrap();
            assert_eq!(parsed, table);
            for (index, name) in NAMES.iter().enumerate().skip(1) {
                assert_eq!(parsed.lookup(name, name_of(&NAMES)), Some(index_u32(index)));
            }
            assert_eq!(parsed.lookup(b"absent", name_of(&NAMES)), None);
            assert_eq!(parsed.lookup(b"", name_of(&NAMES)), None);
        }
    }
}

#[test]
fn sysv_header_layout() {
    let table = SysvHashTable::build(&NAMES, 3).unwrap();
    let bytes = table.write(Encoding::ELF32_BE, 4).unwrap();
    assert_eq!(bytes[..8], [0, 0, 0, 3, 0, 0, 0, 9]);
}

#[test]
fn sysv_lookup_finds_first_duplicate() {
    let names: [&[u8]; 4] = [b"", b"dup", b"other", b"dup"];
    let table = SysvHashTable::build(&names, 1).unwrap();
    assert_eq!(table.lookup(b"dup", name_of(&names)), Some(1));
}

#[test]
fn sysv_empty_table() {
    let table = SysvHashTable::build(&[], 0).unwrap();
    assert_eq!(table.symbol_count(), 0);
    let bytes = table.write(Encoding::ELF64_LE, 4).unwrap();
    let parsed = SysvHashTable::parse(&bytes, Encoding::ELF64_LE, 4).unwrap();
    assert_eq!(parsed.lookup(b"printf", name_of(&NAMES)), None);
}

#[test]
fn sysv_eight_byte_entries() {
    let table = SysvHashTable::build(&NAMES, 0).unwrap();
    for encoding in [Encoding::ELF64_LE, Encoding::ELF64_BE] {
        let bytes = table.write(encoding, 8).unwrap();
        assert_eq!(bytes.len(), (2 + 3 + 9) * 8);
        let parsed = SysvHashTable::parse(&bytes, encoding, 8).unwrap();
        assert_eq!(parsed, table);
        assert_eq!(parsed.lookup(b"memcpy", name_of(&NAMES)), Some(7));
    }

    // Set the high half of the first bucket word.
    let mut bytes = table.write(Encoding::ELF64_LE, 8).unwrap();
    bytes[2 * 8 + 4] = 1;
    assert_invalid_table(SysvHashTable::parse(&bytes, Encoding::ELF64_LE, 8));
}

#[test]
fn sysv_rejects_bad_entry_size() {
    let table = SysvHashTable::build(&NAMES, 0).unwrap();
    let bytes = table.write(Encoding::ELF32_LE, 4).unwrap();
    assert_invalid_table(SysvHashTable::parse(&bytes, Encoding::ELF32_LE, 2));
    assert_invalid_table(table.write(Encoding::ELF32_LE, 16));
}

#[test]
fn sysv_rejects_truncated_data() {
    let table = SysvHashTable::build(&NAMES, 0).unwrap();
    let mut bytes = table.write(Encoding::ELF32_LE, 4).unwrap();
    bytes.pop();
    assert_invalid_table(SysvHashTable::parse(&bytes, Encoding::ELF32_LE, 4));

    let error = SysvHashTable::parse(&[0; 4], Encoding::ELF32_LE, 4).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::BufferTooSmall { .. }));

    // Huge counts must fail before an allocation.
    let huge = [0xff; 8];
    assert_invalid_table(SysvHashTable::parse(&huge, Encoding::ELF32_LE, 4));
    assert_invalid_table(SysvHashTable::parse(&[0xff; 16], Encoding::ELF64_LE, 8));
}

#[test]
fn sysv_cyclic_chain_terminates() {
    // Symbol 1 points to symbol 2, and symbol 2 points back to symbol 1.
    let table = SysvHashTable {
        buckets: vec![1],
        chains: vec![0, 2, 1],
    };
    let mut calls = 0;
    let found = table.lookup(b"absent", |_| {
        calls += 1;
        Some(b"other".as_slice())
    });
    assert_eq!(found, None);
    assert!(calls <= 3);

    // A bucket that points after the chain array.
    let table = SysvHashTable {
        buckets: vec![7],
        chains: vec![0],
    };
    assert_eq!(table.lookup(b"absent", |_| None), None);
}

/// Return the dynamic symbol names after a reorder of the hashed names by `order`.
fn reordered<'a>(hashed: &[&'a [u8]], order: &[usize]) -> Vec<&'a [u8]> {
    let mut names = vec![b"".as_slice()];
    names.extend(order.iter().map(|&index| hashed[index]));
    names
}

fn check_gnu_round_trip(hashed: &[&[u8]], encoding: Encoding, nbuckets: u32) {
    let (table, order) = GnuHashTable::build(hashed, 1, encoding, nbuckets).unwrap();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (0..hashed.len()).collect::<Vec<_>>());
    assert!(table.bloom.len().is_power_of_two());

    let dynsym = reordered(hashed, &order);
    let bytes = table.write(encoding).unwrap();
    let parsed = GnuHashTable::parse(&bytes, encoding).unwrap();
    assert_eq!(parsed, table);
    assert_eq!(parsed.symbol_count(), index_u32(dynsym.len()));
    for (index, name) in dynsym.iter().enumerate().skip(1) {
        assert!(parsed.maybe_contains(gnu_hash(name)));
        assert_eq!(
            parsed.lookup(name, name_of(&dynsym)),
            Some(index_u32(index))
        );
    }
    let absent_names: [&[u8]; 3] = [b"absent", b"", b"printf2"];
    for absent in absent_names {
        assert_eq!(parsed.lookup(absent, name_of(&dynsym)), None);
    }

    // The parser ignores bytes after the end of the chains.
    let mut padded = bytes.clone();
    padded.extend_from_slice(&[0xff; 12]);
    assert_eq!(GnuHashTable::parse(&padded, encoding).unwrap(), table);
}

#[test]
fn gnu_round_trip() {
    for encoding in ENCODINGS {
        for nbuckets in [0, 1, 2, 5] {
            check_gnu_round_trip(&NAMES[1..], encoding, nbuckets);
        }
    }
}

#[test]
fn gnu_round_trip_many_symbols() {
    let owned: Vec<String> = (0..100).map(|index| format!("symbol_{index}")).collect();
    let hashed: Vec<&[u8]> = owned.iter().map(String::as_bytes).collect();
    for encoding in ENCODINGS {
        check_gnu_round_trip(&hashed, encoding, 0);
    }
    let (table, _) = GnuHashTable::build(&hashed, 1, Encoding::ELF32_LE, 0).unwrap();
    assert_eq!(table.buckets.len(), 97);
    assert_eq!(table.bloom.len(), 64);
    assert_eq!(table.bloom_shift, 11);
}

#[test]
fn gnu_parse_explicit_bytes() {
    let encoding = Encoding::ELF32_LE;
    let mut bytes = Vec::new();
    // nbuckets, symoffset, bloom_size, bloom_shift.
    for value in [1, 1, 1, 5] {
        encoding.write_u32(&mut bytes, value);
    }
    encoding.write_u32(&mut bytes, u32::MAX);
    encoding.write_u32(&mut bytes, 1);
    encoding.write_u32(&mut bytes, gnu_hash(b"a") & !1);
    encoding.write_u32(&mut bytes, gnu_hash(b"b") | 1);
    let table = GnuHashTable::parse(&bytes, encoding).unwrap();
    assert_eq!(table.class, Class::Elf32);
    assert_eq!(table.bloom, [u64::from(u32::MAX)]);
    assert_eq!(table.buckets, [1]);
    assert_eq!(table.chains.len(), 2);
    assert_eq!(table.symbol_count(), 3);
    let names: [&[u8]; 3] = [b"", b"a", b"b"];
    assert_eq!(table.lookup(b"b", name_of(&names)), Some(2));
    assert_eq!(table.lookup(b"c", name_of(&names)), None);
    assert_eq!(table.write(encoding).unwrap(), bytes);
}

#[test]
fn gnu_bloom_filter_rejects_names() {
    let names: [&[u8]; 2] = [b"", b"a"];
    let table = GnuHashTable {
        class: Class::Elf64,
        symoffset: 1,
        bloom_shift: 6,
        bloom: vec![0],
        buckets: vec![1],
        chains: vec![gnu_hash(b"a") | 1],
    };
    assert!(!table.maybe_contains(gnu_hash(b"a")));
    assert_eq!(table.lookup(b"a", name_of(&names)), None);
}

#[test]
fn gnu_rejects_truncated_chains() {
    for encoding in ENCODINGS {
        let (table, _) = GnuHashTable::build(&NAMES[1..], 1, encoding, 0).unwrap();
        let mut bytes = table.write(encoding).unwrap();
        bytes.truncate(bytes.len() - 4);
        assert_invalid_table(GnuHashTable::parse(&bytes, encoding));
    }
}

#[test]
fn gnu_rejects_truncated_header_parts() {
    let encoding = Encoding::ELF64_LE;
    let error = GnuHashTable::parse(&[0; 12], encoding).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::BufferTooSmall { .. }));

    // A huge bloom_size must fail before an allocation.
    let mut bytes = Vec::new();
    for value in [1, 1, u32::MAX, 6] {
        encoding.write_u32(&mut bytes, value);
    }
    assert_invalid_table(GnuHashTable::parse(&bytes, encoding));
}

#[test]
fn gnu_empty_table() {
    for encoding in ENCODINGS {
        let (table, order) = GnuHashTable::build(&[], 3, encoding, 0).unwrap();
        assert_eq!(order, Vec::<usize>::new());
        assert_eq!(table.buckets, [0]);
        assert_eq!(table.chains, Vec::<u32>::new());
        assert_eq!(table.symbol_count(), 3);
        let bytes = table.write(encoding).unwrap();
        let parsed = GnuHashTable::parse(&bytes, encoding).unwrap();
        assert_eq!(parsed, table);
        assert_eq!(parsed.lookup(b"printf", name_of(&NAMES)), None);
    }
}

/// An empty Bloom filter passes all names to the buckets. An empty bucket or a bucket before
/// `symoffset` has no symbols.
#[test]
fn gnu_lookup_with_empty_bloom_filter() {
    for bucket in [0, 2] {
        let table = GnuHashTable {
            class: Class::Elf64,
            symoffset: 3,
            bloom_shift: 6,
            bloom: Vec::new(),
            buckets: vec![bucket; 2],
            chains: vec![gnu_hash(b"printf") | 1],
        };
        assert!(table.maybe_contains(gnu_hash(b"printf")));
        assert!(table.maybe_contains(0));
        assert_eq!(table.lookup(b"printf", name_of(&NAMES)), None);
    }
}

#[test]
fn gnu_build_rejects_bad_input() {
    assert_invalid_table(GnuHashTable::build(&NAMES[1..], 0, Encoding::ELF32_LE, 0));
    let error = GnuHashTable::build(&NAMES[1..], u32::MAX, Encoding::ELF32_LE, 0).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::ValueOutOfRange(_)));
}

#[test]
fn gnu_write_rejects_other_class() {
    let (table, _) = GnuHashTable::build(&NAMES[1..], 1, Encoding::ELF64_LE, 0).unwrap();
    assert_invalid_table(table.write(Encoding::ELF32_LE));
}
