use super::*;
use crate::header::Machine;
use crate::prelude::*;

/// ELF32 big-endian: `DT_NEEDED` 1, `DT_STRTAB` 0x1000, `DT_NULL`.
const ELF32_BE: [u8; 24] = [
    0, 0, 0, 1, 0, 0, 0, 1, //
    0, 0, 0, 5, 0, 0, 0x10, 0, //
    0, 0, 0, 0, 0, 0, 0, 0,
];

#[test]
fn elf32_be_round_trip() {
    let (table, count) = DynamicTable::parse_with_count(&ELF32_BE, Encoding::ELF32_BE).unwrap();
    assert_eq!(count, 3);
    assert_eq!(
        table.entries,
        [
            DynamicEntry::new(DynamicTag::NEEDED, 1),
            DynamicEntry::new(DynamicTag::STRTAB, 0x1000),
        ]
    );
    assert_eq!(table.write(Encoding::ELF32_BE).unwrap(), ELF32_BE);
}

#[test]
fn elf64_le_round_trip() {
    let mut table = DynamicTable::new();
    table.push(DynamicEntry::new(DynamicTag::SONAME, 7));
    table.push(DynamicEntry::new(DynamicTag::FLAGS_1, DF_1_PIE | DF_1_NOW));
    let bytes = table.write(Encoding::ELF64_LE).unwrap();
    assert_eq!(bytes.len(), 48);
    assert_eq!(bytes[..8], [14, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        DynamicTable::parse(&bytes, Encoding::ELF64_LE).unwrap(),
        table
    );
    assert!(table.is_pie());
    assert!(table.is_bind_now());
}

#[test]
fn elf32_negative_tag_sign_extends() {
    let bytes = [0xff, 0xff, 0xff, 0xfe, 0, 0, 0, 3];
    let entry = DynamicEntry::parse(&bytes, Encoding::ELF32_BE).unwrap();
    assert_eq!(entry.tag, DynamicTag(-2));
    let mut out = Vec::new();
    entry.write(&mut out, Encoding::ELF32_BE).unwrap();
    assert_eq!(out, bytes);
}

#[test]
fn stops_at_null_with_trailing_garbage() {
    let mut bytes = ELF32_BE.to_vec();
    bytes.extend_from_slice(&[0xaa; 13]);
    let (table, count) = DynamicTable::parse_with_count(&bytes, Encoding::ELF32_BE).unwrap();
    assert_eq!(table.entries.len(), 2);
    assert_eq!(count, 3);
}

#[test]
fn missing_null_uses_complete_entries() {
    let (table, count) =
        DynamicTable::parse_with_count(&ELF32_BE[..20], Encoding::ELF32_BE).unwrap();
    assert_eq!(table.entries.len(), 2);
    assert_eq!(count, 2);
    assert_eq!(
        DynamicTable::parse(&[], Encoding::ELF64_LE)
            .unwrap()
            .entries,
        []
    );
}

#[test]
fn write_padded() {
    let table = DynamicTable::parse(&ELF32_BE, Encoding::ELF32_BE).unwrap();
    assert!(table.write_padded(Encoding::ELF32_BE, 23).is_err());
    let out = table.write_padded(Encoding::ELF32_BE, 40).unwrap();
    assert_eq!(out.len(), 40);
    assert_eq!(
        DynamicTable::parse(&out, Encoding::ELF32_BE).unwrap(),
        table
    );
}

#[test]
fn elf32_value_out_of_range() {
    let mut table = DynamicTable::new();
    table.set(DynamicTag::STRTAB, 0x1_0000_0000);
    assert!(table.write(Encoding::ELF32_LE).is_err());
}

#[test]
fn strings() {
    let strings = StringTable::new(b"\0libc.so.6\0libfoo.so\0/opt\0".to_vec());
    let mut table = DynamicTable::new();
    table.push(DynamicEntry::new(DynamicTag::NEEDED, 1));
    table.push(DynamicEntry::new(DynamicTag::SONAME, 11));
    table.push(DynamicEntry::new(DynamicTag::NEEDED, 11));
    table.push(DynamicEntry::new(DynamicTag::RUNPATH, 21));
    assert_eq!(table.needed(&strings).unwrap(), ["libc.so.6", "libfoo.so"]);
    assert_eq!(table.soname(&strings).unwrap(), Some("libfoo.so"));
    assert_eq!(table.runpath(&strings).unwrap(), Some("/opt"));
    assert_eq!(table.rpath(&strings).unwrap(), None);
    table.set(DynamicTag::SONAME, 1000);
    assert!(table.soname(&strings).is_err());
}

#[test]
fn edits() {
    let mut table = DynamicTable::new();
    table.push(DynamicEntry::new(DynamicTag::NEEDED, 1));
    table.push(DynamicEntry::new(DynamicTag::NEEDED, 2));
    table.insert(0, DynamicEntry::new(DynamicTag::SONAME, 3));
    assert_eq!(table.needed_offsets(), [1, 2]);
    assert_eq!(table.remove(DynamicTag::NEEDED), 2);
    assert!(!table.contains(DynamicTag::NEEDED));
    table.set(DynamicTag::SONAME, 4);
    assert_eq!(table.get(DynamicTag::SONAME), Some(4));
    assert_eq!(table.entries.len(), 1);
}

#[test]
fn info_fields() {
    let mut table = DynamicTable::new();
    table.push(DynamicEntry::new(DynamicTag::STRTAB, 0x400));
    table.push(DynamicEntry::new(DynamicTag::PLTREL, 7));
    table.push(DynamicEntry::new(DynamicTag::FLAGS, DF_TEXTREL));
    table.push(DynamicEntry::new(DynamicTag::GNU_HASH, 0x300));
    let info = table.info();
    assert_eq!(info.strtab, Some(0x400));
    assert_eq!(info.gnu_hash, Some(0x300));
    assert_eq!(info.pltrel, Some(DynamicTag::RELA));
    assert_eq!(info.symtab, None);
    assert_eq!(info.flags, DF_TEXTREL);
    assert!(info.textrel);
    assert!(!info.bind_now);
}

#[test]
fn pointer_and_string_tags() {
    assert!(DynamicTag::STRTAB.is_pointer(Machine::X86_64));
    assert!(!DynamicTag::DEBUG.is_pointer(Machine::X86_64));
    assert!(!DynamicTag::STRSZ.is_pointer(Machine::X86_64));
    assert!(DynamicTag::PPC64_GLINK.is_pointer(Machine::PPC64));
    assert!(!DynamicTag::PPC64_GLINK.is_pointer(Machine::AARCH64));
    assert!(DynamicTag::MIPS_RLD_MAP.is_pointer(Machine::MIPS));
    assert!(DynamicTag::AUDIT.is_string());
    assert!(!DynamicTag::AUDIT.is_pointer(Machine::X86_64));
    assert_eq!(DynamicTag::NEEDED.to_string(), "DT_NEEDED");
    assert_eq!(DynamicTag(0x7000_0001).to_string(), "0x70000001");
}
