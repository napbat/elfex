//! Tests of the prelink library list (`DT_GNU_LIBLIST`).

use super::*;
use crate::builder::{BuilderSection, ElfBuilder};
use crate::elf_file::ElfFile;
use crate::elf_image::ElfImage;
use crate::liblist::{LL_DELAY_LOAD, LL_EXACT_MATCH, Library, LibraryTable};
use crate::program::SegmentType;
use crate::section::{SHF_ALLOC, SHF_WRITE, SectionType};

/// The dynamic string table and the library list of two libraries.
fn tables(encoding: Encoding) -> (Vec<u8>, Vec<u8>) {
    let mut strings = StringTableBuilder::new();
    let c_name = strings.add("libc.so.6").unwrap();
    let math_name = strings.add("libm.so.6").unwrap();
    let list = LibraryTable {
        libraries: vec![
            Library {
                name: c_name,
                time_stamp: 0x6000_0001,
                checksum: 0x1111_2222,
                version: 1,
                flags: LL_EXACT_MATCH,
            },
            Library {
                name: math_name,
                time_stamp: 0x6000_0002,
                checksum: 0x3333_4444,
                version: 0,
                flags: LL_DELAY_LOAD,
            },
        ],
    };
    (strings.into_bytes(), list.write(encoding))
}

fn expected() -> Vec<LibraryListEntry> {
    vec![
        LibraryListEntry {
            name: "libc.so.6".into(),
            time_stamp: 0x6000_0001,
            checksum: 0x1111_2222,
            version: 1,
            flags: LL_EXACT_MATCH,
        },
        LibraryListEntry {
            name: "libm.so.6".into(),
            time_stamp: 0x6000_0002,
            checksum: 0x3333_4444,
            version: 0,
            flags: LL_DELAY_LOAD,
        },
    ]
}

#[test]
fn library_list_through_the_dynamic_table() {
    for encoding in [Encoding::ELF32_BE, Encoding::ELF64_LE] {
        let (strings, list) = tables(encoding);
        let mut flat = Flat::new(encoding, Machine::X86_64);
        // The loader relocated the pointers: `resolve_pointer` subtracts the bias.
        flat.pointer_bias = 0x10_0000;
        let strtab = flat.place(&strings);
        let liblist = flat.place(&list);
        flat.set_dynamic(&[
            (DynamicTag::STRTAB, strtab + flat.pointer_bias),
            (DynamicTag::STRSZ, len(&strings)),
            (DynamicTag::GNU_LIBLIST, liblist + flat.pointer_bias),
            (DynamicTag::GNU_LIBLISTSZ, len(&list)),
        ]);
        let linker = Linker::load(&flat).unwrap();
        assert_eq!(linker.library_list().unwrap(), Some(expected()));
    }
}

#[test]
fn a_missing_library_list_is_none() {
    let mut flat = Flat::new(Encoding::ELF64_LE, Machine::X86_64);
    flat.set_dynamic(&[(DynamicTag::STRSZ, 0)]);
    assert_eq!(Linker::load(&flat).unwrap().library_list().unwrap(), None);
}

#[test]
fn a_malformed_library_list_is_an_error() {
    let encoding = Encoding::ELF64_LE;
    let (strings, list) = tables(encoding);
    for (size, name_offset) in [(None, 0_u32), (Some(30), 0), (Some(20), 0x100)] {
        let mut flat = Flat::new(encoding, Machine::X86_64);
        let strtab = flat.place(&strings);
        let mut list = list.clone();
        if name_offset != 0 {
            list[..4].copy_from_slice(&name_offset.to_le_bytes());
        }
        let liblist = flat.place(&list);
        let mut entries = vec![
            (DynamicTag::STRTAB, strtab),
            (DynamicTag::STRSZ, len(&strings)),
            (DynamicTag::GNU_LIBLIST, liblist),
        ];
        if let Some(size) = size {
            entries.push((DynamicTag::GNU_LIBLISTSZ, size));
        }
        flat.set_dynamic(&entries);
        let error = Linker::load(&flat).unwrap().library_list().unwrap_err();
        assert!(
            matches!(
                error.kind(),
                ErrorKind::InvalidTable(_) | ErrorKind::OffsetOutOfBounds { .. }
            ),
            "{size:?} {name_offset:#x}: {error:?}"
        );
    }
}

/// A file from the builder, with the list in `.gnu.liblist`. `ElfFile`, `ElfImage` and the
/// linking view give the same entries.
#[test]
fn library_list_of_a_built_file() {
    let encoding = Encoding::ELF64_LE;
    let (strings, list) = tables(encoding);
    let builder = |dynamic: Vec<u8>| {
        ElfBuilder::new(encoding)
            .machine(Machine::X86_64)
            .add_section(BuilderSection {
                section_type: SectionType::STRTAB,
                ..BuilderSection::progbits(".dynstr", SHF_ALLOC, strings.clone())
            })
            .add_section(BuilderSection {
                section_type: SectionType::GNU_LIBLIST,
                entsize: 20,
                addralign: 4,
                link_name: Some(".dynstr".into()),
                ..BuilderSection::progbits(".gnu.liblist", SHF_ALLOC, list.clone())
            })
            .add_section(BuilderSection {
                section_type: SectionType::DYNAMIC,
                addralign: 8,
                link_name: Some(".dynstr".into()),
                ..BuilderSection::progbits(".dynamic", SHF_ALLOC | SHF_WRITE, dynamic)
            })
            .add_segment_for_section(SegmentType::DYNAMIC, ".dynamic")
    };
    let dynamic = |strtab: u64, liblist: u64| {
        DynamicTable {
            entries: vec![
                DynamicEntry::new(DynamicTag::STRTAB, strtab),
                DynamicEntry::new(DynamicTag::STRSZ, len(&strings)),
                DynamicEntry::new(DynamicTag::GNU_LIBLIST, liblist),
                DynamicEntry::new(DynamicTag::GNU_LIBLISTSZ, len(&list)),
            ],
        }
        .write(encoding)
        .unwrap()
    };
    let layout = builder(dynamic(0, 0)).try_layout().unwrap();
    let address = |name| layout.section(name).unwrap().addr;
    let bytes = builder(dynamic(address(".dynstr"), address(".gnu.liblist")))
        .try_build()
        .unwrap()
        .try_build()
        .unwrap();

    let file = ElfFile::parse(&bytes).unwrap();
    assert_eq!(file.library_list().unwrap(), Some(expected()));
    assert_eq!(
        file.linking().unwrap().library_list().unwrap(),
        Some(expected())
    );
    let image = ElfImage::parse(&bytes).unwrap();
    assert_eq!(image.library_list().unwrap(), Some(expected()));
    let mapped_bytes = image.to_mapped_image().unwrap();
    let mapped = ElfImage::parse_mapped(&mapped_bytes).unwrap();
    assert_eq!(mapped.library_list().unwrap(), Some(expected()));
}
