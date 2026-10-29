use super::*;
use crate::symbol::{Symbol, SymbolSectionIndexTable, SymbolTable};

/// A source that does not report its size.
struct UnsizedSource<'a>(&'a [u8]);

impl ReadAt for UnsizedSource<'_> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        SliceReader::new(self.0).read_at(offset, buf)
    }

    fn size(&self) -> Option<u64> {
        None
    }
}

#[test]
fn rejects_a_source_without_a_size() {
    let bytes = sample(Encoding::ELF64_LE).build();
    assert!(matches!(
        error_kind(ElfFile::read_from(&UnsizedSource(&bytes), 0)),
        ErrorKind::Generic(_)
    ));
}

#[test]
fn edits_the_data_buffer() {
    let mut elf = sample(Encoding::ELF32_BE);
    let offset = usize::try_from(target_offset(&elf, 7)).unwrap();
    elf.data_mut()[offset] = 0x42;
    assert_eq!(elf.section_data(7).unwrap()[0], 0x42);
    assert_eq!(elf.section_data_mut(4).unwrap(), []);
    assert!(matches!(
        error_kind(elf.section_data_mut(99)),
        ErrorKind::InvalidSection(_)
    ));
    elf.section_headers_mut()[7].offset = 1 << 40;
    let error = elf.section_data_mut(7).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::OffsetOutOfBounds { .. }));
    assert_eq!(
        error.context().unwrap().structure.as_deref(),
        Some("section data")
    );
}

#[test]
fn keeps_any_storage_type() {
    let elf = sample(Encoding::ELF64_LE);
    let bytes = elf.build();

    // The parse of a slice borrows the bytes.
    let borrowed = ElfFile::parse(&bytes).unwrap();
    assert!(core::ptr::eq(borrowed.as_bytes(), bytes.as_slice()));
    assert_eq!(borrowed, elf);
    assert_eq!(borrowed.exports().unwrap(), elf.exports().unwrap());

    // A header edit does not need mutable bytes.
    let mut edited = ElfFile::parse(&bytes).unwrap();
    edited.set_entry_point(0x1234);
    let built = edited.try_build().unwrap();
    assert_eq!(ElfFile::parse(&built).unwrap().entry_point(), 0x1234);
    assert!(core::ptr::eq(edited.into_inner(), bytes.as_slice()));

    // A mutable slice takes edits in place.
    let mut copy = bytes.clone();
    let mut in_place = ElfFile::new(copy.as_mut_slice()).unwrap();
    let offset = target_offset(&elf, 7);
    in_place.bytes_at_mut(offset, 1).unwrap()[0] = 0x42;
    assert_eq!(in_place.section_data(7).unwrap()[0], 0x42);
    assert_eq!(copy[usize::try_from(offset).unwrap()], 0x42);

    // An owned copy takes the edits that make the file larger.
    let mut owned = ElfFile::new(bytes.clone().into_boxed_slice())
        .unwrap()
        .into_owned();
    let section = NewSection::new(".new", SectionType::PROGBITS, vec![1, 2]);
    let index = owned.add_section(section).unwrap();
    assert_eq!(owned.section_data(index).unwrap(), [1, 2]);
    assert_eq!(
        ElfFile::from_vec(bytes.clone()).unwrap().into_inner(),
        bytes
    );
}

#[test]
fn rejects_a_load_segment_past_the_end_of_the_file() {
    let mut elf = sample(Encoding::ELF64_LE);
    let data = elf.section_by_name(".data").unwrap().header.addr;
    let index = elf
        .program_headers()
        .iter()
        .position(|segment| segment.is_load() && segment.contains_vaddr(data))
        .unwrap();
    let end = u64::try_from(elf.len()).unwrap();
    elf.program_headers_mut()[index].offset = end;
    assert!(matches!(
        error_kind(elf.slice_from_vaddr(data)),
        ErrorKind::InvalidAddress(_)
    ));
    let error = elf.read_vaddr(data, 4).unwrap_err();
    assert!(matches!(error.kind, ErrorKind::OffsetOutOfBounds { .. }));
    assert_eq!(error.context().unwrap().address, Some(data));
}

#[test]
fn reads_no_name_past_the_end_of_the_name_table() {
    let mut elf = sample(Encoding::ELF64_LE);
    elf.set_section_data(8, b"\0.interp\0".to_vec()).unwrap();
    let mut names = vec![String::new(); 9];
    names[1] = ".interp".into();
    assert_eq!(elf.section_names(), names);
}

#[test]
fn reads_the_interpreter() {
    let mut elf = sample(Encoding::ELF64_LE);
    assert_eq!(elf.interpreter().unwrap().as_deref(), Some("/lib/ld.so"));
    let index = elf
        .program_headers()
        .iter()
        .position(|segment| segment.segment_type == SegmentType::INTERP)
        .unwrap();
    elf.program_headers_mut()[index].offset = 1 << 40;
    let error = elf.interpreter().unwrap_err();
    assert!(matches!(error.kind, ErrorKind::OffsetOutOfBounds { .. }));
    assert_eq!(
        error.context().unwrap().structure.as_deref(),
        Some("PT_INTERP")
    );
    let static_file = ElfBuilder::new(Encoding::ELF64_LE).build();
    assert_eq!(static_file.interpreter().unwrap(), None);
}

#[test]
fn reads_extended_section_indices_of_dynamic_symbols() {
    let encoding = Encoding::ELF64_LE;
    let symbols = SymbolTable {
        symbols: vec![
            Symbol::default(),
            Symbol {
                shndx: SHN_XINDEX,
                ..Symbol::default()
            },
            Symbol {
                shndx: 1,
                ..Symbol::default()
            },
        ],
    };
    let indices = SymbolSectionIndexTable {
        indices: vec![0, 0x1_0000, 0],
    };
    let elf = ElfBuilder::new(encoding)
        .file_type(FileType::DYN)
        .add_section(BuilderSection {
            section_type: SectionType::DYNSYM,
            entsize: 24,
            addralign: 8,
            ..BuilderSection::progbits(".dynsym", SHF_ALLOC, symbols.write(encoding).unwrap())
        })
        .add_section(BuilderSection {
            section_type: SectionType::SYMTAB_SHNDX,
            link_name: Some(".dynsym".into()),
            entsize: 4,
            addralign: 4,
            ..BuilderSection::progbits(".dynsym_shndx", SHF_ALLOC, indices.write(encoding))
        })
        .build();
    let sections: Vec<Option<u32>> = elf
        .dynamic_symbol_list()
        .unwrap()
        .iter()
        .map(|symbol| symbol.section_index)
        .collect();
    assert_eq!(sections, [Some(0x1_0000), Some(1)]);
}
