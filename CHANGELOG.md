# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release, 0.1.0.

### Added

- `ElfFile`: a raw file with all bytes and lossless round trips. When nothing changes,
  `ElfFile::try_build` returns the input bytes. `ElfFile<D>` is generic over the storage of the
  bytes. `ElfFile::parse` borrows a byte slice and does not copy it, `ElfFile::from_vec` owns a
  `Vec<u8>`, and `ElfFile::new` keeps any storage, for example a memory map. The reads and the
  header edits work with all storage types. The edits that can make the file larger need an
  `ElfFile<Vec<u8>>` (`ElfFile::into_owned`).
- `ElfImage<'a>`: the loader view with the segments, from raw files, loader-mapped images and
  remote processes (`ReadAt`). The parser can fill pages that it cannot read with zeros. The
  segments of an image from a byte slice borrow the bytes (`Segment::data` is a `Cow`). A
  write makes a copy of a borrowed segment. `ElfImage::into_owned` copies all segments.
- `ElfHeaders`: the headers only, with checked address translation for raw and mapped layouts.
- `ElfBuilder`: new executables and shared objects from sections, with the `PT_LOAD` layout,
  `PT_PHDR`, `PT_INTERP` and `PT_GNU_STACK`. `ElfBuilder::try_layout` gives the address, the
  file offset and the size of each section before the build (`BuilderLayout`).
- patchelf-style edits: section data, added and removed sections, new `PT_LOAD` segments, the
  program interpreter and the entry point. `ElfFile::remove_section` renumbers the section
  links, the symbols (`st_shndx` and `SHT_SYMTAB_SHNDX`) and the section group members.
- ELF32 and ELF64, little-endian and big-endian data, and the extended numbering of large header
  tables (`PN_XNUM`, `SHN_XINDEX`).
- Tables with parsers and writers: the dynamic table, symbol tables, string tables, notes, SysV
  and GNU hash tables, GNU symbol versions, section groups (`GroupTable`), `REL`, `RELA` and
  `RELR` relocations, and `.eh_frame` and `.eh_frame_hdr`. Each table builder has a `try_build`
  function that returns a `Result`, and a `build` function that panics on invalid input.
- `EhFrame::parse_with_bases` decodes `DW_EH_PE_textrel` and `DW_EH_PE_datarel` pointers with
  the bases of the caller. `EhFrame::parse_fde_at` reads one FDE and its CIE, for example the
  FDE that `EhFrameHdr::find_fde` gives.
- Compressed relocation formats: the Android packed format `APS2` (`SHT_ANDROID_REL`,
  `SHT_ANDROID_RELA`, `DT_ANDROID_REL`, `DT_ANDROID_RELA`) and CREL (`SHT_CREL`, `DT_CREL`).
  `RelocationTable` decodes and encodes them (`parse_android_packed`, `write_android_packed`,
  `parse_crel`, `write_crel`). `relocation_sections`, `dynamic_relocations` (fields `android`
  and `crel`) and `to_mapped_image_at` use them. `RelocationTable::parse` parses a `REL` or
  `RELA` table with the standard entry size.
- `LinkingView` (`ElfFile::linking`, `ElfImage::linking`): a reusable view of the dynamic
  linking tables. The view parses the symbol table, the version tables and the hash tables when
  you make it, so a symbol lookup with the view is a hash table lookup only. The view is `Send`
  and `Sync`. The linking accessors of `ElfFile` and `ElfImage` parse only the tables that they
  need.
- No copies of the file data in the accessors: `StringTable<'a>` borrows its bytes, and the
  names of a `NamedSymbol<'a>` borrow the string table (`Cow<'a, str>`, a copy only for invalid
  UTF-8). `NamedSymbol::into_owned` copies the strings. `exports` and `imports` describe only
  the symbols that they return.
- Type names for relocations (`Relocation::type_name`) of x86-64, i386, `AArch64`, Arm,
  RISC-V, PowerPC, PowerPC64, S/390, MIPS, `LoongArch`, SPARC and Hexagon, and for notes
  (`Note::type_name`).
- The loader action and the field width of the x86-64 and i386 relocation types
  (`RelocationKind`, `relocation_kind`, `relocation_width`, `Relocation::kind`,
  `Relocation::width`). The width of a `wordclass` field follows the class, so x32 gets 4.
  `TlsRelocationKind` (`tls_relocation_kind`, `Relocation::tls_kind`) gives the thread-local
  storage value that a TLS type writes.
- Core file notes: `NT_FILE` mappings and the `NT_AUXV` auxiliary vector.
- Mapped image helpers: the image origin, the load bias, `to_mapped_image`, and
  `to_mapped_image_at` with the relative relocations. `ElfImage::restore_dynamic_pointers`
  writes the file addresses back into the dynamic table of a process dump.
- `validate()`: a list of the structural problems of a file, an image or the headers only
  (`ElfHeaders::validate`).
- `no_std + alloc` support. The `std` feature adds file helpers and `FileReader`. The crate
  needs a `usize` of at least 32 bits.
- Examples: `elfdump`, `elfpatch`, `dump-process` and `build-tiny`.
- Compatibility tests with real files (`tests/corpus`, ignored by default): a comparison with
  `llvm-readelf`, and a test that edits real programs and runs them.

[Unreleased]: https://github.com/napbat/elfex/commits/main
