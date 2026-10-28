# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

The first release, 0.1.0.

### Added

- `ElfFile`: a raw file with all bytes and lossless round trips. When nothing changes,
  `ElfFile::try_build` returns the input bytes.
- `ElfImage`: the loader view with the segments, from raw files, loader-mapped images and
  remote processes (`ReadAt`). The parser can fill pages that it cannot read with zeros.
- `ElfHeaders`: the headers only, with checked address translation for raw and mapped layouts.
- `ElfBuilder`: new executables and shared objects from sections, with the `PT_LOAD` layout,
  `PT_PHDR`, `PT_INTERP` and `PT_GNU_STACK`.
- patchelf-style edits: section data, added and removed sections, new `PT_LOAD` segments, the
  program interpreter and the entry point.
- ELF32 and ELF64, little-endian and big-endian data, and the extended numbering of large header
  tables (`PN_XNUM`, `SHN_XINDEX`).
- Tables with parsers and writers: the dynamic table, symbol tables, string tables, notes, SysV
  and GNU hash tables, GNU symbol versions, section groups, `REL`, `RELA` and `RELR`
  relocations, and `.eh_frame` and `.eh_frame_hdr`.
- Relocation type names for many architectures (`Relocation::type_name`).
- Core file notes: `NT_FILE` mappings and the `NT_AUXV` auxiliary vector.
- Mapped image helpers: the image origin, the load bias, `to_mapped_image`, and
  `to_mapped_image_at` with the relative relocations.
- `validate()`: a list of the structural problems of a file or an image.
- `no_std + alloc` support. The `std` feature adds file helpers and `FileReader`.
- Examples: `elfdump`, `elfpatch`, `dump-process` and `build-tiny`.

[Unreleased]: https://github.com/napbat/elfex/commits/main
