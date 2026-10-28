//! Section headers (`Elf32_Shdr` and `Elf64_Shdr`), section constants and the compression
//! header (`Elf32_Chdr` and `Elf64_Chdr`).
//!
//! - [`SectionHeader`] parses and writes one section header. [`SectionType`] gives `sh_type`.
//! - The `SHF_*` constants (for example [`SHF_ALLOC`]) are the bits of `sh_flags`.
//! - The `SHN_*` constants (for example [`SHN_UNDEF`]) are the reserved section indices.
//! - [`GRP_COMDAT`] is a flag of a section group (`SHT_GROUP`).
//! - [`CompressionHeader`] and [`CompressionType`] describe `SHF_COMPRESSED` section data.

use crate::endian::{ByteReader, Class, Encoding};
use crate::prelude::*;
use crate::{Error, Result};
use core::ops::Range;

/// `SHN_UNDEF`: an undefined or absent section.
pub const SHN_UNDEF: u16 = 0;
/// `SHN_LORESERVE`: the first reserved section index.
pub const SHN_LORESERVE: u16 = 0xff00;
/// `SHN_LOPROC`: the first processor-specific section index.
pub const SHN_LOPROC: u16 = 0xff00;
/// `SHN_HIPROC`: the last processor-specific section index.
pub const SHN_HIPROC: u16 = 0xff1f;
/// `SHN_LOOS`: the first operating-system-specific section index.
pub const SHN_LOOS: u16 = 0xff20;
/// `SHN_HIOS`: the last operating-system-specific section index.
pub const SHN_HIOS: u16 = 0xff3f;
/// `SHN_ABS`: the symbol has an absolute value.
pub const SHN_ABS: u16 = 0xfff1;
/// `SHN_COMMON`: the symbol is a common block.
pub const SHN_COMMON: u16 = 0xfff2;
/// `SHN_XINDEX`: the real index is in the `SHT_SYMTAB_SHNDX` section, or in section header 0.
pub const SHN_XINDEX: u16 = 0xffff;
/// `SHN_HIRESERVE`: the last reserved section index.
pub const SHN_HIRESERVE: u16 = 0xffff;

/// `SHF_WRITE`: the section is writable at run time.
pub const SHF_WRITE: u64 = 0x1;
/// `SHF_ALLOC`: the section occupies memory at run time.
pub const SHF_ALLOC: u64 = 0x2;
/// `SHF_EXECINSTR`: the section contains executable instructions.
pub const SHF_EXECINSTR: u64 = 0x4;
/// `SHF_MERGE`: the linker can merge equal entries.
pub const SHF_MERGE: u64 = 0x10;
/// `SHF_STRINGS`: the section contains null-terminated strings.
pub const SHF_STRINGS: u64 = 0x20;
/// `SHF_INFO_LINK`: `sh_info` holds a section index.
pub const SHF_INFO_LINK: u64 = 0x40;
/// `SHF_LINK_ORDER`: the section keeps the order of the section that `sh_link` names.
pub const SHF_LINK_ORDER: u64 = 0x80;
/// `SHF_OS_NONCONFORMING`: the section needs operating-system-specific processing.
pub const SHF_OS_NONCONFORMING: u64 = 0x100;
/// `SHF_GROUP`: the section is a member of a section group.
pub const SHF_GROUP: u64 = 0x200;
/// `SHF_TLS`: the section holds thread-local storage.
pub const SHF_TLS: u64 = 0x400;
/// `SHF_COMPRESSED`: the section data starts with a compression header.
pub const SHF_COMPRESSED: u64 = 0x800;
/// `SHF_GNU_RETAIN`: the linker must not garbage-collect the section.
pub const SHF_GNU_RETAIN: u64 = 0x20_0000;
/// `SHF_MASKOS`: the bits for operating-system-specific flags.
pub const SHF_MASKOS: u64 = 0x0ff0_0000;
/// `SHF_MASKPROC`: the bits for processor-specific flags.
pub const SHF_MASKPROC: u64 = 0xf000_0000;
/// `SHF_EXCLUDE`: the linker excludes the section from executables and shared objects.
pub const SHF_EXCLUDE: u64 = 0x8000_0000;

/// `GRP_COMDAT`: the section group is a COMDAT group.
pub const GRP_COMDAT: u32 = 0x1;

elf_value_type! {
    /// The section type (`sh_type`).
    pub struct SectionType(u32);
    /// `SHT_NULL`: an unused section header.
    NULL = 0, "SHT_NULL";
    /// `SHT_PROGBITS`: data that the program defines.
    PROGBITS = 1, "SHT_PROGBITS";
    /// `SHT_SYMTAB`: the full symbol table.
    SYMTAB = 2, "SHT_SYMTAB";
    /// `SHT_STRTAB`: a string table.
    STRTAB = 3, "SHT_STRTAB";
    /// `SHT_RELA`: relocations with explicit addends.
    RELA = 4, "SHT_RELA";
    /// `SHT_HASH`: the System V symbol hash table.
    HASH = 5, "SHT_HASH";
    /// `SHT_DYNAMIC`: the dynamic linking table.
    DYNAMIC = 6, "SHT_DYNAMIC";
    /// `SHT_NOTE`: notes.
    NOTE = 7, "SHT_NOTE";
    /// `SHT_NOBITS`: data that occupies memory but no file bytes, for example `.bss`.
    NOBITS = 8, "SHT_NOBITS";
    /// `SHT_REL`: relocations without explicit addends.
    REL = 9, "SHT_REL";
    /// `SHT_SHLIB`: reserved.
    SHLIB = 10, "SHT_SHLIB";
    /// `SHT_DYNSYM`: the dynamic symbol table.
    DYNSYM = 11, "SHT_DYNSYM";
    /// `SHT_INIT_ARRAY`: an array of initialization functions.
    INIT_ARRAY = 14, "SHT_INIT_ARRAY";
    /// `SHT_FINI_ARRAY`: an array of termination functions.
    FINI_ARRAY = 15, "SHT_FINI_ARRAY";
    /// `SHT_PREINIT_ARRAY`: an array of pre-initialization functions.
    PREINIT_ARRAY = 16, "SHT_PREINIT_ARRAY";
    /// `SHT_GROUP`: a section group.
    GROUP = 17, "SHT_GROUP";
    /// `SHT_SYMTAB_SHNDX`: extended section indices of a symbol table.
    SYMTAB_SHNDX = 18, "SHT_SYMTAB_SHNDX";
    /// `SHT_RELR`: relative relocations in the compact RELR format.
    RELR = 19, "SHT_RELR";
    /// `SHT_ANDROID_REL`: Android packed relocations without addends.
    ANDROID_REL = 0x6000_0001, "SHT_ANDROID_REL";
    /// `SHT_ANDROID_RELA`: Android packed relocations with addends.
    ANDROID_RELA = 0x6000_0002, "SHT_ANDROID_RELA";
    /// `SHT_LLVM_ODRTAB`: the LLVM ODR table.
    LLVM_ODRTAB = 0x6fff_4c00, "SHT_LLVM_ODRTAB";
    /// `SHT_LLVM_LINKER_OPTIONS`: LLVM linker options.
    LLVM_LINKER_OPTIONS = 0x6fff_4c01, "SHT_LLVM_LINKER_OPTIONS";
    /// `SHT_LLVM_ADDRSIG`: the LLVM address-significance table.
    LLVM_ADDRSIG = 0x6fff_4c03, "SHT_LLVM_ADDRSIG";
    /// `SHT_GNU_ATTRIBUTES`: GNU object attributes.
    GNU_ATTRIBUTES = 0x6fff_fff5, "SHT_GNU_ATTRIBUTES";
    /// `SHT_GNU_HASH`: the GNU symbol hash table.
    GNU_HASH = 0x6fff_fff6, "SHT_GNU_HASH";
    /// `SHT_GNU_LIBLIST`: the GNU prelink library list.
    GNU_LIBLIST = 0x6fff_fff7, "SHT_GNU_LIBLIST";
    /// `SHT_CHECKSUM`: a checksum of the DSO content.
    CHECKSUM = 0x6fff_fff8, "SHT_CHECKSUM";
    /// `SHT_GNU_VERDEF`: symbol version definitions.
    GNU_VERDEF = 0x6fff_fffd, "SHT_GNU_VERDEF";
    /// `SHT_GNU_VERNEED`: symbol version requirements.
    GNU_VERNEED = 0x6fff_fffe, "SHT_GNU_VERNEED";
    /// `SHT_GNU_VERSYM`: the symbol version table.
    GNU_VERSYM = 0x6fff_ffff, "SHT_GNU_VERSYM";
}

impl SectionType {
    /// `SHT_LOOS`: the first value for operating-system-specific types.
    pub const LOOS: Self = Self(0x6000_0000);
    /// `SHT_HIOS`: the last value for operating-system-specific types.
    pub const HIOS: Self = Self(0x6fff_ffff);
    /// `SHT_LOPROC`: the first value for processor-specific types.
    pub const LOPROC: Self = Self(0x7000_0000);
    /// `SHT_HIPROC`: the last value for processor-specific types.
    pub const HIPROC: Self = Self(0x7fff_ffff);
    /// `SHT_LOUSER`: the first value for application-specific types.
    pub const LOUSER: Self = Self(0x8000_0000);
    /// `SHT_HIUSER`: the last value for application-specific types.
    pub const HIUSER: Self = Self(0xffff_ffff);
    /// `SHT_ARM_EXIDX`: the Arm exception index table (`EM_ARM` only).
    pub const ARM_EXIDX: Self = Self(0x7000_0001);
    /// `SHT_ARM_ATTRIBUTES`: Arm build attributes (`EM_ARM` only).
    pub const ARM_ATTRIBUTES: Self = Self(0x7000_0003);
    /// `SHT_X86_64_UNWIND`: x86-64 unwind data (`EM_X86_64` only).
    pub const X86_64_UNWIND: Self = Self(0x7000_0001);
    /// `SHT_RISCV_ATTRIBUTES`: RISC-V attributes (`EM_RISCV` only).
    pub const RISCV_ATTRIBUTES: Self = Self(0x7000_0003);
    /// `SHT_MIPS_ABIFLAGS`: MIPS ABI flags (`EM_MIPS` only).
    pub const MIPS_ABIFLAGS: Self = Self(0x7000_002a);
}

/// The size of `Elf32_Shdr` in bytes.
pub const ELF32_SECTION_HEADER_SIZE: usize = 40;
/// The size of `Elf64_Shdr` in bytes.
pub const ELF64_SECTION_HEADER_SIZE: usize = 64;

/// A section header (`Elf32_Shdr` or `Elf64_Shdr`).
///
/// The fields keep the names of the specification without the `sh_` prefix.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SectionHeader {
    /// The offset of the section name in the section name string table (`sh_name`).
    pub name: u32,
    /// The section type (`sh_type`).
    pub section_type: SectionType,
    /// The section flags (`sh_flags`): a combination of the `SHF_*` values.
    pub flags: u64,
    /// The virtual address of the section in memory (`sh_addr`), or 0.
    pub addr: u64,
    /// The file offset of the section data (`sh_offset`).
    pub offset: u64,
    /// The size of the section in bytes (`sh_size`).
    pub size: u64,
    /// A section index link (`sh_link`). The meaning depends on the section type.
    pub link: u32,
    /// Extra information (`sh_info`). The meaning depends on the section type.
    pub info: u32,
    /// The alignment of the section (`sh_addralign`). 0 and 1 mean no alignment.
    pub addralign: u64,
    /// The size of one entry for a table section (`sh_entsize`), or 0.
    pub entsize: u64,
}

impl SectionHeader {
    /// Return the size of the structure for `class`: 40 or 64 bytes.
    #[must_use]
    pub const fn size(class: Class) -> usize {
        match class {
            Class::Elf32 => ELF32_SECTION_HEADER_SIZE,
            Class::Elf64 => ELF64_SECTION_HEADER_SIZE,
        }
    }

    /// Return the standard `e_shentsize` value for `class`.
    #[must_use]
    pub const fn standard_size(class: Class) -> u16 {
        match class {
            Class::Elf32 => 40,
            Class::Elf64 => 64,
        }
    }

    /// Parse a section header from the start of `bytes`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` is
    /// shorter than the structure.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        let size = Self::size(encoding.class);
        let bytes = bytes
            .get(..size)
            .ok_or_else(|| Error::buffer_too_small(size, bytes.len()))?;
        let mut reader = ByteReader::new(bytes, encoding);
        Ok(Self {
            name: reader.u32()?,
            section_type: SectionType(reader.u32()?),
            flags: reader.addr()?,
            addr: reader.addr()?,
            offset: reader.addr()?,
            size: reader.addr()?,
            link: reader.u32()?,
            info: reader.u32()?,
            addralign: reader.addr()?,
            entsize: reader.addr()?,
        })
    }

    /// Append the serialized section header to `out`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an ELF32
    /// header has a value that does not fit in 32 bits.
    pub fn write(&self, out: &mut Vec<u8>, encoding: Encoding) -> Result<()> {
        encoding.write_u32(out, self.name);
        encoding.write_u32(out, self.section_type.0);
        encoding.write_addr(out, self.flags)?;
        encoding.write_addr(out, self.addr)?;
        encoding.write_addr(out, self.offset)?;
        encoding.write_addr(out, self.size)?;
        encoding.write_u32(out, self.link);
        encoding.write_u32(out, self.info);
        encoding.write_addr(out, self.addralign)?;
        encoding.write_addr(out, self.entsize)?;
        Ok(())
    }

    /// Return `true` if the section has file bytes: its type is not `SHT_NOBITS` or
    /// `SHT_NULL`.
    #[must_use]
    pub fn has_file_data(&self) -> bool {
        self.section_type != SectionType::NOBITS && self.section_type != SectionType::NULL
    }

    /// Return the file range of the section data, or `None` if the section has no file bytes
    /// or the end overflows.
    #[must_use]
    pub fn file_range(&self) -> Option<Range<u64>> {
        if !self.has_file_data() {
            return None;
        }
        Some(self.offset..self.offset.checked_add(self.size)?)
    }

    /// Return the virtual address range of the section, or `None` if the section does not
    /// have `SHF_ALLOC` or the end overflows.
    #[must_use]
    pub fn memory_range(&self) -> Option<Range<u64>> {
        if !self.is_alloc() {
            return None;
        }
        Some(self.addr..self.addr.checked_add(self.size)?)
    }

    /// Return `true` if the section has the `SHF_ALLOC` flag.
    #[must_use]
    pub const fn is_alloc(&self) -> bool {
        self.flags & SHF_ALLOC != 0
    }

    /// Return `true` if the section has the `SHF_WRITE` flag.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & SHF_WRITE != 0
    }

    /// Return `true` if the section has the `SHF_EXECINSTR` flag.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags & SHF_EXECINSTR != 0
    }

    /// Return `true` if the section has the `SHF_COMPRESSED` flag.
    #[must_use]
    pub const fn is_compressed(&self) -> bool {
        self.flags & SHF_COMPRESSED != 0
    }
}

elf_value_type! {
    /// The compression algorithm of a compressed section (`ch_type`).
    pub struct CompressionType(u32);
    /// `ELFCOMPRESS_ZLIB`: zlib (DEFLATE).
    ZLIB = 1, "ELFCOMPRESS_ZLIB";
    /// `ELFCOMPRESS_ZSTD`: Zstandard.
    ZSTD = 2, "ELFCOMPRESS_ZSTD";
}

/// The compression header at the start of a `SHF_COMPRESSED` section (`Elf32_Chdr` or
/// `Elf64_Chdr`).
///
/// Elfex does not decompress data. Give the bytes after the header to a decompressor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct CompressionHeader {
    /// The compression algorithm (`ch_type`).
    pub compression_type: CompressionType,
    /// The size of the uncompressed data in bytes (`ch_size`).
    pub size: u64,
    /// The alignment of the uncompressed data (`ch_addralign`).
    pub addralign: u64,
}

impl CompressionHeader {
    /// Return the size of the structure for `class`: 12 or 24 bytes.
    #[must_use]
    pub const fn size(class: Class) -> usize {
        match class {
            Class::Elf32 => 12,
            Class::Elf64 => 24,
        }
    }

    /// Parse a compression header from the start of `bytes`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` is
    /// shorter than the structure.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        let mut reader = ByteReader::new(bytes, encoding);
        let compression_type = CompressionType(reader.u32()?);
        if encoding.is_64bit() {
            // `Elf64_Chdr` has a reserved `ch_reserved` word after `ch_type`.
            reader.u32()?;
        }
        Ok(Self {
            compression_type,
            size: reader.addr()?,
            addralign: reader.addr()?,
        })
    }

    /// Append the serialized compression header to `out`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an ELF32
    /// header has a value that does not fit in 32 bits.
    pub fn write(&self, out: &mut Vec<u8>, encoding: Encoding) -> Result<()> {
        encoding.write_u32(out, self.compression_type.0);
        if encoding.is_64bit() {
            encoding.write_u32(out, 0);
        }
        encoding.write_addr(out, self.size)?;
        encoding.write_addr(out, self.addralign)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_both_classes() {
        let header = SectionHeader {
            name: 7,
            section_type: SectionType::NOBITS,
            flags: SHF_ALLOC | SHF_WRITE,
            addr: 0x2000,
            offset: 0x1000,
            size: 0x40,
            link: 0,
            info: 0,
            addralign: 16,
            entsize: 0,
        };
        for encoding in [Encoding::ELF32_BE, Encoding::ELF64_LE] {
            let mut out = Vec::new();
            header.write(&mut out, encoding).unwrap();
            assert_eq!(out.len(), SectionHeader::size(encoding.class));
            assert_eq!(SectionHeader::parse(&out, encoding).unwrap(), header);
        }
        assert_eq!(header.file_range(), None);
        assert_eq!(header.memory_range(), Some(0x2000..0x2040));
    }

    #[test]
    fn flag_accessors_and_ranges() {
        let compressed = SectionHeader {
            section_type: SectionType::PROGBITS,
            flags: SHF_COMPRESSED,
            offset: 0x100,
            size: 0x10,
            ..SectionHeader::default()
        };
        assert!(compressed.is_compressed());
        assert!(!compressed.is_alloc() && !compressed.is_writable());
        assert_eq!(compressed.memory_range(), None);
        assert_eq!(compressed.file_range(), Some(0x100..0x110));
        let wrapping = SectionHeader {
            flags: SHF_ALLOC,
            addr: u64::MAX,
            offset: u64::MAX,
            ..compressed
        };
        assert!(!wrapping.is_compressed());
        assert_eq!(wrapping.memory_range(), None);
        assert_eq!(wrapping.file_range(), None);
        let error = SectionHeader::parse(&[0; 39], Encoding::ELF32_BE).unwrap_err();
        assert!(matches!(
            error.kind(),
            crate::ErrorKind::BufferTooSmall {
                expected: 40,
                actual: 39
            }
        ));
    }

    #[test]
    fn compression_header_round_trips() {
        let header = CompressionHeader {
            compression_type: CompressionType::ZSTD,
            size: 0x1234,
            addralign: 8,
        };
        for encoding in [Encoding::ELF32_LE, Encoding::ELF64_BE] {
            let mut out = Vec::new();
            header.write(&mut out, encoding).unwrap();
            assert_eq!(out.len(), CompressionHeader::size(encoding.class));
            assert_eq!(CompressionHeader::parse(&out, encoding).unwrap(), header);
        }
    }
}
