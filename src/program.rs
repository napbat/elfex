//! Program headers (`Elf32_Phdr` and `Elf64_Phdr`) and segment constants.

use crate::endian::{ByteReader, Class, Encoding};
use crate::prelude::*;
use crate::{Error, Result};
use core::ops::Range;

/// `PF_X`: the segment is executable.
pub const PF_X: u32 = 0x1;
/// `PF_W`: the segment is writable.
pub const PF_W: u32 = 0x2;
/// `PF_R`: the segment is readable.
pub const PF_R: u32 = 0x4;
/// `PF_MASKOS`: the bits for operating-system-specific flags.
pub const PF_MASKOS: u32 = 0x0ff0_0000;
/// `PF_MASKPROC`: the bits for processor-specific flags.
pub const PF_MASKPROC: u32 = 0xf000_0000;

/// `PN_XNUM`: the `e_phnum` escape value. Section header 0 holds the real count in `sh_info`.
pub const PN_XNUM: u16 = 0xffff;

elf_value_type! {
    /// The segment type (`p_type`).
    pub struct SegmentType(u32);
    /// `PT_NULL`: an unused entry.
    NULL = 0, "PT_NULL";
    /// `PT_LOAD`: a loadable segment.
    LOAD = 1, "PT_LOAD";
    /// `PT_DYNAMIC`: the dynamic linking table.
    DYNAMIC = 2, "PT_DYNAMIC";
    /// `PT_INTERP`: the path of the program interpreter.
    INTERP = 3, "PT_INTERP";
    /// `PT_NOTE`: notes.
    NOTE = 4, "PT_NOTE";
    /// `PT_SHLIB`: reserved.
    SHLIB = 5, "PT_SHLIB";
    /// `PT_PHDR`: the program header table itself.
    PHDR = 6, "PT_PHDR";
    /// `PT_TLS`: the thread-local storage template.
    TLS = 7, "PT_TLS";
    /// `PT_GNU_EH_FRAME`: the `.eh_frame_hdr` section.
    GNU_EH_FRAME = 0x6474_e550, "PT_GNU_EH_FRAME";
    /// `PT_GNU_STACK`: the stack permissions.
    GNU_STACK = 0x6474_e551, "PT_GNU_STACK";
    /// `PT_GNU_RELRO`: the range that is read-only after relocation.
    GNU_RELRO = 0x6474_e552, "PT_GNU_RELRO";
    /// `PT_GNU_PROPERTY`: the `.note.gnu.property` section.
    GNU_PROPERTY = 0x6474_e553, "PT_GNU_PROPERTY";
    /// `PT_GNU_SFRAME`: the `.sframe` section.
    GNU_SFRAME = 0x6474_e554, "PT_GNU_SFRAME";
    /// `PT_SUNW_UNWIND`: the unwind table on Solaris.
    SUNW_UNWIND = 0x6464_e550, "PT_SUNW_UNWIND";
    /// `PT_OPENBSD_RANDOMIZE`: data that the OpenBSD loader fills with random bytes.
    OPENBSD_RANDOMIZE = 0x65a3_dbe6, "PT_OPENBSD_RANDOMIZE";
    /// `PT_OPENBSD_WXNEEDED`: the program needs writable and executable mappings.
    OPENBSD_WXNEEDED = 0x65a3_dbe7, "PT_OPENBSD_WXNEEDED";
    /// `PT_OPENBSD_BOOTDATA`: OpenBSD boot data.
    OPENBSD_BOOTDATA = 0x65a4_1be6, "PT_OPENBSD_BOOTDATA";
}

impl SegmentType {
    /// `PT_LOOS`: the first value for operating-system-specific types.
    pub const LOOS: Self = Self(0x6000_0000);
    /// `PT_HIOS`: the last value for operating-system-specific types.
    pub const HIOS: Self = Self(0x6fff_ffff);
    /// `PT_LOPROC`: the first value for processor-specific types.
    pub const LOPROC: Self = Self(0x7000_0000);
    /// `PT_HIPROC`: the last value for processor-specific types.
    pub const HIPROC: Self = Self(0x7fff_ffff);
    /// `PT_ARM_EXIDX`: the Arm exception index table (`EM_ARM` only).
    pub const ARM_EXIDX: Self = Self(0x7000_0001);
    /// `PT_AARCH64_MEMTAG_MTE`: the AArch64 memory tags (`EM_AARCH64` only).
    pub const AARCH64_MEMTAG_MTE: Self = Self(0x7000_0002);
    /// `PT_MIPS_REGINFO`: the MIPS register usage information (`EM_MIPS` only).
    pub const MIPS_REGINFO: Self = Self(0x7000_0000);
    /// `PT_MIPS_ABIFLAGS`: the MIPS ABI flags (`EM_MIPS` only).
    pub const MIPS_ABIFLAGS: Self = Self(0x7000_0003);
    /// `PT_RISCV_ATTRIBUTES`: the RISC-V attributes (`EM_RISCV` only).
    pub const RISCV_ATTRIBUTES: Self = Self(0x7000_0003);
}

/// The size of `Elf32_Phdr` in bytes.
pub const ELF32_PROGRAM_HEADER_SIZE: usize = 32;
/// The size of `Elf64_Phdr` in bytes.
pub const ELF64_PROGRAM_HEADER_SIZE: usize = 56;

/// A program header (`Elf32_Phdr` or `Elf64_Phdr`).
///
/// The fields keep the names of the specification without the `p_` prefix. ELF32 and ELF64
/// store the fields in a different order. [`Self::parse`] and [`Self::write`] use the order of
/// the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgramHeader {
    /// The segment type (`p_type`).
    pub segment_type: SegmentType,
    /// The segment flags (`p_flags`): a combination of `PF_R`, `PF_W` and `PF_X`.
    pub flags: u32,
    /// The file offset of the segment data (`p_offset`).
    pub offset: u64,
    /// The virtual address of the segment (`p_vaddr`).
    pub vaddr: u64,
    /// The physical address of the segment (`p_paddr`).
    pub paddr: u64,
    /// The number of bytes in the file (`p_filesz`).
    pub filesz: u64,
    /// The number of bytes in memory (`p_memsz`). The bytes after `filesz` are zero.
    pub memsz: u64,
    /// The alignment of the segment (`p_align`). 0 and 1 mean no alignment.
    pub align: u64,
}

impl ProgramHeader {
    /// Return the size of the structure for `class`: 32 or 56 bytes.
    #[must_use]
    pub const fn size(class: Class) -> usize {
        match class {
            Class::Elf32 => ELF32_PROGRAM_HEADER_SIZE,
            Class::Elf64 => ELF64_PROGRAM_HEADER_SIZE,
        }
    }

    /// Return the standard `e_phentsize` value for `class`.
    #[must_use]
    pub const fn standard_size(class: Class) -> u16 {
        match class {
            Class::Elf32 => 32,
            Class::Elf64 => 56,
        }
    }

    /// Parse a program header from the start of `bytes`.
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
        let segment_type = SegmentType(reader.u32()?);
        if encoding.is_64bit() {
            Ok(Self {
                segment_type,
                flags: reader.u32()?,
                offset: reader.u64()?,
                vaddr: reader.u64()?,
                paddr: reader.u64()?,
                filesz: reader.u64()?,
                memsz: reader.u64()?,
                align: reader.u64()?,
            })
        } else {
            let offset = reader.addr()?;
            let vaddr = reader.addr()?;
            let paddr = reader.addr()?;
            let filesz = reader.addr()?;
            let memsz = reader.addr()?;
            let flags = reader.u32()?;
            let align = reader.addr()?;
            Ok(Self {
                segment_type,
                flags,
                offset,
                vaddr,
                paddr,
                filesz,
                memsz,
                align,
            })
        }
    }

    /// Append the serialized program header to `out`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an ELF32
    /// header has a value that does not fit in 32 bits.
    pub fn write(&self, out: &mut Vec<u8>, encoding: Encoding) -> Result<()> {
        encoding.write_u32(out, self.segment_type.0);
        if encoding.is_64bit() {
            encoding.write_u32(out, self.flags);
        }
        encoding.write_addr(out, self.offset)?;
        encoding.write_addr(out, self.vaddr)?;
        encoding.write_addr(out, self.paddr)?;
        encoding.write_addr(out, self.filesz)?;
        encoding.write_addr(out, self.memsz)?;
        if !encoding.is_64bit() {
            encoding.write_u32(out, self.flags);
        }
        encoding.write_addr(out, self.align)?;
        Ok(())
    }

    /// Return the file range of the segment data, or `None` if the end overflows.
    #[must_use]
    pub fn file_range(&self) -> Option<Range<u64>> {
        Some(self.offset..self.offset.checked_add(self.filesz)?)
    }

    /// Return the virtual address range of the segment in memory, or `None` on overflow.
    #[must_use]
    pub fn memory_range(&self) -> Option<Range<u64>> {
        Some(self.vaddr..self.vaddr.checked_add(self.memsz)?)
    }

    /// Return `true` if `vaddr` is in the memory range of the segment.
    #[must_use]
    pub fn contains_vaddr(&self, vaddr: u64) -> bool {
        self.memory_range()
            .is_some_and(|range| range.contains(&vaddr))
    }

    /// Return `true` for a `PT_LOAD` segment.
    #[must_use]
    pub fn is_load(&self) -> bool {
        self.segment_type == SegmentType::LOAD
    }

    /// Return `true` if the segment has the `PF_R` flag.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.flags & PF_R != 0
    }

    /// Return `true` if the segment has the `PF_W` flag.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    /// Return `true` if the segment has the `PF_X` flag.
    #[must_use]
    pub const fn is_executable(&self) -> bool {
        self.flags & PF_X != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_in_class_field_order() {
        let header = ProgramHeader {
            segment_type: SegmentType::LOAD,
            flags: PF_R | PF_X,
            offset: 0x1000,
            vaddr: 0x40_1000,
            paddr: 0x40_1000,
            filesz: 0x20,
            memsz: 0x30,
            align: 0x1000,
        };
        for encoding in [Encoding::ELF32_LE, Encoding::ELF64_BE] {
            let mut out = Vec::new();
            header.write(&mut out, encoding).unwrap();
            assert_eq!(out.len(), ProgramHeader::size(encoding.class));
            assert_eq!(ProgramHeader::parse(&out, encoding).unwrap(), header);
        }
        let mut elf32 = Vec::new();
        header.write(&mut elf32, Encoding::ELF32_LE).unwrap();
        // ELF32 puts `p_flags` after `p_memsz`.
        assert_eq!(
            Encoding::ELF32_LE.read_u32(&elf32, 24).unwrap(),
            PF_R | PF_X
        );
        assert!(header.contains_vaddr(0x40_102f));
        assert!(!header.contains_vaddr(0x40_1030));
    }
}
