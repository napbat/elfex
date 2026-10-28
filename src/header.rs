//! The ELF file header (`Elf32_Ehdr` and `Elf64_Ehdr`).

use crate::endian::{ByteReader, Class, Encoding};
use crate::ident::{EI_NIDENT, Ident};
use crate::prelude::*;
use crate::{Error, Result};

elf_value_type! {
    /// The object file type (`e_type`).
    pub struct FileType(u16);
    /// `ET_NONE`: no file type.
    NONE = 0, "ET_NONE";
    /// `ET_REL`: a relocatable object file.
    REL = 1, "ET_REL";
    /// `ET_EXEC`: an executable file with fixed addresses.
    EXEC = 2, "ET_EXEC";
    /// `ET_DYN`: a shared object or a position-independent executable.
    DYN = 3, "ET_DYN";
    /// `ET_CORE`: a core file.
    CORE = 4, "ET_CORE";
}

impl FileType {
    /// `ET_LOOS`: the first value for operating-system-specific types.
    pub const LOOS: Self = Self(0xfe00);
    /// `ET_HIOS`: the last value for operating-system-specific types.
    pub const HIOS: Self = Self(0xfeff);
    /// `ET_LOPROC`: the first value for processor-specific types.
    pub const LOPROC: Self = Self(0xff00);
    /// `ET_HIPROC`: the last value for processor-specific types.
    pub const HIPROC: Self = Self(0xffff);
}

elf_value_type! {
    /// The target architecture (`e_machine`).
    pub struct Machine(u16);
    /// `EM_NONE`: no machine.
    NONE = 0, "EM_NONE";
    /// `EM_M32`: AT&T WE 32100.
    M32 = 1, "EM_M32";
    /// `EM_SPARC`: SPARC.
    SPARC = 2, "EM_SPARC";
    /// `EM_386`: Intel 80386.
    I386 = 3, "EM_386";
    /// `EM_68K`: Motorola 68000.
    M68K = 4, "EM_68K";
    /// `EM_88K`: Motorola 88000.
    M88K = 5, "EM_88K";
    /// `EM_IAMCU`: Intel MCU.
    IAMCU = 6, "EM_IAMCU";
    /// `EM_860`: Intel 80860.
    I860 = 7, "EM_860";
    /// `EM_MIPS`: MIPS I.
    MIPS = 8, "EM_MIPS";
    /// `EM_S370`: IBM System/370.
    S370 = 9, "EM_S370";
    /// `EM_MIPS_RS3_LE`: MIPS RS3000 little-endian.
    MIPS_RS3_LE = 10, "EM_MIPS_RS3_LE";
    /// `EM_PARISC`: HP PA-RISC.
    PARISC = 15, "EM_PARISC";
    /// `EM_SPARC32PLUS`: SPARC with enhanced instruction set.
    SPARC32PLUS = 18, "EM_SPARC32PLUS";
    /// `EM_PPC`: 32-bit PowerPC.
    PPC = 20, "EM_PPC";
    /// `EM_PPC64`: 64-bit PowerPC.
    PPC64 = 21, "EM_PPC64";
    /// `EM_S390`: IBM S/390 and z/Architecture.
    S390 = 22, "EM_S390";
    /// `EM_ARM`: 32-bit Arm.
    ARM = 40, "EM_ARM";
    /// `EM_SH`: Hitachi SH.
    SH = 42, "EM_SH";
    /// `EM_SPARCV9`: SPARC V9.
    SPARCV9 = 43, "EM_SPARCV9";
    /// `EM_IA_64`: Intel Itanium.
    IA_64 = 50, "EM_IA_64";
    /// `EM_X86_64`: AMD x86-64.
    X86_64 = 62, "EM_X86_64";
    /// `EM_VAX`: DEC VAX.
    VAX = 75, "EM_VAX";
    /// `EM_AVR`: Atmel AVR.
    AVR = 83, "EM_AVR";
    /// `EM_OPENRISC`: OpenRISC.
    OPENRISC = 92, "EM_OPENRISC";
    /// `EM_ARC_COMPACT`: ARCompact.
    ARC_COMPACT = 93, "EM_ARC_COMPACT";
    /// `EM_XTENSA`: Tensilica Xtensa.
    XTENSA = 94, "EM_XTENSA";
    /// `EM_MSP430`: TI MSP430.
    MSP430 = 105, "EM_MSP430";
    /// `EM_BLACKFIN`: Analog Devices Blackfin.
    BLACKFIN = 106, "EM_BLACKFIN";
    /// `EM_ALTERA_NIOS2`: Altera Nios II.
    ALTERA_NIOS2 = 113, "EM_ALTERA_NIOS2";
    /// `EM_HEXAGON`: Qualcomm Hexagon.
    HEXAGON = 164, "EM_HEXAGON";
    /// `EM_AARCH64`: 64-bit Arm.
    AARCH64 = 183, "EM_AARCH64";
    /// `EM_MICROBLAZE`: Xilinx MicroBlaze.
    MICROBLAZE = 189, "EM_MICROBLAZE";
    /// `EM_CUDA`: NVIDIA CUDA.
    CUDA = 190, "EM_CUDA";
    /// `EM_TILEGX`: Tilera TILE-Gx.
    TILEGX = 191, "EM_TILEGX";
    /// `EM_AMDGPU`: AMD GPU.
    AMDGPU = 224, "EM_AMDGPU";
    /// `EM_RISCV`: RISC-V.
    RISCV = 243, "EM_RISCV";
    /// `EM_BPF`: Linux BPF.
    BPF = 247, "EM_BPF";
    /// `EM_CSKY`: C-SKY.
    CSKY = 252, "EM_CSKY";
    /// `EM_LOONGARCH`: LoongArch.
    LOONGARCH = 258, "EM_LOONGARCH";
    /// `EM_ALPHA`: DEC Alpha (unofficial value).
    ALPHA = 0x9026, "EM_ALPHA";
}

/// The size of `Elf32_Ehdr` in bytes.
pub const ELF32_HEADER_SIZE: usize = 52;
/// The size of `Elf64_Ehdr` in bytes.
pub const ELF64_HEADER_SIZE: usize = 64;

/// The ELF file header (`Elf32_Ehdr` or `Elf64_Ehdr`).
///
/// The fields keep the names of the specification without the `e_` prefix. Address and offset
/// fields are `u64` for both classes.
///
/// The count fields are the raw values. If the file uses extended numbering, `shnum`,
/// `shstrndx` or `phnum` hold an escape value, and section header 0 holds the real value.
/// [`ElfHeaders`](crate::ElfHeaders) resolves this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileHeader {
    /// The identification bytes (`e_ident`).
    pub ident: Ident,
    /// The object file type (`e_type`).
    pub file_type: FileType,
    /// The target architecture (`e_machine`).
    pub machine: Machine,
    /// The object file version (`e_version`).
    pub version: u32,
    /// The virtual address of the entry point (`e_entry`), or 0.
    pub entry: u64,
    /// The file offset of the program header table (`e_phoff`), or 0.
    pub phoff: u64,
    /// The file offset of the section header table (`e_shoff`), or 0.
    pub shoff: u64,
    /// The processor-specific flags (`e_flags`).
    pub flags: u32,
    /// The size of this header in bytes (`e_ehsize`).
    pub ehsize: u16,
    /// The size of one program header in bytes (`e_phentsize`).
    pub phentsize: u16,
    /// The number of program headers (`e_phnum`), or `PN_XNUM`.
    pub phnum: u16,
    /// The size of one section header in bytes (`e_shentsize`).
    pub shentsize: u16,
    /// The number of section headers (`e_shnum`), or 0 with extended numbering.
    pub shnum: u16,
    /// The section index of the section name string table (`e_shstrndx`), or `SHN_XINDEX`.
    pub shstrndx: u16,
}

impl FileHeader {
    /// Create a header with the standard sizes for `encoding` and all other fields zero.
    #[must_use]
    pub fn new(encoding: Encoding, file_type: FileType, machine: Machine) -> Self {
        Self {
            ident: Ident::new(encoding),
            file_type,
            machine,
            version: u32::from(crate::ident::EV_CURRENT),
            entry: 0,
            phoff: 0,
            shoff: 0,
            flags: 0,
            ehsize: Self::standard_size(encoding.class),
            phentsize: crate::program::ProgramHeader::standard_size(encoding.class),
            phnum: 0,
            shentsize: crate::section::SectionHeader::standard_size(encoding.class),
            shnum: 0,
            shstrndx: 0,
        }
    }

    /// Return the size of the header structure for `class`: 52 or 64 bytes.
    #[must_use]
    pub const fn size(class: Class) -> usize {
        match class {
            Class::Elf32 => ELF32_HEADER_SIZE,
            Class::Elf64 => ELF64_HEADER_SIZE,
        }
    }

    /// Return the standard `e_ehsize` value for `class`.
    #[must_use]
    pub const fn standard_size(class: Class) -> u16 {
        match class {
            Class::Elf32 => 52,
            Class::Elf64 => 64,
        }
    }

    /// Parse the header from the start of `bytes`.
    ///
    /// # Errors
    ///
    /// - Return an error from [`Ident::parse`] for bad identification bytes.
    /// - Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` ends
    ///   before the header ends.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let ident = Ident::parse(bytes)?;
        let encoding = ident.encoding();
        let size = Self::size(encoding.class);
        let body = bytes
            .get(EI_NIDENT..size)
            .ok_or_else(|| Error::buffer_too_small(size, bytes.len()))?;
        let mut reader = ByteReader::new(body, encoding);
        Ok(Self {
            ident,
            file_type: FileType(reader.u16()?),
            machine: Machine(reader.u16()?),
            version: reader.u32()?,
            entry: reader.addr()?,
            phoff: reader.addr()?,
            shoff: reader.addr()?,
            flags: reader.u32()?,
            ehsize: reader.u16()?,
            phentsize: reader.u16()?,
            phnum: reader.u16()?,
            shentsize: reader.u16()?,
            shnum: reader.u16()?,
            shstrndx: reader.u16()?,
        })
    }

    /// Return the class and the byte order of the file.
    #[must_use]
    pub const fn encoding(&self) -> Encoding {
        self.ident.encoding()
    }

    /// Append the serialized header to `out`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an ELF32
    /// header has an address or offset that does not fit in 32 bits.
    pub fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        let encoding = self.encoding();
        out.extend_from_slice(&self.ident.to_bytes());
        encoding.write_u16(out, self.file_type.0);
        encoding.write_u16(out, self.machine.0);
        encoding.write_u32(out, self.version);
        encoding.write_addr(out, self.entry)?;
        encoding.write_addr(out, self.phoff)?;
        encoding.write_addr(out, self.shoff)?;
        encoding.write_u32(out, self.flags);
        encoding.write_u16(out, self.ehsize);
        encoding.write_u16(out, self.phentsize);
        encoding.write_u16(out, self.phnum);
        encoding.write_u16(out, self.shentsize);
        encoding.write_u16(out, self.shnum);
        encoding.write_u16(out, self.shstrndx);
        Ok(())
    }

    /// Serialize the header to a new vector.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::write`].
    pub fn to_bytes(self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(Self::size(self.ident.class));
        self.write(&mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_both_classes() {
        for encoding in [Encoding::ELF32_BE, Encoding::ELF64_LE] {
            let mut header = FileHeader::new(encoding, FileType::DYN, Machine::RISCV);
            header.entry = 0x1234;
            header.phoff = 0x40;
            header.shnum = 3;
            let bytes = header.to_bytes().unwrap();
            assert_eq!(bytes.len(), FileHeader::size(encoding.class));
            assert_eq!(FileHeader::parse(&bytes).unwrap(), header);
            assert!(FileHeader::parse(&bytes[..bytes.len() - 1]).is_err());
        }
    }

    #[test]
    fn elf32_rejects_wide_addresses() {
        let mut header = FileHeader::new(Encoding::ELF32_LE, FileType::EXEC, Machine::I386);
        header.entry = 0x1_0000_0000;
        assert!(header.to_bytes().is_err());
        assert_eq!(Machine::I386.to_string(), "EM_386");
        assert_eq!(Machine(0x1234).to_string(), "0x1234");
    }
}
