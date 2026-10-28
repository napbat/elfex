//! Relocation entries and tables: `Elf32_Rel`, `Elf32_Rela`, `Elf64_Rel`, `Elf64_Rela` and
//! the relative relocation format `Elf32_Relr` / `Elf64_Relr`.
//!
//! [`Relocation`] is one entry. [`RelocationTable`] is the contents of an `SHT_REL` or
//! `SHT_RELA` section, or of the range that `DT_REL`, `DT_RELA` or `DT_JMPREL` names.
//! [`RelrTable`] is the contents of an `SHT_RELR` section or of the `DT_RELR` range.
//!
//! The relocation type values are processor-specific. The submodules ([`x86_64`], [`i386`],
//! [`aarch64`], [`arm`], [`riscv`], [`ppc`], [`ppc64`], [`s390`], [`mips`], [`loongarch`])
//! hold the `R_*` constants. Use [`relocation_type_name`] to get the spec name of a type.
//!
//! # Examples
//!
//! ```
//! use elfex::reloc::x86_64::{R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE};
//! use elfex::reloc::{Relocation, RelocationTable, RelrTable};
//! use elfex::{Encoding, Machine};
//!
//! let encoding = Encoding::ELF64_LE;
//! let mut table = RelocationTable::new(true);
//! table.relocations.push(Relocation::with_addend(0x4000, 0, R_X86_64_RELATIVE, 0x1234));
//! table.relocations.push(Relocation::with_addend(0x4008, 1, R_X86_64_JUMP_SLOT, 0));
//! let bytes = table.write(encoding, Machine::X86_64)?;
//! assert_eq!(bytes.len(), 2 * 24);
//!
//! let parsed = RelocationTable::parse_rela(&bytes, encoding, Machine::X86_64)?;
//! assert_eq!(parsed, table);
//! assert!(parsed.relocations[0].is_relative(Machine::X86_64));
//! let name = parsed.relocations[1].type_name(Machine::X86_64);
//! assert_eq!(name, Some("R_X86_64_JUMP_SLOT"));
//!
//! // A RELR table packs the addresses of relative relocations.
//! let relr = RelrTable::from_addresses(vec![0x4010, 0x4000, 0x4008], encoding)?;
//! let packed = RelrTable::parse(&relr.write(encoding)?, encoding)?;
//! assert_eq!(packed.addresses, [0x4000, 0x4008, 0x4010]);
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::endian::{ByteReader, Class, Encoding, Endian};
use crate::header::Machine;
use crate::prelude::*;
use crate::{Error, Result};

/// Declare relocation type constants and a `name` function for one processor.
///
/// Each value must occur only once, so that `name` is unambiguous.
macro_rules! reloc_types {
    ($($name:ident = $value:expr;)*) => {
        $(
            #[doc = concat!("The relocation type `", stringify!($name), "`.")]
            pub const $name: u32 = $value;
        )*

        /// Return the spec name of a relocation type, or `None` for an unknown type.
        #[must_use]
        pub const fn name(r_type: u32) -> Option<&'static str> {
            match r_type {
                $($name => Some(stringify!($name)),)*
                _ => None,
            }
        }
    };
}

pub mod aarch64;
pub mod arm;
pub mod i386;
pub mod loongarch;
pub mod mips;
pub mod ppc;
pub mod ppc64;
mod relr;
pub mod riscv;
pub mod s390;
pub mod x86_64;

#[cfg(test)]
mod tests;

pub use relr::RelrTable;

/// A relocation entry: `Elf32_Rel`, `Elf32_Rela`, `Elf64_Rel` or `Elf64_Rela`.
///
/// The `r_info` field is split into [`symbol`](Self::symbol) and [`r_type`](Self::r_type).
/// In ELF32, `r_info` is `(symbol << 8) | r_type`. In ELF64, `r_info` is
/// `(symbol << 32) | r_type`.
///
/// ELF64 MIPS stores `r_info` as `u32 r_sym, u8 r_ssym, u8 r_type3, u8 r_type2, u8 r_type`
/// in file order. For this layout, [`r_type`](Self::r_type) holds
/// `r_type | r_type2 << 8 | r_type3 << 16 | r_ssym << 24`. This packing is the same for both
/// byte orders, and the write methods restore the original bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Relocation {
    /// `r_offset`: the location to change. This is a virtual address in `ET_EXEC` and `ET_DYN`
    /// files, and an offset in the target section in `ET_REL` files.
    pub offset: u64,
    /// The symbol table index part of `r_info` (`ELF32_R_SYM` / `ELF64_R_SYM`).
    pub symbol: u32,
    /// The type part of `r_info` (`ELF32_R_TYPE` / `ELF64_R_TYPE`). See the type docs for the
    /// ELF64 MIPS packing.
    pub r_type: u32,
    /// `r_addend`: the explicit addend of a `Rela` entry, or `None` for a `Rel` entry.
    pub addend: Option<i64>,
}

impl Relocation {
    /// Create a `Rel` entry (no addend).
    #[must_use]
    pub const fn new(offset: u64, symbol: u32, r_type: u32) -> Self {
        Self {
            offset,
            symbol,
            r_type,
            addend: None,
        }
    }

    /// Create a `Rela` entry (with an addend).
    #[must_use]
    pub const fn with_addend(offset: u64, symbol: u32, r_type: u32, addend: i64) -> Self {
        Self {
            offset,
            symbol,
            r_type,
            addend: Some(addend),
        }
    }

    /// Return the size in bytes of one entry: 8 (`Elf32_Rel`), 12 (`Elf32_Rela`),
    /// 16 (`Elf64_Rel`) or 24 (`Elf64_Rela`).
    #[must_use]
    pub const fn size(class: Class, with_addend: bool) -> usize {
        let words = if with_addend { 3 } else { 2 };
        class.addr_size() * words
    }

    /// Parse one entry from the start of `bytes`.
    ///
    /// `machine` selects the ELF64 MIPS `r_info` layout. If `with_addend` is `true`, the entry
    /// is a `Rela` entry.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` is
    /// shorter than one entry.
    pub fn parse(
        bytes: &[u8],
        encoding: Encoding,
        machine: Machine,
        with_addend: bool,
    ) -> Result<Self> {
        let mut reader = ByteReader::new(bytes, encoding);
        let offset = reader.addr()?;
        let (symbol, r_type) = match encoding.class {
            Class::Elf32 => {
                let info = reader.u32()?;
                (info >> 8, info & 0xff)
            }
            Class::Elf64 => decode_info64(reader.u64()?, encoding, machine),
        };
        let addend = if with_addend {
            Some(reader.signed_addr()?)
        } else {
            None
        };
        Ok(Self {
            offset,
            symbol,
            r_type,
            addend,
        })
    }

    /// Append the entry to `out`. Write `r_addend` if and only if
    /// [`addend`](Self::addend) is `Some`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) for ELF32 if
    /// the offset or the addend does not fit in 32 bits, the symbol index is larger than
    /// `0xffffff`, or the type is larger than `0xff`. Nothing is appended on error.
    pub fn write(&self, out: &mut Vec<u8>, encoding: Encoding, machine: Machine) -> Result<()> {
        let mut entry = Vec::with_capacity(Self::size(encoding.class, self.addend.is_some()));
        encoding
            .write_addr(&mut entry, self.offset)
            .map_err(|e| e.in_structure(self.structure_name(encoding.class)))?;
        match encoding.class {
            Class::Elf32 => {
                if self.symbol > 0x00ff_ffff {
                    return Err(Error::value_out_of_range(format!(
                        "symbol index {} does not fit in ELF32 r_info",
                        self.symbol
                    ))
                    .in_structure(self.structure_name(encoding.class)));
                }
                if self.r_type > 0xff {
                    return Err(Error::value_out_of_range(format!(
                        "relocation type {:#x} does not fit in ELF32 r_info",
                        self.r_type
                    ))
                    .in_structure(self.structure_name(encoding.class)));
                }
                encoding.write_u32(&mut entry, (self.symbol << 8) | self.r_type);
            }
            Class::Elf64 => {
                encoding.write_u64(
                    &mut entry,
                    encode_info64(self.symbol, self.r_type, encoding, machine),
                );
            }
        }
        if let Some(addend) = self.addend {
            encoding
                .write_signed_addr(&mut entry, addend)
                .map_err(|e| e.in_structure(self.structure_name(encoding.class)))?;
        }
        out.extend_from_slice(&entry);
        Ok(())
    }

    /// Return `true` if the type is the relative relocation type of `machine`
    /// (see [`relative_type`]).
    #[must_use]
    pub fn is_relative(&self, machine: Machine) -> bool {
        relative_type(machine) == Some(self.r_type)
    }

    /// Return `true` if the type is the indirect relative relocation type of `machine`
    /// (see [`irelative_type`]).
    #[must_use]
    pub fn is_irelative(&self, machine: Machine) -> bool {
        irelative_type(machine) == Some(self.r_type)
    }

    /// Return the spec name of the relocation type for `machine`, for example
    /// `"R_X86_64_RELATIVE"` (see [`relocation_type_name`]).
    ///
    /// For MIPS, the name is the name of the first type: the low byte of
    /// [`r_type`](Self::r_type). An ELF64 MIPS entry packs up to three types in this field.
    /// Return `None` for an unknown machine or type.
    #[must_use]
    pub const fn type_name(&self, machine: Machine) -> Option<&'static str> {
        let r_type = if machine.0 == Machine::MIPS.0 {
            self.r_type & 0xff
        } else {
            self.r_type
        };
        relocation_type_name(machine, r_type)
    }

    /// Return the spec name of the entry structure.
    const fn structure_name(&self, class: Class) -> &'static str {
        match (class, self.addend.is_some()) {
            (Class::Elf32, false) => "Elf32_Rel",
            (Class::Elf32, true) => "Elf32_Rela",
            (Class::Elf64, false) => "Elf64_Rel",
            (Class::Elf64, true) => "Elf64_Rela",
        }
    }
}

/// Return `true` if ELF64 `r_info` uses the MIPS64 little-endian field layout.
fn is_mips64_le(encoding: Encoding, machine: Machine) -> bool {
    machine == Machine::MIPS && encoding.endian == Endian::Little
}

/// Split an ELF64 `r_info` value into the symbol index and the type.
fn decode_info64(info: u64, encoding: Encoding, machine: Machine) -> (u32, u32) {
    if is_mips64_le(encoding, machine) {
        // File order: u32 r_sym (little-endian), r_ssym, r_type3, r_type2, r_type.
        let b = info.to_le_bytes();
        let symbol = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let r_type = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        (symbol, r_type)
    } else {
        let b = info.to_be_bytes();
        let symbol = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        let r_type = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
        (symbol, r_type)
    }
}

/// Join the symbol index and the type into an ELF64 `r_info` value.
fn encode_info64(symbol: u32, r_type: u32, encoding: Encoding, machine: Machine) -> u64 {
    if is_mips64_le(encoding, machine) {
        let s = symbol.to_le_bytes();
        let t = r_type.to_be_bytes();
        u64::from_le_bytes([s[0], s[1], s[2], s[3], t[0], t[1], t[2], t[3]])
    } else {
        (u64::from(symbol) << 32) | u64::from(r_type)
    }
}

/// A relocation table: the entries of an `SHT_REL` or `SHT_RELA` section, or of the range that
/// `DT_REL`, `DT_RELA` or `DT_JMPREL` names.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocationTable {
    /// The entries in table order.
    pub relocations: Vec<Relocation>,
    /// `true` for a `Rela` table (`SHT_RELA`, `DT_RELA`), `false` for a `Rel` table.
    pub with_addend: bool,
}

impl RelocationTable {
    /// Create an empty table.
    #[must_use]
    pub const fn new(with_addend: bool) -> Self {
        Self {
            relocations: Vec::new(),
            with_addend,
        }
    }

    /// Parse a table of `Elf32_Rel` or `Elf64_Rel` entries.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is not a multiple of the entry size.
    pub fn parse_rel(bytes: &[u8], encoding: Encoding, machine: Machine) -> Result<Self> {
        Self::parse_with_entsize(
            bytes,
            encoding,
            machine,
            false,
            Relocation::size(encoding.class, false),
        )
    }

    /// Parse a table of `Elf32_Rela` or `Elf64_Rela` entries.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is not a multiple of the entry size.
    pub fn parse_rela(bytes: &[u8], encoding: Encoding, machine: Machine) -> Result<Self> {
        Self::parse_with_entsize(
            bytes,
            encoding,
            machine,
            true,
            Relocation::size(encoding.class, true),
        )
    }

    /// Parse a table with an explicit entry size (`sh_entsize`, `DT_RELENT` or `DT_RELAENT`).
    ///
    /// The entry size can be larger than the structure size. The parser then ignores the
    /// bytes after the structure in each entry.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `entsize` is
    /// smaller than the structure size, or if the length of `bytes` is not a multiple of
    /// `entsize`.
    pub fn parse_with_entsize(
        bytes: &[u8],
        encoding: Encoding,
        machine: Machine,
        with_addend: bool,
        entsize: usize,
    ) -> Result<Self> {
        let structure = if with_addend { "Elf_Rela" } else { "Elf_Rel" };
        let min = Relocation::size(encoding.class, with_addend);
        if entsize < min {
            return Err(Error::invalid_table(format!(
                "relocation entry size {entsize} is smaller than {min}"
            ))
            .in_structure(structure));
        }
        if !bytes.len().is_multiple_of(entsize) {
            return Err(Error::invalid_table(format!(
                "relocation table size {} is not a multiple of the entry size {entsize}",
                bytes.len()
            ))
            .in_structure(structure));
        }
        let relocations = bytes
            .chunks_exact(entsize)
            .enumerate()
            .map(|(index, chunk)| {
                Relocation::parse(chunk, encoding, machine, with_addend).map_err(|e| {
                    e.in_structure(structure)
                        .at_offset(u64::try_from(index.saturating_mul(entsize)).unwrap_or(u64::MAX))
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            relocations,
            with_addend,
        })
    }

    /// Serialize the table.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if an entry of a
    ///   `Rel` table has an addend, or an entry of a `Rela` table has no addend.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an entry
    ///   does not fit in an ELF32 entry (see [`Relocation::write`]).
    pub fn write(&self, encoding: Encoding, machine: Machine) -> Result<Vec<u8>> {
        let entry_size = Relocation::size(encoding.class, self.with_addend);
        let mut out = Vec::with_capacity(self.relocations.len().saturating_mul(entry_size));
        for (index, relocation) in self.relocations.iter().enumerate() {
            if relocation.addend.is_some() != self.with_addend {
                let msg = if self.with_addend {
                    format!("relocation {index} has no addend in a RELA table")
                } else {
                    format!("relocation {index} has an addend in a REL table")
                };
                return Err(Error::invalid_table(msg));
            }
            relocation.write(&mut out, encoding, machine)?;
        }
        Ok(out)
    }

    /// Return the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.relocations.len()
    }

    /// Return `true` if the table has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.relocations.is_empty()
    }

    /// Return an iterator over the entries.
    pub fn iter(&self) -> core::slice::Iter<'_, Relocation> {
        self.relocations.iter()
    }
}

impl<'a> IntoIterator for &'a RelocationTable {
    type Item = &'a Relocation;
    type IntoIter = core::slice::Iter<'a, Relocation>;

    fn into_iter(self) -> Self::IntoIter {
        self.relocations.iter()
    }
}

/// Return the spec name of relocation type `r_type` for `machine`, for example
/// `"R_X86_64_RELATIVE"`.
///
/// The lists are complete for x86-64, i386, `AArch64`, Arm and RISC-V, and hold the common
/// types for PowerPC, PowerPC64, S/390, MIPS and `LoongArch`. For ELF64 MIPS, give one type
/// byte (`r_type & 0xff` of a [`Relocation`]). Return `None` for an unknown machine or type.
#[must_use]
pub const fn relocation_type_name(machine: Machine, r_type: u32) -> Option<&'static str> {
    match machine {
        Machine::X86_64 => x86_64::name(r_type),
        Machine::I386 => i386::name(r_type),
        Machine::AARCH64 => aarch64::name(r_type),
        Machine::ARM => arm::name(r_type),
        Machine::RISCV => riscv::name(r_type),
        Machine::PPC => ppc::name(r_type),
        Machine::PPC64 => ppc64::name(r_type),
        Machine::S390 => s390::name(r_type),
        Machine::MIPS => mips::name(r_type),
        Machine::LOONGARCH => loongarch::name(r_type),
        _ => None,
    }
}

/// Return the relative relocation type of `machine` (`B + A`, no symbol), for example
/// `R_X86_64_RELATIVE`.
///
/// Return `None` for MIPS: MIPS has no pure relative type. `R_MIPS_REL32` with symbol 0 acts
/// as a relative relocation, but its meaning depends on the GOT layout. Also return `None` for
/// a machine that this crate does not know.
#[must_use]
pub const fn relative_type(machine: Machine) -> Option<u32> {
    match machine {
        Machine::X86_64 => Some(x86_64::R_X86_64_RELATIVE),
        Machine::I386 => Some(i386::R_386_RELATIVE),
        Machine::AARCH64 => Some(aarch64::R_AARCH64_RELATIVE),
        Machine::ARM => Some(arm::R_ARM_RELATIVE),
        Machine::RISCV => Some(riscv::R_RISCV_RELATIVE),
        Machine::PPC => Some(ppc::R_PPC_RELATIVE),
        Machine::PPC64 => Some(ppc64::R_PPC64_RELATIVE),
        Machine::S390 => Some(s390::R_390_RELATIVE),
        Machine::LOONGARCH => Some(loongarch::R_LARCH_RELATIVE),
        _ => None,
    }
}

/// Return the indirect relative relocation type of `machine` (the resolver result of `B + A`),
/// for example `R_X86_64_IRELATIVE`.
///
/// Return `None` for MIPS and for a machine that this crate does not know.
#[must_use]
pub const fn irelative_type(machine: Machine) -> Option<u32> {
    match machine {
        Machine::X86_64 => Some(x86_64::R_X86_64_IRELATIVE),
        Machine::I386 => Some(i386::R_386_IRELATIVE),
        Machine::AARCH64 => Some(aarch64::R_AARCH64_IRELATIVE),
        Machine::ARM => Some(arm::R_ARM_IRELATIVE),
        Machine::RISCV => Some(riscv::R_RISCV_IRELATIVE),
        Machine::PPC => Some(ppc::R_PPC_IRELATIVE),
        Machine::PPC64 => Some(ppc64::R_PPC64_IRELATIVE),
        Machine::S390 => Some(s390::R_390_IRELATIVE),
        Machine::LOONGARCH => Some(loongarch::R_LARCH_IRELATIVE),
        _ => None,
    }
}
