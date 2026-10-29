//! The loader action and the field width of a relocation type: [`RelocationKind`],
//! [`relocation_kind`] and [`relocation_width`].
//!
//! The functions know the x86-64 and the i386 relocation types. For other machines, they
//! return [`RelocationKind::Other`] and `None`.

use super::{i386, x86_64};
use crate::endian::Class;
use crate::header::Machine;

/// The common action of a relocation type.
///
/// The names follow the System V psABI. `S` is the symbol value, `A` is the addend and `B`
/// is the load bias of the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RelocationKind {
    /// `R_*_NONE`: the entry changes nothing.
    None,
    /// `B + A`: the load bias plus the addend, for example `R_X86_64_RELATIVE`.
    Relative,
    /// `S`: the address of a symbol in a data word of the global offset table, for example
    /// `R_X86_64_GLOB_DAT`.
    GlobalData,
    /// `S`: the address of a function in a slot of the procedure linkage table, for example
    /// `R_X86_64_JUMP_SLOT`.
    JumpSlot,
    /// `S + A`: the absolute address of a symbol, for example `R_X86_64_64`.
    Absolute,
    /// A copy of the initial bytes of a symbol. The symbol size (`st_size`) gives the number
    /// of bytes, for example `R_X86_64_COPY`.
    Copy,
    /// A thread-local storage (TLS) value that the loader computes: a module ID, an offset
    /// or a descriptor, for example `R_X86_64_DTPMOD64` or `R_X86_64_TLSDESC`.
    Tls,
    /// The result of the resolver function at `B + A`, for example `R_X86_64_IRELATIVE`.
    ///
    /// The value is not known before the resolver runs. Do not adjust the stored word as a
    /// relative relocation.
    IndirectRelative,
    /// Another action, or a type that this crate does not classify.
    Other,
}

/// Return the action of relocation type `r_type` for `machine`.
///
/// The function classifies the x86-64 and the i386 types. It returns
/// [`RelocationKind::Other`] for the types of other machines.
///
/// # Examples
///
/// ```
/// use elfex::Machine;
/// use elfex::reloc::x86_64::{R_X86_64_IRELATIVE, R_X86_64_RELATIVE};
/// use elfex::reloc::{RelocationKind, relocation_kind};
///
/// assert_eq!(relocation_kind(Machine::X86_64, R_X86_64_RELATIVE), RelocationKind::Relative);
/// assert_eq!(
///     relocation_kind(Machine::X86_64, R_X86_64_IRELATIVE),
///     RelocationKind::IndirectRelative,
/// );
/// ```
#[must_use]
pub const fn relocation_kind(machine: Machine, r_type: u32) -> RelocationKind {
    match machine {
        Machine::X86_64 => x86_64_kind(r_type),
        Machine::I386 => i386_kind(r_type),
        _ => RelocationKind::Other,
    }
}

/// Return the number of bytes that relocation type `r_type` of `machine` changes at
/// `r_offset`, or `None` if the type has no fixed width.
///
/// The width is the size of the relocation field in the psABI (`word8`, `word16`, `word32`,
/// `word64` or `wordclass`). `class` gives the size of `wordclass`: it is 4 for x32, the
/// ELF32 form of x86-64. A TLS descriptor is two words. `R_*_NONE` changes 0 bytes.
///
/// Return `None` for these types:
///
/// - `R_*_COPY`: the symbol size gives the number of bytes.
/// - A type that marks an instruction sequence, for example `R_X86_64_TLSDESC_CALL`.
/// - An unknown type, or a type of a machine other than x86-64 and i386.
///
/// # Examples
///
/// ```
/// use elfex::reloc::relocation_width;
/// use elfex::reloc::x86_64::{R_X86_64_COPY, R_X86_64_PC32, R_X86_64_RELATIVE};
/// use elfex::{Class, Machine};
///
/// assert_eq!(relocation_width(Machine::X86_64, Class::Elf64, R_X86_64_RELATIVE), Some(8));
/// assert_eq!(relocation_width(Machine::X86_64, Class::Elf32, R_X86_64_RELATIVE), Some(4));
/// assert_eq!(relocation_width(Machine::X86_64, Class::Elf64, R_X86_64_PC32), Some(4));
/// assert_eq!(relocation_width(Machine::X86_64, Class::Elf64, R_X86_64_COPY), None);
/// ```
#[must_use]
pub const fn relocation_width(machine: Machine, class: Class, r_type: u32) -> Option<u8> {
    match machine {
        Machine::X86_64 => x86_64_width(class, r_type),
        Machine::I386 => i386_width(r_type),
        _ => None,
    }
}

/// Classify an x86-64 relocation type.
const fn x86_64_kind(r_type: u32) -> RelocationKind {
    match r_type {
        x86_64::R_X86_64_NONE => RelocationKind::None,
        x86_64::R_X86_64_RELATIVE | x86_64::R_X86_64_RELATIVE64 => RelocationKind::Relative,
        x86_64::R_X86_64_GLOB_DAT => RelocationKind::GlobalData,
        x86_64::R_X86_64_JUMP_SLOT => RelocationKind::JumpSlot,
        x86_64::R_X86_64_64 => RelocationKind::Absolute,
        x86_64::R_X86_64_COPY => RelocationKind::Copy,
        x86_64::R_X86_64_DTPMOD64
        | x86_64::R_X86_64_DTPOFF64
        | x86_64::R_X86_64_TPOFF64
        | x86_64::R_X86_64_TLSDESC => RelocationKind::Tls,
        x86_64::R_X86_64_IRELATIVE => RelocationKind::IndirectRelative,
        _ => RelocationKind::Other,
    }
}

/// Classify an i386 relocation type.
const fn i386_kind(r_type: u32) -> RelocationKind {
    match r_type {
        i386::R_386_NONE => RelocationKind::None,
        i386::R_386_RELATIVE => RelocationKind::Relative,
        i386::R_386_GLOB_DAT => RelocationKind::GlobalData,
        i386::R_386_JMP_SLOT => RelocationKind::JumpSlot,
        i386::R_386_32 => RelocationKind::Absolute,
        i386::R_386_COPY => RelocationKind::Copy,
        i386::R_386_TLS_TPOFF
        | i386::R_386_TLS_DTPMOD32
        | i386::R_386_TLS_DTPOFF32
        | i386::R_386_TLS_TPOFF32
        | i386::R_386_TLS_DESC => RelocationKind::Tls,
        i386::R_386_IRELATIVE => RelocationKind::IndirectRelative,
        _ => RelocationKind::Other,
    }
}

/// Return the field width of an x86-64 relocation type (System V AMD64 psABI, table
/// "Relocation Types").
const fn x86_64_width(class: Class, r_type: u32) -> Option<u8> {
    let wordclass = match class {
        Class::Elf32 => 4,
        Class::Elf64 => 8,
    };
    match r_type {
        x86_64::R_X86_64_NONE => Some(0),
        x86_64::R_X86_64_8 | x86_64::R_X86_64_PC8 => Some(1),
        x86_64::R_X86_64_16 | x86_64::R_X86_64_PC16 => Some(2),
        x86_64::R_X86_64_PC32
        | x86_64::R_X86_64_GOT32
        | x86_64::R_X86_64_PLT32
        | x86_64::R_X86_64_GOTPCREL
        | x86_64::R_X86_64_32
        | x86_64::R_X86_64_32S
        | x86_64::R_X86_64_TLSGD
        | x86_64::R_X86_64_TLSLD
        | x86_64::R_X86_64_DTPOFF32
        | x86_64::R_X86_64_GOTTPOFF
        | x86_64::R_X86_64_TPOFF32
        | x86_64::R_X86_64_GOTPC32
        | x86_64::R_X86_64_SIZE32
        | x86_64::R_X86_64_GOTPC32_TLSDESC
        | x86_64::R_X86_64_PC32_BND
        | x86_64::R_X86_64_PLT32_BND
        | x86_64::R_X86_64_GOTPCRELX
        | x86_64::R_X86_64_REX_GOTPCRELX
        | x86_64::R_X86_64_CODE_4_GOTPCRELX
        | x86_64::R_X86_64_CODE_4_GOTTPOFF
        | x86_64::R_X86_64_CODE_4_GOTPC32_TLSDESC => Some(4),
        x86_64::R_X86_64_64
        | x86_64::R_X86_64_DTPMOD64
        | x86_64::R_X86_64_DTPOFF64
        | x86_64::R_X86_64_TPOFF64
        | x86_64::R_X86_64_PC64
        | x86_64::R_X86_64_GOTOFF64
        | x86_64::R_X86_64_GOT64
        | x86_64::R_X86_64_GOTPCREL64
        | x86_64::R_X86_64_GOTPC64
        | x86_64::R_X86_64_GOTPLT64
        | x86_64::R_X86_64_PLTOFF64
        | x86_64::R_X86_64_SIZE64
        | x86_64::R_X86_64_RELATIVE64 => Some(8),
        x86_64::R_X86_64_GLOB_DAT
        | x86_64::R_X86_64_JUMP_SLOT
        | x86_64::R_X86_64_RELATIVE
        | x86_64::R_X86_64_IRELATIVE => Some(wordclass),
        // A TLS descriptor is two words: the resolver function and its argument.
        x86_64::R_X86_64_TLSDESC => Some(2 * wordclass),
        _ => None,
    }
}

/// Return the field width of an i386 relocation type (System V i386 psABI, table
/// "Relocation Types", and the TLS extensions).
const fn i386_width(r_type: u32) -> Option<u8> {
    match r_type {
        i386::R_386_NONE => Some(0),
        i386::R_386_8 | i386::R_386_PC8 => Some(1),
        i386::R_386_16 | i386::R_386_PC16 => Some(2),
        i386::R_386_32
        | i386::R_386_PC32
        | i386::R_386_GOT32
        | i386::R_386_PLT32
        | i386::R_386_GLOB_DAT
        | i386::R_386_JMP_SLOT
        | i386::R_386_RELATIVE
        | i386::R_386_GOTOFF
        | i386::R_386_GOTPC
        | i386::R_386_32PLT
        | i386::R_386_TLS_TPOFF
        | i386::R_386_TLS_IE
        | i386::R_386_TLS_GOTIE
        | i386::R_386_TLS_LE
        | i386::R_386_TLS_GD
        | i386::R_386_TLS_LDM
        | i386::R_386_TLS_GD_32
        | i386::R_386_TLS_LDM_32
        | i386::R_386_TLS_LDO_32
        | i386::R_386_TLS_IE_32
        | i386::R_386_TLS_LE_32
        | i386::R_386_TLS_DTPMOD32
        | i386::R_386_TLS_DTPOFF32
        | i386::R_386_TLS_TPOFF32
        | i386::R_386_SIZE32
        | i386::R_386_TLS_GOTDESC
        | i386::R_386_IRELATIVE
        | i386::R_386_GOT32X => Some(4),
        // A TLS descriptor is two words: the resolver function and its argument.
        i386::R_386_TLS_DESC => Some(8),
        _ => None,
    }
}
