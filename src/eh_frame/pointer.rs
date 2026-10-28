//! `DW_EH_PE_*` pointer encodings and LEB128 values in `.eh_frame` and `.eh_frame_hdr`.

use crate::endian::{Class, Encoding};
use crate::prelude::*;
use crate::{Error, Result};

/// `DW_EH_PE_absptr`: an unsigned class-sized value (4 bytes in ELF32, 8 bytes in ELF64).
pub const DW_EH_PE_ABSPTR: u8 = 0x00;
/// `DW_EH_PE_uleb128`: an unsigned LEB128 value.
pub const DW_EH_PE_ULEB128: u8 = 0x01;
/// `DW_EH_PE_udata2`: an unsigned 2-byte value.
pub const DW_EH_PE_UDATA2: u8 = 0x02;
/// `DW_EH_PE_udata4`: an unsigned 4-byte value.
pub const DW_EH_PE_UDATA4: u8 = 0x03;
/// `DW_EH_PE_udata8`: an unsigned 8-byte value.
pub const DW_EH_PE_UDATA8: u8 = 0x04;
/// `DW_EH_PE_signed`: a signed class-sized value.
pub const DW_EH_PE_SIGNED: u8 = 0x08;
/// `DW_EH_PE_sleb128`: a signed LEB128 value.
pub const DW_EH_PE_SLEB128: u8 = 0x09;
/// `DW_EH_PE_sdata2`: a signed 2-byte value.
pub const DW_EH_PE_SDATA2: u8 = 0x0a;
/// `DW_EH_PE_sdata4`: a signed 4-byte value.
pub const DW_EH_PE_SDATA4: u8 = 0x0b;
/// `DW_EH_PE_sdata8`: a signed 8-byte value.
pub const DW_EH_PE_SDATA8: u8 = 0x0c;
/// `DW_EH_PE_pcrel`: the value is relative to the address of the encoded field.
pub const DW_EH_PE_PCREL: u8 = 0x10;
/// `DW_EH_PE_textrel`: the value is relative to the start of the text section.
pub const DW_EH_PE_TEXTREL: u8 = 0x20;
/// `DW_EH_PE_datarel`: the value is relative to a data address (in `.eh_frame_hdr`, the
/// section start).
pub const DW_EH_PE_DATAREL: u8 = 0x30;
/// `DW_EH_PE_funcrel`: the value is relative to the start of the function.
pub const DW_EH_PE_FUNCREL: u8 = 0x40;
/// `DW_EH_PE_aligned`: the value is a class-sized address, aligned to the address size.
pub const DW_EH_PE_ALIGNED: u8 = 0x50;
/// `DW_EH_PE_indirect`: the decoded address is the address of the real pointer.
pub const DW_EH_PE_INDIRECT: u8 = 0x80;
/// `DW_EH_PE_omit`: no value is present.
pub const DW_EH_PE_OMIT: u8 = 0xff;

/// The base addresses for relative `DW_EH_PE_*` pointer encodings.
///
/// All values are virtual addresses. A relative encoding whose base is `None` is an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PointerBases {
    /// The virtual address of the encoded field (`DW_EH_PE_pcrel`). [`read_encoded_pointer`]
    /// ignores this value and uses its `field_address` argument.
    pub pc: Option<u64>,
    /// The base for `DW_EH_PE_textrel`.
    pub text: Option<u64>,
    /// The base for `DW_EH_PE_datarel`.
    pub data: Option<u64>,
    /// The base for `DW_EH_PE_funcrel`: the start address of the function.
    pub func: Option<u64>,
}

/// Return `value` wrapped to the address size of the class.
pub(crate) const fn wrap_address(encoding: Encoding, value: u64) -> u64 {
    match encoding.class {
        Class::Elf32 => value & 0xffff_ffff,
        Class::Elf64 => value,
    }
}

/// Return the virtual address of `offset` bytes after `base`, wrapped to the class.
pub(crate) fn address_at(encoding: Encoding, base: u64, offset: usize) -> u64 {
    wrap_address(
        encoding,
        base.wrapping_add(u64::try_from(offset).unwrap_or(u64::MAX)),
    )
}

/// Return the fixed size in bytes of a pointer encoding, or `None` for LEB128 values and
/// `DW_EH_PE_omit`.
#[must_use]
pub fn encoded_pointer_size(encoding: Encoding, pointer_encoding: u8) -> Option<usize> {
    if pointer_encoding == DW_EH_PE_OMIT {
        return None;
    }
    if pointer_encoding & 0x70 == DW_EH_PE_ALIGNED {
        return Some(encoding.addr_size());
    }
    match pointer_encoding & 0x0f {
        DW_EH_PE_ABSPTR | DW_EH_PE_SIGNED => Some(encoding.addr_size()),
        DW_EH_PE_UDATA2 | DW_EH_PE_SDATA2 => Some(2),
        DW_EH_PE_UDATA4 | DW_EH_PE_SDATA4 => Some(4),
        DW_EH_PE_UDATA8 | DW_EH_PE_SDATA8 => Some(8),
        _ => None,
    }
}

/// Read an unsigned LEB128 value at `*offset` and move `offset` past it.
///
/// # Errors
///
/// - Return [`crate::ErrorKind::BufferTooSmall`] if the value does not end in `bytes`.
/// - Return [`crate::ErrorKind::InvalidTable`] if the value does not fit in 64 bits.
pub fn read_uleb128(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let mut pos = *offset;
    let mut result = 0_u64;
    let mut shift = 0_u32;
    loop {
        let byte = *bytes
            .get(pos)
            .ok_or_else(|| Error::buffer_too_small(pos.saturating_add(1), bytes.len()))?;
        pos += 1;
        let low = u64::from(byte & 0x7f);
        if shift < 64 {
            if shift == 63 && low > 1 {
                return Err(leb_overflow(*offset));
            }
            result |= low << shift;
        } else if low != 0 {
            return Err(leb_overflow(*offset));
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            *offset = pos;
            return Ok(result);
        }
    }
}

/// Read a signed LEB128 value at `*offset` and move `offset` past it.
///
/// # Errors
///
/// - Return [`crate::ErrorKind::BufferTooSmall`] if the value does not end in `bytes`.
/// - Return [`crate::ErrorKind::InvalidTable`] if the value does not fit in 64 bits.
pub fn read_sleb128(bytes: &[u8], offset: &mut usize) -> Result<i64> {
    let mut pos = *offset;
    let mut result = 0_i64;
    let mut shift = 0_u32;
    loop {
        let byte = *bytes
            .get(pos)
            .ok_or_else(|| Error::buffer_too_small(pos.saturating_add(1), bytes.len()))?;
        pos += 1;
        let low = i64::from(byte & 0x7f);
        if shift < 64 {
            // At bit 63, only a full sign extension (0 or 0x7f) fits in 64 bits.
            if shift == 63 && low != 0 && low != 0x7f {
                return Err(leb_overflow(*offset));
            }
            result |= low << shift;
        } else {
            let expected = if result < 0 { 0x7f } else { 0 };
            if low != expected {
                return Err(leb_overflow(*offset));
            }
        }
        shift = shift.saturating_add(7);
        if byte & 0x80 == 0 {
            if shift < 64 && byte & 0x40 != 0 {
                result |= -1_i64 << shift;
            }
            *offset = pos;
            return Ok(result);
        }
    }
}

/// Return the error for a LEB128 value that does not fit in 64 bits.
fn leb_overflow(offset: usize) -> Error {
    Error::invalid_table("LEB128 value does not fit in 64 bits")
        .at_offset(u64::try_from(offset).unwrap_or(u64::MAX))
}

/// Append `value` as an unsigned LEB128 value to `out`.
pub fn write_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Append `value` as a signed LEB128 value to `out`.
pub fn write_sleb128(out: &mut Vec<u8>, mut value: i64) {
    loop {
        let byte = u8::try_from(value & 0x7f).unwrap_or(0);
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Read the raw value of a pointer format (the low 4 bits of a `DW_EH_PE_*` encoding).
fn read_raw(bytes: &[u8], offset: &mut usize, encoding: Encoding, format: u8) -> Result<u64> {
    let start = *offset;
    let (value, size) = match format {
        DW_EH_PE_ABSPTR => (encoding.read_addr(bytes, start)?, encoding.addr_size()),
        DW_EH_PE_SIGNED => (
            encoding.read_signed_addr(bytes, start)?.cast_unsigned(),
            encoding.addr_size(),
        ),
        DW_EH_PE_ULEB128 => return read_uleb128(bytes, offset),
        DW_EH_PE_SLEB128 => return read_sleb128(bytes, offset).map(i64::cast_unsigned),
        DW_EH_PE_UDATA2 => (u64::from(encoding.read_u16(bytes, start)?), 2),
        DW_EH_PE_UDATA4 => (u64::from(encoding.read_u32(bytes, start)?), 4),
        DW_EH_PE_UDATA8 => (encoding.read_u64(bytes, start)?, 8),
        DW_EH_PE_SDATA2 => (
            i64::from(encoding.read_u16(bytes, start)?.cast_signed()).cast_unsigned(),
            2,
        ),
        DW_EH_PE_SDATA4 => (
            i64::from(encoding.read_i32(bytes, start)?).cast_unsigned(),
            4,
        ),
        DW_EH_PE_SDATA8 => (encoding.read_i64(bytes, start)?.cast_unsigned(), 8),
        other => {
            return Err(Error::invalid_table(format!(
                "unknown DW_EH_PE pointer format {other:#x}"
            )));
        }
    };
    *offset = start + size;
    Ok(value)
}

/// Read a `DW_EH_PE_*` encoded pointer at `*offset` and move `offset` past it.
///
/// `field_address` is the virtual address of `bytes[*offset]`. `DW_EH_PE_pcrel` values are
/// relative to it. `DW_EH_PE_textrel`, `DW_EH_PE_datarel` and `DW_EH_PE_funcrel` values are
/// relative to the matching base in `bases`. `DW_EH_PE_aligned` first moves `offset` until the
/// field address is a multiple of the address size, then reads a class-sized address.
/// The arithmetic wraps to the address size of the class (32 bits for ELF32).
///
/// For `DW_EH_PE_indirect`, the function returns the address of the real pointer. elfex does
/// not dereference it.
///
/// # Errors
///
/// - Return [`crate::ErrorKind::BufferTooSmall`] if the value does not fit in `bytes`.
/// - Return [`crate::ErrorKind::InvalidTable`] for an unknown encoding, a relative encoding
///   whose base is not in `bases`, or a LEB128 value that does not fit in 64 bits.
pub fn read_encoded_pointer(
    bytes: &[u8],
    offset: &mut usize,
    encoding: Encoding,
    pointer_encoding: u8,
    field_address: u64,
    bases: &PointerBases,
) -> Result<Option<u64>> {
    if pointer_encoding == DW_EH_PE_OMIT {
        return Ok(None);
    }
    let application = pointer_encoding & 0x70;
    if application == DW_EH_PE_ALIGNED {
        let size = encoding.addr_size();
        let misalign =
            usize::try_from(field_address % u64::try_from(size).unwrap_or(8)).unwrap_or(0);
        let pad = (size - misalign) % size;
        let mut pos = offset
            .checked_add(pad)
            .ok_or_else(|| Error::buffer_too_small(usize::MAX, bytes.len()))?;
        let value = read_raw(bytes, &mut pos, encoding, DW_EH_PE_ABSPTR)?;
        *offset = pos;
        return Ok(Some(value));
    }
    let start = *offset;
    let mut pos = start;
    let raw = read_raw(bytes, &mut pos, encoding, pointer_encoding & 0x0f)?;
    let base = match application {
        0 => Some(0),
        DW_EH_PE_PCREL => Some(field_address),
        DW_EH_PE_TEXTREL => bases.text,
        DW_EH_PE_DATAREL => bases.data,
        DW_EH_PE_FUNCREL => bases.func,
        other => {
            return Err(Error::invalid_table(format!(
                "unknown DW_EH_PE pointer application {other:#x}"
            ))
            .at_address(field_address));
        }
    };
    let base = base.ok_or_else(|| {
        Error::invalid_table(format!(
            "no base address for DW_EH_PE encoding {pointer_encoding:#x}"
        ))
        .at_address(field_address)
    })?;
    *offset = pos;
    Ok(Some(wrap_address(encoding, base.wrapping_add(raw))))
}
