//! The compact relocation format CREL (`SHT_CREL`, `DT_CREL`).
//!
//! The format is the one of LLVM (`decodeCrel` and `encodeCrel` in `llvm/Object/ELF.h`):
//!
//! 1. A ULEB128 header: `count << 3 | addend_flag << 2 | shift`. `CREL_HDR_ADDEND` is the
//!    addend flag. Each offset is the decoded offset shifted left by `shift`.
//! 2. One entry for each relocation. The first byte holds two flag bits (three with the addend
//!    flag) and the low bits of the offset delta. Bit 7 of the first byte means that a ULEB128
//!    value with the high bits of the offset delta follows.
//! 3. Then the SLEB128 deltas of the symbol index (flag bit 0), of the type (flag bit 1) and of
//!    the addend (flag bit 2), if the flag bit is set.

use super::{Relocation, RelocationTable, low32, wrap_addend, wrap_address};
use crate::eh_frame::{read_sleb128, read_uleb128, write_sleb128, write_uleb128};
use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};

/// `CREL_HDR_ADDEND`: the header flag of a CREL table with explicit addends.
pub const CREL_HDR_ADDEND: u64 = 4;

/// The structure name for the error context.
const STRUCTURE: &str = "SHT_CREL";

/// Add the error context of a CREL value at `pos` to `error`.
fn at(error: Error, pos: usize) -> Error {
    error
        .in_structure(STRUCTURE)
        .at_offset(u64::try_from(pos).unwrap_or(u64::MAX))
}

/// Read a ULEB128 value of a CREL table.
fn unsigned(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    let start = *pos;
    read_uleb128(bytes, pos).map_err(|error| at(error, start))
}

/// Read a SLEB128 value of a CREL table as the bits of a 64-bit word.
fn signed(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    let start = *pos;
    read_sleb128(bytes, pos)
        .map(i64::cast_unsigned)
        .map_err(|error| at(error, start))
}

impl RelocationTable {
    /// Decode a CREL table.
    ///
    /// The header selects [`with_addend`](Self::with_addend). The symbol indices and the types
    /// are 32-bit deltas. The offsets and the addends are deltas that wrap at the class size,
    /// as in LLVM. The decoder ignores the bytes after the last entry.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the header
    ///   count is larger than the number of bytes after the header (each entry has at least one
    ///   byte), or if a value does not fit in 64 bits.
    /// - Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if the table
    ///   ends in an entry.
    pub fn parse_crel(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        let mut pos = 0;
        let header = unsigned(bytes, &mut pos)?;
        let with_addend = header & CREL_HDR_ADDEND != 0;
        let flag_bits: u32 = if with_addend { 3 } else { 2 };
        let shift = low32(header & 3);
        let count = header >> 3;
        let available = bytes.len().saturating_sub(pos);
        let count = usize::try_from(count)
            .ok()
            .filter(|count| *count <= available)
            .ok_or_else(|| {
                at(
                    Error::invalid_table(format!(
                        "the relocation count {count} is larger than the {available} bytes after the header"
                    )),
                    0,
                )
            })?;
        let mut relocations = Vec::with_capacity(count);
        let (mut offset, mut addend) = (0_u64, 0_u64);
        let (mut symbol, mut r_type) = (0_u32, 0_u32);
        for _ in 0..count {
            let byte = *bytes.get(pos).ok_or_else(|| {
                at(
                    Error::buffer_too_small(pos.saturating_add(1), bytes.len()),
                    pos,
                )
            })?;
            pos += 1;
            offset = offset.wrapping_add(u64::from(byte >> flag_bits));
            if byte & 0x80 != 0 {
                let high = unsigned(bytes, &mut pos)?;
                offset = offset
                    .wrapping_add(high << (7 - flag_bits))
                    .wrapping_sub(0x80 >> flag_bits);
            }
            if byte & 1 != 0 {
                symbol = symbol.wrapping_add(low32(signed(bytes, &mut pos)?));
            }
            if byte & 2 != 0 {
                r_type = r_type.wrapping_add(low32(signed(bytes, &mut pos)?));
            }
            if with_addend && byte & 4 != 0 {
                addend = addend.wrapping_add(signed(bytes, &mut pos)?);
            }
            relocations.push(Relocation {
                offset: wrap_address(offset << shift, encoding),
                symbol,
                r_type,
                addend: with_addend.then(|| wrap_addend(addend.cast_signed(), encoding)),
            });
        }
        Ok(Self {
            relocations,
            with_addend,
        })
    }

    /// Encode the table in the CREL format.
    ///
    /// The header has the addend flag if [`with_addend`](Self::with_addend) is `true`. The
    /// shift is the number of low zero bits that all offsets share, at most 3, as in LLVM.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if an entry of a
    ///   table without addends has an addend, or an entry of a table with addends has none.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) for ELF32 if
    ///   an offset or an addend does not fit in 32 bits.
    pub fn write_crel(&self, encoding: Encoding) -> Result<Vec<u8>> {
        let mut mask = 8_u64;
        for (index, relocation) in self.relocations.iter().enumerate() {
            self.check_addend(index, relocation)?;
            relocation.check_class(encoding)?;
            mask |= relocation.offset;
        }
        let shift = mask.trailing_zeros();
        let flag_bits: u32 = if self.with_addend { 3 } else { 2 };
        // A `Vec` holds at most `isize::MAX` bytes, and an entry has 32 bytes, so the count
        // shifted left by 3 fits in 64 bits.
        let count = u64::try_from(self.relocations.len()).unwrap_or(u64::MAX);
        let header =
            (count << 3) | if self.with_addend { CREL_HDR_ADDEND } else { 0 } | u64::from(shift);
        let mut out = Vec::with_capacity(self.relocations.len().saturating_add(10));
        write_uleb128(&mut out, header);
        let mut previous = Relocation::default();
        let limit = 1_u64 << (7 - flag_bits);
        for relocation in &self.relocations {
            let delta =
                wrap_address(relocation.offset.wrapping_sub(previous.offset), encoding) >> shift;
            let addend = relocation.addend.unwrap_or(0);
            let flags = u8::from(relocation.symbol != previous.symbol)
                | (u8::from(relocation.r_type != previous.r_type) << 1)
                | (u8::from(addend != previous.addend.unwrap_or(0)) << 2);
            // The low bits of the delta fit in the 7 bits of the first byte.
            let low = u8::try_from((delta & (limit - 1)) << flag_bits).unwrap_or(0);
            if delta < limit {
                out.push(low | flags);
            } else {
                out.push(0x80 | low | flags);
                write_uleb128(&mut out, delta >> (7 - flag_bits));
            }
            if flags & 1 != 0 {
                let step = relocation.symbol.wrapping_sub(previous.symbol);
                write_sleb128(&mut out, i64::from(step.cast_signed()));
            }
            if flags & 2 != 0 {
                let step = relocation.r_type.wrapping_sub(previous.r_type);
                write_sleb128(&mut out, i64::from(step.cast_signed()));
            }
            if flags & 4 != 0 {
                let step = addend.wrapping_sub(previous.addend.unwrap_or(0));
                write_sleb128(&mut out, wrap_addend(step, encoding));
            }
            previous = *relocation;
        }
        Ok(out)
    }
}
