//! The Android packed relocation format `APS2` (`SHT_ANDROID_REL`, `SHT_ANDROID_RELA`,
//! `DT_ANDROID_REL`, `DT_ANDROID_RELA`).
//!
//! The format is the one of bionic (`packed_reloc_iterator`) and of LLVM
//! (`ELFFile::android_relas`):
//!
//! 1. The magic bytes `APS2`.
//! 2. The relocation count and the initial offset, as SLEB128 values.
//! 3. Groups of entries until the count is complete. A group starts with its entry count and
//!    its `RELOCATION_*` flags. Then come the shared values that the flags select: the offset
//!    delta, `r_info` and the addend delta. Then each entry gives the values that the group
//!    does not share, in the same order.

use super::{Relocation, RelocationTable, decode_info, wrap_addend, wrap_address};
use crate::eh_frame::{read_sleb128, write_sleb128};
use crate::endian::Encoding;
use crate::header::Machine;
use crate::prelude::*;
use crate::{Error, Result};

/// The magic bytes at the start of an Android packed relocation table.
pub const ANDROID_PACKED_MAGIC: [u8; 4] = *b"APS2";
/// `RELOCATION_GROUPED_BY_INFO_FLAG`: all entries of the group have the same `r_info`.
pub const RELOCATION_GROUPED_BY_INFO_FLAG: u64 = 1;
/// `RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG`: all entries of the group have the same offset
/// delta.
pub const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: u64 = 2;
/// `RELOCATION_GROUPED_BY_ADDEND_FLAG`: all entries of the group have the same addend.
pub const RELOCATION_GROUPED_BY_ADDEND_FLAG: u64 = 4;
/// `RELOCATION_GROUP_HAS_ADDEND_FLAG`: the entries of the group have addends. Without this
/// flag, the addend of each entry is 0.
pub const RELOCATION_GROUP_HAS_ADDEND_FLAG: u64 = 8;
/// The largest number of entries that
/// [`RelocationTable::parse_android_packed`] decodes for each byte of its input.
///
/// A group that shares the offset delta and `r_info` gives many entries from a few bytes. The
/// limit stops a small table that declares a very large count. A linker output uses much less
/// than this ratio.
pub const ANDROID_PACKED_MAX_ENTRIES_PER_BYTE: usize = 1024;

/// A reader of the SLEB128 values of a packed table.
struct Reader<'a> {
    /// The table, with the magic bytes.
    bytes: &'a [u8],
    /// The offset of the next value.
    pos: usize,
    /// The structure name for the error context.
    structure: &'static str,
}

impl Reader<'_> {
    /// Read the next SLEB128 value.
    fn signed(&mut self) -> Result<i64> {
        let pos = self.pos;
        read_sleb128(self.bytes, &mut self.pos).map_err(|error| {
            error
                .in_structure(self.structure)
                .at_offset(offset_u64(pos))
        })
    }

    /// Read the next SLEB128 value as the bits of a 64-bit word.
    fn word(&mut self) -> Result<u64> {
        self.signed().map(i64::cast_unsigned)
    }

    /// Return an `InvalidTable` error at the offset `pos`.
    fn error(&self, pos: usize, msg: String) -> Error {
        Error::invalid_table(msg)
            .in_structure(self.structure)
            .at_offset(offset_u64(pos))
    }
}

/// The shared values of one group.
struct Group {
    /// The offset delta of all entries, or `None` if each entry gives its delta.
    offset_delta: Option<u64>,
    /// The `r_info` value of all entries, or `None` if each entry gives its value.
    info: Option<u64>,
    /// `true` if each entry gives an addend delta.
    entry_addends: bool,
}

impl Group {
    /// Read the flags and the shared values of a group. Update `addend` as the group header
    /// demands.
    fn read(reader: &mut Reader<'_>, with_addend: bool, addend: &mut i64) -> Result<Self> {
        let flags_pos = reader.pos;
        let flags = reader.word()?;
        let has_addend = flags & RELOCATION_GROUP_HAS_ADDEND_FLAG != 0;
        if has_addend && !with_addend {
            return Err(reader.error(
                flags_pos,
                "a relocation group has addends in a table without addends".into(),
            ));
        }
        let offset_delta = if flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0 {
            Some(reader.word()?)
        } else {
            None
        };
        let info = if flags & RELOCATION_GROUPED_BY_INFO_FLAG != 0 {
            Some(reader.word()?)
        } else {
            None
        };
        let by_addend = flags & RELOCATION_GROUPED_BY_ADDEND_FLAG != 0;
        if has_addend && by_addend {
            *addend = addend.wrapping_add(reader.signed()?);
        }
        if !has_addend {
            *addend = 0;
        }
        Ok(Self {
            offset_delta,
            info,
            entry_addends: has_addend && !by_addend,
        })
    }
}

impl RelocationTable {
    /// Decode an Android packed relocation table (`APS2`).
    ///
    /// Set `with_addend` to `true` for `SHT_ANDROID_RELA` and `DT_ANDROID_RELA`, and to
    /// `false` for `SHT_ANDROID_REL` and `DT_ANDROID_REL`. The offsets, the addends and the
    /// `r_info` values are deltas. Their sums wrap at the class size, as in the loader. The
    /// decoder ignores the bytes after the last group: a linker can pad the table.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the table does
    ///   not start with `APS2`, if the count is more than
    ///   [`ANDROID_PACKED_MAX_ENTRIES_PER_BYTE`] times the length of `bytes`, if a group has
    ///   more entries than the count leaves, if a group of a table without addends has
    ///   `RELOCATION_GROUP_HAS_ADDEND_FLAG`, or if a value does not fit in 64 bits.
    /// - Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if the table
    ///   ends in a value.
    pub fn parse_android_packed(
        bytes: &[u8],
        encoding: Encoding,
        machine: Machine,
        with_addend: bool,
    ) -> Result<Self> {
        let structure = if with_addend {
            "SHT_ANDROID_RELA"
        } else {
            "SHT_ANDROID_REL"
        };
        if !bytes.starts_with(&ANDROID_PACKED_MAGIC) {
            return Err(
                Error::invalid_table("the packed relocations do not start with APS2")
                    .in_structure(structure),
            );
        }
        let mut reader = Reader {
            bytes,
            pos: ANDROID_PACKED_MAGIC.len(),
            structure,
        };
        let count = reader.word()?;
        let mut offset = reader.word()?;
        let budget = bytes
            .len()
            .saturating_mul(ANDROID_PACKED_MAX_ENTRIES_PER_BYTE);
        let mut remaining = usize::try_from(count)
            .ok()
            .filter(|count| *count <= budget)
            .ok_or_else(|| {
                reader.error(
                    ANDROID_PACKED_MAGIC.len(),
                    format!(
                        "the relocation count {count} is larger than the limit {budget} for {} bytes",
                        bytes.len()
                    ),
                )
            })?;
        let mut relocations = Vec::with_capacity(remaining.min(bytes.len()));
        let mut addend = 0_i64;
        while remaining > 0 {
            let group_pos = reader.pos;
            let size = reader.word()?;
            let size = usize::try_from(size)
                .ok()
                .filter(|size| *size <= remaining)
                .ok_or_else(|| {
                    reader.error(
                        group_pos,
                        format!(
                            "the relocation group has {size} entries, but only {remaining} remain"
                        ),
                    )
                })?;
            remaining -= size;
            let group = Group::read(&mut reader, with_addend, &mut addend)?;
            for _ in 0..size {
                let delta = match group.offset_delta {
                    Some(delta) => delta,
                    None => reader.word()?,
                };
                offset = offset.wrapping_add(delta);
                let info = match group.info {
                    Some(info) => info,
                    None => reader.word()?,
                };
                if group.entry_addends {
                    addend = addend.wrapping_add(reader.signed()?);
                }
                let (symbol, r_type) = decode_info(info, encoding, machine);
                relocations.push(Relocation {
                    offset: wrap_address(offset, encoding),
                    symbol,
                    r_type,
                    addend: with_addend.then(|| wrap_addend(addend, encoding)),
                });
            }
        }
        Ok(Self {
            relocations,
            with_addend,
        })
    }

    /// Encode the table in the Android packed format (`APS2`).
    ///
    /// The encoder puts each run of two or more entries with the same offset delta, `r_info`
    /// and addend in one group that shares these values. It puts the other entries in groups
    /// that share nothing. The initial offset is 0, and the encoder adds no padding.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if an entry of a
    ///   table without addends has an addend, or an entry of a table with addends has none.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an entry
    ///   does not fit in an ELF32 entry (see [`Relocation::write`]).
    pub fn write_android_packed(&self, encoding: Encoding, machine: Machine) -> Result<Vec<u8>> {
        let mut entries = Vec::with_capacity(self.relocations.len());
        let mut previous = 0_u64;
        for (index, relocation) in self.relocations.iter().enumerate() {
            self.check_addend(index, relocation)?;
            relocation.check_class(encoding)?;
            entries.push(Entry {
                delta: relocation.offset.wrapping_sub(previous),
                info: relocation.info(encoding, machine)?,
                addend: relocation.addend.unwrap_or(0),
            });
            previous = relocation.offset;
        }
        let mut out = ANDROID_PACKED_MAGIC.to_vec();
        write_sleb128(&mut out, count_i64(entries.len())?);
        write_sleb128(&mut out, 0);
        let mut addend = 0_i64;
        let mut start = 0;
        while start < entries.len() {
            let repeats = |index: usize| entries.get(index + 1) == entries.get(index);
            let end = if repeats(start) {
                let end = (start..entries.len())
                    .find(|index| !repeats(*index))
                    .map_or(entries.len(), |index| index + 1);
                write_shared_group(
                    &mut out,
                    &entries[start..end],
                    self.with_addend,
                    &mut addend,
                )?;
                end
            } else {
                let end = (start..entries.len())
                    .find(|index| repeats(*index))
                    .unwrap_or(entries.len());
                write_plain_group(
                    &mut out,
                    &entries[start..end],
                    self.with_addend,
                    &mut addend,
                )?;
                end
            };
            start = end;
        }
        Ok(out)
    }
}

/// The values of one entry for the encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    /// The offset minus the offset of the previous entry.
    delta: u64,
    /// The `r_info` value.
    info: u64,
    /// The addend, or 0.
    addend: i64,
}

/// Append a group of equal entries that shares the offset delta, `r_info` and the addend.
fn write_shared_group(
    out: &mut Vec<u8>,
    entries: &[Entry],
    with_addend: bool,
    addend: &mut i64,
) -> Result<()> {
    let Some(first) = entries.first() else {
        return Ok(());
    };
    let has_addend = with_addend && first.addend != 0;
    let mut flags = RELOCATION_GROUPED_BY_INFO_FLAG | RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG;
    if has_addend {
        flags |= RELOCATION_GROUPED_BY_ADDEND_FLAG | RELOCATION_GROUP_HAS_ADDEND_FLAG;
    }
    write_sleb128(out, count_i64(entries.len())?);
    write_sleb128(out, flags.cast_signed());
    write_sleb128(out, first.delta.cast_signed());
    write_sleb128(out, first.info.cast_signed());
    if has_addend {
        write_sleb128(out, first.addend.wrapping_sub(*addend));
        *addend = first.addend;
    } else {
        *addend = 0;
    }
    Ok(())
}

/// Append a group that shares no value: each entry gives its offset delta, its `r_info` and,
/// if an addend is not 0, its addend delta.
fn write_plain_group(
    out: &mut Vec<u8>,
    entries: &[Entry],
    with_addend: bool,
    addend: &mut i64,
) -> Result<()> {
    let has_addend = with_addend && entries.iter().any(|entry| entry.addend != 0);
    let flags = if has_addend {
        RELOCATION_GROUP_HAS_ADDEND_FLAG
    } else {
        0
    };
    write_sleb128(out, count_i64(entries.len())?);
    write_sleb128(out, flags.cast_signed());
    if !has_addend {
        *addend = 0;
    }
    for entry in entries {
        write_sleb128(out, entry.delta.cast_signed());
        write_sleb128(out, entry.info.cast_signed());
        if has_addend {
            write_sleb128(out, entry.addend.wrapping_sub(*addend));
            *addend = entry.addend;
        }
    }
    Ok(())
}

/// Convert an entry count to the signed value of the stream.
fn count_i64(count: usize) -> Result<i64> {
    i64::try_from(count).map_err(|_| {
        Error::value_out_of_range(format!("the relocation count {count} is too large"))
            .in_structure("APS2")
    })
}

/// Convert a stream position to a `u64` offset for the error context.
fn offset_u64(pos: usize) -> u64 {
    u64::try_from(pos).unwrap_or(u64::MAX)
}
