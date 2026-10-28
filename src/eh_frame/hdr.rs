//! The `.eh_frame_hdr` section (`PT_GNU_EH_FRAME` segment): the binary search table of FDEs.

use super::pointer::{
    DW_EH_PE_DATAREL, DW_EH_PE_OMIT, DW_EH_PE_PCREL, DW_EH_PE_SDATA4, DW_EH_PE_UDATA4,
    PointerBases, address_at, encoded_pointer_size, read_encoded_pointer, wrap_address,
};
use crate::endian::{Class, Encoding};
use crate::prelude::*;
use crate::{Error, Result};

/// One entry of the `.eh_frame_hdr` binary search table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EhFrameHdrEntry {
    /// The virtual address of the first instruction that the FDE covers.
    pub initial_location: u64,
    /// The virtual address of the FDE in `.eh_frame`.
    pub fde_address: u64,
}

/// The `.eh_frame_hdr` section, which the `PT_GNU_EH_FRAME` segment maps.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EhFrameHdr {
    /// The format version. elfex reads and writes version 1.
    pub version: u8,
    /// The `DW_EH_PE_*` encoding of `eh_frame_ptr`.
    pub eh_frame_ptr_encoding: u8,
    /// The `DW_EH_PE_*` encoding of the FDE count.
    pub fde_count_encoding: u8,
    /// The `DW_EH_PE_*` encoding of the table values.
    pub table_encoding: u8,
    /// The decoded virtual address of the `.eh_frame` section.
    pub eh_frame_ptr: u64,
    /// The binary search table, sorted by `initial_location`.
    pub entries: Vec<EhFrameHdrEntry>,
}

/// Return the `InvalidTable` error for `.eh_frame_hdr` with `msg`.
fn hdr_error(msg: &str) -> Error {
    Error::invalid_table(msg).in_structure(".eh_frame_hdr")
}

impl EhFrameHdr {
    /// Parse an `.eh_frame_hdr` section.
    ///
    /// `section_address` is the virtual address of the first byte of `bytes`.
    /// `DW_EH_PE_pcrel` values are relative to the address of their field and
    /// `DW_EH_PE_datarel` values are relative to `section_address`. If the FDE count or the
    /// table encoding is `DW_EH_PE_omit`, the table is empty.
    ///
    /// # Errors
    ///
    /// - Return [`crate::ErrorKind::BufferTooSmall`] if the data is truncated.
    /// - Return [`crate::ErrorKind::InvalidTable`] for an unknown version or encoding, an omitted
    ///   `eh_frame_ptr`, or a table that does not fit in `bytes`.
    pub fn parse(bytes: &[u8], encoding: Encoding, section_address: u64) -> Result<Self> {
        let header = bytes
            .get(..4)
            .ok_or_else(|| Error::buffer_too_small(4, bytes.len()))?;
        let (version, eh_frame_ptr_encoding, fde_count_encoding, table_encoding) =
            (header[0], header[1], header[2], header[3]);
        if version != 1 {
            return Err(hdr_error("unsupported .eh_frame_hdr version"));
        }
        let bases = PointerBases {
            data: Some(section_address),
            ..PointerBases::default()
        };
        let mut offset = 4;
        let read = |offset: &mut usize, pe: u8| {
            let field = address_at(encoding, section_address, *offset);
            read_encoded_pointer(bytes, offset, encoding, pe, field, &bases)
        };
        let eh_frame_ptr = read(&mut offset, eh_frame_ptr_encoding)?
            .ok_or_else(|| hdr_error("eh_frame_ptr is omitted"))?;
        let mut entries = Vec::new();
        if let Some(count) = read(&mut offset, fde_count_encoding)?
            && table_encoding != DW_EH_PE_OMIT
        {
            let count = usize::try_from(count).map_err(|_| hdr_error("FDE count is too large"))?;
            // Each value has at least one byte (LEB128) or its fixed size.
            let value_size = encoded_pointer_size(encoding, table_encoding).unwrap_or(1);
            let needed = count
                .checked_mul(value_size)
                .and_then(|n| n.checked_mul(2))
                .ok_or_else(|| hdr_error("FDE count is too large"))?;
            let remaining = bytes.len().saturating_sub(offset);
            if needed > remaining {
                return Err(
                    Error::buffer_too_small(offset.saturating_add(needed), bytes.len())
                        .in_structure(".eh_frame_hdr"),
                );
            }
            entries.reserve(count);
            // The table encoding is not `DW_EH_PE_omit`, so each value is present.
            for _ in 0..count {
                let initial_location = read(&mut offset, table_encoding)?.unwrap_or_default();
                let fde_address = read(&mut offset, table_encoding)?.unwrap_or_default();
                entries.push(EhFrameHdrEntry {
                    initial_location,
                    fde_address,
                });
            }
        }
        Ok(Self {
            version,
            eh_frame_ptr_encoding,
            fde_count_encoding,
            table_encoding,
            eh_frame_ptr,
            entries,
        })
    }

    /// Return the virtual address of the FDE that covers `pc`.
    ///
    /// The result is the FDE of the last entry whose `initial_location` is less than or equal
    /// to `pc`. The entries must be sorted by `initial_location`. The function does not check
    /// the address range of the FDE.
    #[must_use]
    pub fn find_fde(&self, pc: u64) -> Option<u64> {
        let index = self.entries.partition_point(|e| e.initial_location <= pc);
        index
            .checked_sub(1)
            .and_then(|i| self.entries.get(i))
            .map(|e| e.fde_address)
    }

    /// Serialize the section for the virtual address `section_address`.
    ///
    /// The output is version 1, with `eh_frame_ptr` as `DW_EH_PE_pcrel | DW_EH_PE_sdata4`, the
    /// FDE count as `DW_EH_PE_udata4` and the table as `DW_EH_PE_datarel | DW_EH_PE_sdata4`,
    /// sorted by `initial_location`. The encoding fields of `self` are ignored.
    ///
    /// # Errors
    ///
    /// Return [`crate::ErrorKind::ValueOutOfRange`] if a value does not fit in `sdata4` or the
    /// entry count does not fit in `udata4`.
    pub fn write(&self, encoding: Encoding, section_address: u64) -> Result<Vec<u8>> {
        let count = u32::try_from(self.entries.len())
            .map_err(|_| Error::value_out_of_range("too many .eh_frame_hdr entries"))?;
        let mut entries = self.entries.clone();
        entries.sort_by_key(|e| e.initial_location);
        let mut out = Vec::with_capacity(12 + entries.len() * 8);
        out.extend_from_slice(&[
            1,
            DW_EH_PE_PCREL | DW_EH_PE_SDATA4,
            DW_EH_PE_UDATA4,
            DW_EH_PE_DATAREL | DW_EH_PE_SDATA4,
        ]);
        let field = address_at(encoding, section_address, 4);
        encoding.write_i32(&mut out, sdata4(encoding, self.eh_frame_ptr, field)?);
        encoding.write_u32(&mut out, count);
        for entry in &entries {
            encoding.write_i32(
                &mut out,
                sdata4(encoding, entry.initial_location, section_address)?,
            );
            encoding.write_i32(
                &mut out,
                sdata4(encoding, entry.fde_address, section_address)?,
            );
        }
        Ok(out)
    }
}

/// Return `value - base` as a signed 4-byte value, with class-sized wrapping arithmetic.
fn sdata4(encoding: Encoding, value: u64, base: u64) -> Result<i32> {
    let diff = wrap_address(encoding, value.wrapping_sub(base));
    let signed = match encoding.class {
        Class::Elf32 => i64::from(u32::try_from(diff).unwrap_or(0).cast_signed()),
        Class::Elf64 => diff.cast_signed(),
    };
    i32::try_from(signed).map_err(|_| {
        Error::value_out_of_range(format!(
            "{value:#x} is not within sdata4 range of {base:#x}"
        ))
        .in_structure(".eh_frame_hdr")
    })
}
