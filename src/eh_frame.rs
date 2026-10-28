//! The `.eh_frame` section (CIE and FDE records) and the `.eh_frame_hdr` search table.
//!
//! [`EhFrame::parse`] reads the Common Information Entries ([`Cie`]) and Frame Description
//! Entries ([`Fde`]) of an `.eh_frame` section. It does not interpret the call frame
//! instructions: they stay as raw bytes. [`EhFrameHdr`] reads and writes the
//! `.eh_frame_hdr` section that the `PT_GNU_EH_FRAME` segment maps.
//!
//! The module also decodes `DW_EH_PE_*` pointers ([`read_encoded_pointer`]), and reads and
//! writes LEB128 values ([`read_uleb128`], [`write_uleb128`]).
//!
//! # Examples
//!
//! ```
//! use elfex::eh_frame::{EhFrame, EhFrameEntry, EhFrameHdr, EhFrameHdrEntry};
//! use elfex::Encoding;
//!
//! let encoding = Encoding::ELF64_LE;
//! // The crate has no `.eh_frame` writer. Write a CIE (version 1, no augmentation) and an
//! // FDE for the code at 0x1000..0x1010 with the `Encoding` helpers.
//! let mut frame = Vec::new();
//! encoding.write_u32(&mut frame, 12); // The CIE length.
//! encoding.write_u32(&mut frame, 0); // The CIE id.
//! // The version, "", the code and data alignment factors, the return address register
//! // and DW_CFA_nop padding.
//! frame.extend_from_slice(&[1, 0, 1, 0x78, 16, 0, 0, 0]);
//! encoding.write_u32(&mut frame, 20); // The FDE length.
//! encoding.write_u32(&mut frame, 20); // The CIE pointer: back to offset 0.
//! encoding.write_u64(&mut frame, 0x1000); // The initial location.
//! encoding.write_u64(&mut frame, 0x10); // The address range.
//! encoding.write_u32(&mut frame, 0); // The terminator.
//!
//! let entries = EhFrame::parse(&frame, encoding, 0x2000)?;
//! let [EhFrameEntry::Cie(cie), EhFrameEntry::Fde(fde)] = entries.as_slice() else {
//!     panic!("the section has one CIE and one FDE");
//! };
//! assert_eq!(cie.data_alignment_factor, -8);
//! assert_eq!((fde.cie_offset, fde.pc_begin, fde.pc_range), (0, 0x1000, 0x10));
//!
//! // The `.eh_frame_hdr` search table gives the FDE of an address.
//! let hdr = EhFrameHdr {
//!     version: 1,
//!     eh_frame_ptr: 0x2000,
//!     entries: vec![EhFrameHdrEntry { initial_location: 0x1000, fde_address: 0x2010 }],
//!     ..EhFrameHdr::default()
//! };
//! let parsed = EhFrameHdr::parse(&hdr.write(encoding, 0x1800)?, encoding, 0x1800)?;
//! assert_eq!(parsed.eh_frame_ptr, 0x2000);
//! assert_eq!(parsed.find_fde(0x1008), Some(0x2010));
//! # Ok::<(), elfex::Error>(())
//! ```

mod hdr;
mod pointer;
#[cfg(test)]
mod tests;

pub use hdr::{EhFrameHdr, EhFrameHdrEntry};
pub use pointer::{
    DW_EH_PE_ABSPTR, DW_EH_PE_ALIGNED, DW_EH_PE_DATAREL, DW_EH_PE_FUNCREL, DW_EH_PE_INDIRECT,
    DW_EH_PE_OMIT, DW_EH_PE_PCREL, DW_EH_PE_SDATA2, DW_EH_PE_SDATA4, DW_EH_PE_SDATA8,
    DW_EH_PE_SIGNED, DW_EH_PE_SLEB128, DW_EH_PE_TEXTREL, DW_EH_PE_UDATA2, DW_EH_PE_UDATA4,
    DW_EH_PE_UDATA8, DW_EH_PE_ULEB128, PointerBases, encoded_pointer_size, read_encoded_pointer,
    read_sleb128, read_uleb128, write_sleb128, write_uleb128,
};

use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};
use pointer::address_at;

/// A Common Information Entry (CIE) in `.eh_frame`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Cie {
    /// The offset of the CIE length field in the section.
    pub offset: u64,
    /// The CIE version: 1, 3 or 4.
    pub version: u8,
    /// The augmentation string, for example `zR` or `zPLR`.
    pub augmentation: String,
    /// The address size (version 4 only).
    pub address_size: Option<u8>,
    /// The segment selector size (version 4 only).
    pub segment_size: Option<u8>,
    /// The code alignment factor.
    pub code_alignment_factor: u64,
    /// The data alignment factor.
    pub data_alignment_factor: i64,
    /// The return address register number.
    pub return_address_register: u64,
    /// The `DW_EH_PE_*` encoding of the FDE addresses (augmentation `R`). The default is
    /// `DW_EH_PE_absptr`.
    pub fde_pointer_encoding: u8,
    /// The `DW_EH_PE_*` encoding of the FDE LSDA pointers (augmentation `L`).
    pub lsda_encoding: Option<u8>,
    /// The decoded virtual address of the personality routine (augmentation `P`). For a
    /// `DW_EH_PE_indirect` encoding, this is the address of the pointer to the routine.
    pub personality: Option<u64>,
    /// `true` if the augmentation has `S` (a signal frame).
    pub is_signal_frame: bool,
    /// The initial call frame instructions, not interpreted.
    pub initial_instructions: Vec<u8>,
}

/// A Frame Description Entry (FDE) in `.eh_frame`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fde {
    /// The offset of the FDE length field in the section.
    pub offset: u64,
    /// The offset of the length field of the CIE of this FDE in the section.
    pub cie_offset: u64,
    /// The virtual address of the first instruction that the FDE covers.
    pub pc_begin: u64,
    /// The number of bytes of code that the FDE covers.
    pub pc_range: u64,
    /// The decoded virtual address of the Language-Specific Data Area, if present.
    pub lsda: Option<u64>,
    /// The call frame instructions, not interpreted.
    pub instructions: Vec<u8>,
}

/// One record of an `.eh_frame` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EhFrameEntry {
    /// A Common Information Entry.
    Cie(Cie),
    /// A Frame Description Entry.
    Fde(Fde),
}

/// The parser of the `.eh_frame` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EhFrame;

/// The length and identifier fields of one `.eh_frame` record.
struct RecordHeader {
    /// The offset of the identifier (CIE id or CIE pointer) field.
    id_offset: usize,
    /// The identifier value.
    id: u64,
    /// The offset after the identifier field.
    body: usize,
    /// The offset after the record.
    end: usize,
}

/// Return the `InvalidTable` error for `.eh_frame` with `msg` at `offset`.
fn frame_error(msg: &str, offset: usize) -> Error {
    Error::invalid_table(msg)
        .in_structure(".eh_frame")
        .at_offset(u64::try_from(offset).unwrap_or(u64::MAX))
}

/// Convert a section offset to `u64`.
fn offset_u64(offset: usize) -> u64 {
    u64::try_from(offset).unwrap_or(u64::MAX)
}

/// Read one byte at `*pos` and move `pos` past it.
fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8> {
    let value = *bytes
        .get(*pos)
        .ok_or_else(|| Error::buffer_too_small(pos.saturating_add(1), bytes.len()))?;
    *pos += 1;
    Ok(value)
}

/// Return `pos + len` if it is not after `end`.
fn checked_end(pos: usize, len: u64, end: usize) -> Result<usize> {
    usize::try_from(len)
        .ok()
        .and_then(|len| pos.checked_add(len))
        .filter(|e| *e <= end)
        .ok_or_else(|| Error::buffer_too_small(usize::MAX, end))
}

impl EhFrame {
    /// Parse all records of an `.eh_frame` section.
    ///
    /// `section_address` is the virtual address of the first byte of `bytes`. The parser
    /// supports 32-bit and 64-bit DWARF lengths, CIE versions 1, 3 and 4, and the
    /// augmentations `z`, `R`, `L`, `P`, `S`, `B` and `G`. It skips unknown augmentation data
    /// after `z`. A zero length record ends the section.
    ///
    /// # Errors
    ///
    /// - Return [`crate::ErrorKind::BufferTooSmall`] if a record is truncated.
    /// - Return [`crate::ErrorKind::InvalidTable`] for an unsupported CIE version or
    ///   augmentation, or an FDE whose CIE pointer does not point to a CIE.
    /// - Return [`crate::ErrorKind::InvalidUtf8`] if the augmentation string is not UTF-8.
    pub fn parse(
        bytes: &[u8],
        encoding: Encoding,
        section_address: u64,
    ) -> Result<Vec<EhFrameEntry>> {
        let mut entries = Vec::new();
        // The CIEs in section order. A CIE pointer always points backward, so the list is
        // sorted by offset.
        let mut cies: Vec<Cie> = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let Some(header) = read_record_header(bytes, encoding, offset)? else {
                break;
            };
            let record = &bytes[..header.end];
            if header.id == 0 {
                let cie = parse_cie(record, encoding, section_address, offset, header.body)?;
                cies.push(cie.clone());
                entries.push(EhFrameEntry::Cie(cie));
            } else {
                let cie_offset = offset_u64(header.id_offset)
                    .checked_sub(header.id)
                    .ok_or_else(|| frame_error("CIE pointer is before the section", offset))?;
                let cie = cies
                    .binary_search_by_key(&cie_offset, |c| c.offset)
                    .ok()
                    .and_then(|i| cies.get(i))
                    .ok_or_else(|| frame_error("CIE pointer does not point to a CIE", offset))?;
                let fde = parse_fde(record, encoding, section_address, cie, offset, header.body)?;
                entries.push(EhFrameEntry::Fde(Fde { cie_offset, ..fde }));
            }
            offset = header.end;
        }
        Ok(entries)
    }
}

/// Read the length and identifier of the record at `offset`, or `None` for a terminator.
fn read_record_header(
    bytes: &[u8],
    encoding: Encoding,
    offset: usize,
) -> Result<Option<RecordHeader>> {
    let length32 = encoding.read_u32(bytes, offset)?;
    if length32 == 0 {
        return Ok(None);
    }
    // In `.eh_frame`, the CIE id and the CIE pointer are 4 bytes also in a record with a 64-bit
    // length (LSB, libgcc, libunwind). Only `.debug_frame` uses 8 bytes there.
    let (length, id_offset) = if length32 == 0xffff_ffff {
        let length = encoding.read_u64(bytes, offset.saturating_add(4))?;
        (length, offset.saturating_add(12))
    } else {
        (u64::from(length32), offset.saturating_add(4))
    };
    let end = checked_end(id_offset, length, bytes.len())
        .map_err(|e| e.in_structure(".eh_frame").at_offset(offset_u64(offset)))?;
    let id = u64::from(encoding.read_u32(&bytes[..end], id_offset)?);
    Ok(Some(RecordHeader {
        id_offset,
        id,
        body: id_offset + 4,
        end,
    }))
}

/// Parse the CIE that starts at `offset`. `record` ends at the end of the CIE and `pos` is
/// the offset after the CIE id.
fn parse_cie(
    record: &[u8],
    encoding: Encoding,
    section_address: u64,
    offset: usize,
    mut pos: usize,
) -> Result<Cie> {
    let version = read_u8(record, &mut pos)?;
    if !matches!(version, 1 | 3 | 4) {
        return Err(frame_error("unsupported CIE version", offset));
    }
    let rest = record.get(pos..).unwrap_or_default();
    let nul = rest
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| Error::buffer_too_small(record.len().saturating_add(1), record.len()))?;
    let augmentation = core::str::from_utf8(&rest[..nul])
        .map_err(|_| Error::invalid_utf8().in_structure(".eh_frame"))?
        .to_string();
    pos += nul + 1;
    let mut cie = Cie {
        offset: offset_u64(offset),
        version,
        augmentation,
        ..Cie::default()
    };
    if augmentation_has_eh(&cie.augmentation) {
        // The old GCC `eh` augmentation has a class-sized pointer here.
        pos = pos
            .checked_add(encoding.addr_size())
            .filter(|p| *p <= record.len())
            .ok_or_else(|| Error::buffer_too_small(usize::MAX, record.len()))?;
    }
    if version == 4 {
        cie.address_size = Some(read_u8(record, &mut pos)?);
        cie.segment_size = Some(read_u8(record, &mut pos)?);
    }
    cie.code_alignment_factor = read_uleb128(record, &mut pos)?;
    cie.data_alignment_factor = read_sleb128(record, &mut pos)?;
    cie.return_address_register = if version == 1 {
        u64::from(read_u8(record, &mut pos)?)
    } else {
        read_uleb128(record, &mut pos)?
    };
    if cie.augmentation.starts_with('z') {
        pos = parse_cie_augmentation(record, encoding, section_address, pos, &mut cie)?;
    } else if !cie.augmentation.is_empty() && !augmentation_has_eh(&cie.augmentation) {
        return Err(frame_error("unsupported CIE augmentation", offset));
    }
    cie.initial_instructions = record.get(pos..).unwrap_or_default().to_vec();
    Ok(cie)
}

/// Return `true` for the old GCC augmentation `eh`.
fn augmentation_has_eh(augmentation: &str) -> bool {
    augmentation == "eh"
}

/// Read the augmentation data of a CIE with a `z` augmentation, and return the offset after it.
fn parse_cie_augmentation(
    record: &[u8],
    encoding: Encoding,
    section_address: u64,
    mut pos: usize,
    cie: &mut Cie,
) -> Result<usize> {
    let length = read_uleb128(record, &mut pos)?;
    let end = checked_end(pos, length, record.len())?;
    let data = &record[..end];
    let bases = PointerBases::default();
    for c in cie.augmentation.chars().skip(1) {
        match c {
            'R' => cie.fde_pointer_encoding = read_u8(data, &mut pos)?,
            'L' => cie.lsda_encoding = Some(read_u8(data, &mut pos)?),
            'P' => {
                let pe = read_u8(data, &mut pos)?;
                let field = address_at(encoding, section_address, pos);
                cie.personality =
                    read_encoded_pointer(data, &mut pos, encoding, pe, field, &bases)?;
            }
            'S' => cie.is_signal_frame = true,
            // AArch64 pointer authentication with the B key and memory tagging have no data.
            'B' | 'G' => {}
            // The augmentation data length tells where the data ends.
            _ => break,
        }
    }
    Ok(end)
}

/// Parse the FDE that starts at `offset`. `record` ends at the end of the FDE and `pos` is
/// the offset after the CIE pointer.
fn parse_fde(
    record: &[u8],
    encoding: Encoding,
    section_address: u64,
    cie: &Cie,
    offset: usize,
    mut pos: usize,
) -> Result<Fde> {
    let pe = cie.fde_pointer_encoding;
    let bases = PointerBases::default();
    let field = address_at(encoding, section_address, pos);
    let pc_begin = read_encoded_pointer(record, &mut pos, encoding, pe, field, &bases)?
        .ok_or_else(|| frame_error("FDE pc_begin is omitted", offset))?;
    // The address range uses the value format only, without the base.
    let field = address_at(encoding, section_address, pos);
    let pc_range = read_encoded_pointer(record, &mut pos, encoding, pe & 0x0f, field, &bases)?
        .ok_or_else(|| frame_error("FDE pc_range is omitted", offset))?;
    let mut lsda = None;
    if cie.augmentation.starts_with('z') {
        let length = read_uleb128(record, &mut pos)?;
        let end = checked_end(pos, length, record.len())?;
        if let Some(lsda_encoding) = cie.lsda_encoding {
            let func_bases = PointerBases {
                func: Some(pc_begin),
                ..PointerBases::default()
            };
            let field = address_at(encoding, section_address, pos);
            lsda = read_encoded_pointer(
                &record[..end],
                &mut pos,
                encoding,
                lsda_encoding,
                field,
                &func_bases,
            )?;
        }
        pos = end;
    }
    Ok(Fde {
        offset: offset_u64(offset),
        cie_offset: 0,
        pc_begin,
        pc_range,
        lsda,
        instructions: record.get(pos..).unwrap_or_default().to_vec(),
    })
}
