//! Read and write the memory of an [`ElfImage`] at virtual addresses.

use super::{ElfImage, Segment};
use crate::prelude::*;
use crate::program::{ProgramHeader, SegmentType};
use crate::{Error, Result};

/// Return `true` if the memory range of `header` contains `len` bytes at `vaddr`.
fn memory_contains(header: &ProgramHeader, vaddr: u64, len: u64) -> bool {
    let Some(end) = vaddr.checked_add(len) else {
        return false;
    };
    header
        .memory_range()
        .is_some_and(|range| range.start <= vaddr && end <= range.end)
}

impl ElfImage {
    /// Return the first `PT_LOAD` segment whose memory range contains `len` bytes at `vaddr`.
    fn load_segment_for(&self, vaddr: u64, len: u64) -> Option<&Segment> {
        self.load_segments()
            .find(|segment| memory_contains(&segment.header, vaddr, len))
    }

    /// Read `len` bytes of memory at the virtual address `vaddr`.
    ///
    /// The bytes must be in the memory range of one `PT_LOAD` segment. The bytes after the
    /// segment data, up to `p_memsz`, read as zeros. If more than one `PT_LOAD` segment
    /// contains the range, the function reads the first one in program header order.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no
    ///   `PT_LOAD` memory range contains the bytes.
    /// - Return a generic error if the allocation of `len` bytes fails.
    pub fn read_vaddr(&self, vaddr: u64, len: usize) -> Result<Vec<u8>> {
        // A `usize` value always fits in `u64`.
        let len_u64 = u64::try_from(len).unwrap_or(u64::MAX);
        let segment = self
            .load_segment_for(vaddr, len_u64)
            .ok_or_else(|| Error::invalid_address(vaddr))?;
        let mut out = Vec::new();
        out.try_reserve_exact(len)
            .map_err(|_| Error::generic(format!("cannot allocate {len} bytes")))?;
        let memory = segment.memory_data();
        if let Ok(start) = usize::try_from(vaddr - segment.header.vaddr)
            && let Some(available) = memory.get(start..)
        {
            out.extend_from_slice(available.get(..len).unwrap_or(available));
        }
        out.resize(len, 0);
        Ok(out)
    }

    /// Return the segment data from the virtual address `vaddr` to the end of the data of its
    /// `PT_LOAD` segment.
    ///
    /// This is the largest slice that the image can give at `vaddr`. The slice is empty if
    /// `vaddr` is in the zero-filled memory after the segment data.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no `PT_LOAD`
    /// memory range contains `vaddr`.
    pub fn slice_from_vaddr(&self, vaddr: u64) -> Result<&[u8]> {
        let segment = self
            .load_segments()
            .find(|segment| segment.header.contains_vaddr(vaddr))
            .ok_or_else(|| Error::invalid_address(vaddr))?;
        let memory = segment.memory_data();
        let slice = usize::try_from(vaddr - segment.header.vaddr)
            .ok()
            .and_then(|start| memory.get(start..))
            .unwrap_or_default();
        Ok(slice)
    }

    /// Write `bytes` to memory at the virtual address `vaddr`.
    ///
    /// The bytes must be in the memory range of one `PT_LOAD` segment. If the bytes go past
    /// the segment data, the function first extends the data with zeros. The data never
    /// grows past `p_memsz`.
    ///
    /// [`Self::try_build`] writes only the first `p_filesz` bytes of each segment. To keep
    /// bytes after `p_filesz` in the raw file, also increase `p_filesz`.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no
    ///   `PT_LOAD` memory range contains the bytes.
    /// - Return a generic error if the allocation of the new data fails.
    pub fn write_vaddr(&mut self, vaddr: u64, bytes: &[u8]) -> Result<()> {
        // A `usize` value always fits in `u64`.
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let segment = self
            .segments
            .iter_mut()
            .find(|segment| segment.is_load() && memory_contains(&segment.header, vaddr, len))
            .ok_or_else(|| Error::invalid_address(vaddr))?;
        // The memory range contains the bytes, so the offsets are not larger than `p_memsz`.
        let start = usize::try_from(vaddr - segment.header.vaddr)
            .map_err(|_| Error::invalid_address(vaddr))?;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| Error::invalid_address(vaddr))?;
        if segment.data.len() < end {
            segment
                .data
                .try_reserve_exact(end - segment.data.len())
                .map_err(|_| Error::generic(format!("cannot allocate {end} bytes")))?;
            segment.data.resize(end, 0);
        }
        // The data has at least `end` bytes.
        segment.data[start..end].copy_from_slice(bytes);
        Ok(())
    }

    /// Return the path of the program interpreter from the `PT_INTERP` segment.
    ///
    /// The path is the segment bytes up to the first null byte. If the segment has no own
    /// data, the function reads the bytes through the `PT_LOAD` memory. Return `None` if the
    /// image has no `PT_INTERP` segment.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no
    ///   `PT_LOAD` segment contains the `PT_INTERP` address.
    /// - Return [`ErrorKind::InvalidUtf8`](crate::ErrorKind::InvalidUtf8) if the path is not
    ///   UTF-8.
    pub fn interpreter(&self) -> Result<Option<String>> {
        let Some(segment) = self.segment(SegmentType::INTERP) else {
            return Ok(None);
        };
        let bytes = if segment.data.is_empty() {
            self.slice_from_vaddr(segment.header.vaddr)
                .map_err(|error| error.in_structure("PT_INTERP"))?
        } else {
            segment.data.as_slice()
        };
        let limit = usize::try_from(segment.header.filesz)
            .map_or(bytes.len(), |size| size.min(bytes.len()));
        let bytes = bytes.get(..limit).unwrap_or(bytes);
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        let path = bytes
            .get(..end)
            .and_then(|path| core::str::from_utf8(path).ok())
            .ok_or_else(|| Error::invalid_utf8().in_structure("PT_INTERP"))?;
        Ok(Some(path.to_string()))
    }
}
