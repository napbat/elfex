//! Serialize an [`ElfImage`] as a loader-mapped image or as a raw file without sections, and
//! validate it.

use super::{ElfImage, zeroed};
use crate::elf::validate::validate_headers;
use crate::header::FileHeader;
use crate::prelude::*;
use crate::program::{PN_XNUM, ProgramHeader};
use crate::section::SHN_UNDEF;
use crate::validation::ValidationResult;
use crate::{Error, Result};

#[cfg(feature = "std")]
use std::{fs::File, path::Path};

/// Bytes to put at a file offset in the raw file.
struct Placement<'a> {
    /// The file offset of the bytes.
    offset: u64,
    /// The number of bytes that the placement covers. The bytes after `bytes` are zeros.
    extent: u64,
    /// The bytes to copy.
    bytes: &'a [u8],
}

impl ElfImage {
    /// Make a loader-mapped image: the memory from the image origin to the end of the highest
    /// `PT_LOAD` memory range.
    ///
    /// The function copies the data of each `PT_LOAD` segment to its virtual address minus the
    /// image origin, in program header order. A later segment overwrites the bytes of an
    /// earlier segment. The memory after the segment data, and the gaps between segments, are
    /// zeros. The function does not apply relocations.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if the image
    ///   has no `PT_LOAD` segment, if the image origin is undefined, or if the size does not
    ///   fit in memory.
    /// - Return a generic error if the allocation fails.
    pub fn to_mapped_image(&self) -> Result<Vec<u8>> {
        let origin = self.image_origin().ok_or_else(|| {
            Error::invalid_segment("the image has no PT_LOAD segment with a defined origin")
        })?;
        let size = self
            .image_end()
            .and_then(|end| end.checked_sub(origin))
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| {
                Error::invalid_segment("the mapped image size does not fit in memory")
            })?;
        let mut image = zeroed(size)?;
        for segment in self.load_segments() {
            let memory = segment.memory_data();
            // `origin` is not larger than the lowest `p_vaddr`, and `size` is not smaller than
            // the end of each memory range minus `origin`. Thus the image contains the target.
            let target = segment
                .header
                .vaddr
                .checked_sub(origin)
                .and_then(|start| usize::try_from(start).ok())
                .and_then(|start| image.get_mut(start..start.checked_add(memory.len())?));
            if let Some(target) = target {
                target.copy_from_slice(memory);
            }
        }
        Ok(image)
    }

    /// Serialize the image as a raw ELF file without sections.
    ///
    /// # Panics
    ///
    /// Panic if the image is not valid for a raw file. Use [`Self::try_build`] to handle
    /// invalid input.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("ELF image build failed: use ElfImage::try_build() to handle invalid input")
    }

    /// Serialize the image as a raw ELF file without sections.
    ///
    /// The function writes these items, in this order:
    ///
    /// 1. The first `p_filesz` bytes of each `PT_LOAD` segment at `p_offset`, in program
    ///    header order. If the data is shorter, the other bytes are zeros.
    /// 2. The data of each other segment that has own data, at `p_offset`.
    /// 3. The ELF header at offset 0, and the program header table at `e_phoff`.
    ///
    /// A later item overwrites the bytes of an earlier item. Thus the headers overwrite the
    /// start of the first segment, which normally holds a copy of the headers. The gaps are
    /// zeros. The output ends at the end of the last item.
    ///
    /// The output header has `e_shoff`, `e_shnum` and `e_shstrndx` set to 0, because the image
    /// has no sections. `e_phnum` is the number of segments. If `e_phentsize` is smaller than
    /// the program header structure, the function uses the structure size.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidHeader`](crate::ErrorKind::InvalidHeader) if the image has
    ///   `PN_XNUM` (65535) or more segments, because that needs section header 0. Also return
    ///   it if the image has segments and `e_phoff` is 0.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an ELF32
    ///   header has a value that does not fit in 32 bits.
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if the output
    ///   size overflows or does not fit in memory.
    /// - Return a generic error if the allocation fails.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let header = self.output_header()?;
        let header_bytes = header.to_bytes()?;
        let table = self.program_header_table(header.phentsize)?;
        let mut placements = Vec::with_capacity(self.segments.len() + 2);
        let loads = self.segments.iter().filter(|segment| segment.is_load());
        let others = self
            .segments
            .iter()
            .filter(|segment| !segment.is_load() && !segment.data.is_empty());
        for segment in loads.chain(others) {
            let limit = usize::try_from(segment.header.filesz)
                .map_or(segment.data.len(), |size| size.min(segment.data.len()));
            placements.push(Placement {
                offset: segment.header.offset,
                extent: segment.header.filesz,
                bytes: segment.data.get(..limit).unwrap_or(&segment.data),
            });
        }
        placements.push(Placement::of(0, &header_bytes));
        placements.push(Placement::of(header.phoff, &table));
        write_placements(&placements)
    }

    /// Return the file header of the output file.
    fn output_header(&self) -> Result<FileHeader> {
        let mut header = self.header;
        let count = self.segments.len();
        header.phnum = u16::try_from(count)
            .ok()
            .filter(|phnum| *phnum < PN_XNUM)
            .ok_or_else(|| {
                Error::invalid_header(format!(
                    "{count} program headers need PN_XNUM, and an image without sections has no section header 0"
                ))
            })?;
        if count > 0 {
            let standard = ProgramHeader::standard_size(header.ident.class);
            header.phentsize = header.phentsize.max(standard);
            if header.phoff == 0 {
                return Err(Error::invalid_header(
                    "e_phoff is 0, but the image has program headers",
                ));
            }
        }
        header.shoff = 0;
        header.shnum = 0;
        header.shstrndx = SHN_UNDEF;
        Ok(header)
    }

    /// Serialize the program header table with entries of `entry_size` bytes.
    fn program_header_table(&self, entry_size: u16) -> Result<Vec<u8>> {
        let encoding = self.encoding();
        let entry_size = usize::from(entry_size);
        // `output_header` limits the count to fewer than `PN_XNUM`: the size does not overflow.
        let total = entry_size.saturating_mul(self.segments.len());
        let mut table = Vec::new();
        table
            .try_reserve_exact(total)
            .map_err(|_| Error::generic(format!("cannot allocate {total} bytes")))?;
        for segment in &self.segments {
            let start = table.len();
            segment.header.write(&mut table, encoding)?;
            table.resize(start + entry_size, 0);
        }
        Ok(table)
    }

    /// Write the image to a stream as a raw ELF file without sections.
    ///
    /// # Errors
    ///
    /// Return an error if [`Self::try_build`] fails or the stream write fails.
    pub fn write_to<W: nostdio::Write>(&self, stream: &mut W) -> Result<()> {
        stream.write_all(&self.try_build()?)?;
        Ok(())
    }

    /// Write the image to a file on disk as a raw ELF file without sections.
    ///
    /// # Errors
    ///
    /// Return an error if [`Self::try_build`] fails, the file does not open, or the write
    /// fails.
    #[cfg(feature = "std")]
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.write_to(&mut File::create(path)?)
    }

    /// Check the file header and the program headers for structural problems.
    ///
    /// The image does not know the size of its source file. Thus the checks against the end of
    /// the file do not occur.
    #[must_use]
    pub fn validate(&self) -> ValidationResult {
        let mut result = ValidationResult::new();
        validate_headers(&self.headers(), None, &mut result);
        result
    }
}

impl<'a> Placement<'a> {
    /// Return a placement that covers exactly `bytes`.
    fn of(offset: u64, bytes: &'a [u8]) -> Self {
        Self {
            offset,
            extent: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            bytes,
        }
    }
}

/// Write the placements, in order, to a new zero-filled buffer.
fn write_placements(placements: &[Placement<'_>]) -> Result<Vec<u8>> {
    let too_large = || Error::invalid_segment("the output file size overflows");
    let mut size = 0u64;
    for placement in placements.iter().filter(|placement| placement.extent > 0) {
        let end = placement
            .offset
            .checked_add(placement.extent)
            .ok_or_else(too_large)?;
        size = size.max(end);
    }
    let mut out = zeroed(usize::try_from(size).map_err(|_| too_large())?)?;
    for placement in placements {
        if placement.bytes.is_empty() {
            continue;
        }
        let target = usize::try_from(placement.offset)
            .ok()
            .and_then(|start| out.get_mut(start..start.checked_add(placement.bytes.len())?))
            .ok_or_else(too_large)?;
        target.copy_from_slice(placement.bytes);
    }
    Ok(out)
}
