//! Serialize the headers of an [`ElfFile`] into a copy of the file bytes.

use super::{ElfFile, align_up, overlaps, resolved_phnum, resolved_shnum, table_range};
use crate::header::FileHeader;
use crate::prelude::*;
use crate::program::{PN_XNUM, ProgramHeader, SegmentType};
use crate::section::{SHN_LORESERVE, SectionHeader};
use crate::{Error, Result};
use core::ops::Range;

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::path::Path;

impl ElfFile {
    /// Build the raw file: the data buffer with the current headers.
    ///
    /// The build starts from the data buffer. Then it writes these items:
    ///
    /// 1. The section header table at `e_shoff`, if [`Self::section_headers`] is not empty.
    ///    If the table changed and does not fit in its range, the build moves it to the end of
    ///    the file, aligned to the address size, and changes `e_shoff`. The table does not fit
    ///    if it overlaps the file header, the program header table, a section or a segment.
    /// 2. The program header table at `e_phoff`.
    /// 3. The file header at offset 0.
    ///
    /// The build sets `e_phnum` and `e_shnum` from the lengths of the header lists. It uses
    /// extended numbering for large counts: `e_phnum` is `PN_XNUM` and `sh_info` of section
    /// header 0 holds a count of `PN_XNUM` or more. `e_shnum` is 0 and `sh_size` of section
    /// header 0 holds a count of `SHN_LORESERVE` or more. If the fields already give the
    /// correct count, the build keeps them as they are.
    ///
    /// If [`Self::section_headers`] is empty, the build keeps `e_shoff`, `e_shnum` and
    /// `e_shstrndx`. Thus a section header table that the parser cannot read stays in the
    /// file. To remove the table, set the three fields to 0 with [`Self::header_mut`].
    ///
    /// The build does not change the [`ElfFile`]. When nothing changed after the parse, the
    /// result is equal to the input bytes.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if the file
    ///   has program headers but `e_phoff` is 0, or if a changed program header table overlaps
    ///   the file header, a section, the section header table or a segment that is not
    ///   `PT_LOAD` or `PT_PHDR`.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if a value
    ///   does not fit in its ELF32 field, or if `PN_XNUM` or more program headers need a
    ///   section header 0.
    /// - Return [`ErrorKind::InvalidHeader`](crate::ErrorKind::InvalidHeader) if the program
    ///   header table overlaps the file header or the section header table, and the bytes
    ///   that the build writes for them change the program header entries. An unchanged
    ///   file builds without this error, because its headers come from the same bytes.
    /// - Return a generic error if the output is too large to allocate.
    pub fn try_build(&self) -> Result<Vec<u8>> {
        let class = self.encoding().class;
        let mut header = self.headers.header;
        let mut zero = self.headers.section_headers.first().copied();
        self.encode_counts(&mut header, zero.as_mut())?;
        if !self.headers.program_headers.is_empty()
            && usize::from(header.phentsize) < ProgramHeader::size(class)
        {
            header.phentsize = ProgramHeader::standard_size(class);
        }
        if !self.headers.section_headers.is_empty()
            && usize::from(header.shentsize) < SectionHeader::size(class)
        {
            header.shentsize = SectionHeader::standard_size(class);
        }
        if !self.headers.program_headers.is_empty() && header.phoff == 0 {
            return Err(Error::invalid_segment(
                "the file has program headers, but e_phoff is 0",
            ));
        }
        let program_range = table_range(
            header.phoff,
            self.headers.program_headers.len(),
            header.phentsize,
        );

        let mut out = self.data.clone();
        let section_range =
            self.write_section_table(&mut out, &mut header, zero, &program_range)?;
        self.write_program_table(&mut out, &header, &section_range)?;
        let mut header_bytes = Vec::with_capacity(FileHeader::size(class));
        header.write(&mut header_bytes)?;
        write_bytes(&mut out, 0, &header_bytes)?;
        if overlaps(&self.header_range(), &program_range)
            || overlaps(&section_range, &program_range)
        {
            self.check_program_table(&out, &header)?;
        }
        Ok(out)
    }

    /// Check that `out` holds the program header table at `e_phoff` after the build wrote
    /// the file header and the section header table, which overlap it.
    fn check_program_table(&self, out: &[u8], header: &FileHeader) -> Result<()> {
        let encoding = self.encoding();
        let image = table_image(
            out,
            header.phoff,
            header.phentsize,
            &self.headers.program_headers,
            |_, segment: &ProgramHeader, buffer: &mut Vec<u8>| segment.write(buffer, encoding),
        )?;
        if is_unchanged(out, header.phoff, &image) {
            return Ok(());
        }
        Err(Error::invalid_header(
            "the program header table overlaps the file header or the section header table, and their new bytes change it",
        )
        .at_offset(header.phoff)
        .in_structure("program header table"))
    }

    /// Build the raw file, or panic if the headers are not valid.
    ///
    /// # Panics
    ///
    /// Panic if [`Self::try_build`] returns an error. Use [`Self::try_build`] to handle
    /// invalid headers.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        self.try_build()
            .expect("ElfFile build failed: use try_build() to handle invalid input")
    }

    /// Build the raw file and write it to a `nostdio` stream.
    ///
    /// # Errors
    ///
    /// Return an error if [`Self::try_build`] fails or the write to the stream fails.
    pub fn write_to<W: nostdio::Write>(&self, stream: &mut W) -> Result<()> {
        stream.write_all(&self.try_build()?)?;
        Ok(())
    }

    /// Build the raw file and write it to disk.
    ///
    /// # Errors
    ///
    /// Return an error if [`Self::try_build`] fails, or if the creation of the file or the
    /// write fails.
    #[cfg(feature = "std")]
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.write_to(&mut File::create(path)?)
    }

    /// Set the count fields of `header` and `zero` (section header 0) from the header lists.
    fn encode_counts(
        &self,
        header: &mut FileHeader,
        mut zero: Option<&mut SectionHeader>,
    ) -> Result<()> {
        let raw_zero = zero.as_deref().copied().or_else(|| self.raw_section_zero());
        let phnum = u64::try_from(self.headers.program_headers.len())
            .map_err(|_| Error::value_out_of_range("too many program headers"))?;
        if resolved_phnum(header, raw_zero.as_ref()) != phnum {
            match u16::try_from(phnum) {
                Ok(count) if count < PN_XNUM => {
                    if header.phnum == PN_XNUM
                        && let Some(zero) = zero.as_deref_mut()
                    {
                        zero.info = 0;
                    }
                    header.phnum = count;
                }
                _ => {
                    let zero = zero.as_deref_mut().ok_or_else(|| {
                        Error::value_out_of_range(
                            "PN_XNUM or more program headers need a section header 0",
                        )
                    })?;
                    zero.info = u32::try_from(phnum)
                        .map_err(|_| Error::value_out_of_range("too many program headers"))?;
                    header.phnum = PN_XNUM;
                }
            }
        }

        let Some(zero) = zero else {
            return Ok(());
        };
        let shnum = u64::try_from(self.headers.section_headers.len())
            .map_err(|_| Error::value_out_of_range("too many section headers"))?;
        if resolved_shnum(header, Some(&*zero)) != shnum {
            match u16::try_from(shnum) {
                Ok(count) if count < SHN_LORESERVE => {
                    if header.shnum == 0 {
                        zero.size = 0;
                    }
                    header.shnum = count;
                }
                _ => {
                    header.shnum = 0;
                    zero.size = shnum;
                }
            }
        }
        Ok(())
    }

    /// Read section header 0 at `e_shoff` from the data buffer, as the parser does.
    pub(super) fn raw_section_zero(&self) -> Option<SectionHeader> {
        let header = &self.headers.header;
        if header.shoff == 0 {
            return None;
        }
        let encoding = self.encoding();
        let bytes = self
            .bytes_at(header.shoff, SectionHeader::size(encoding.class))
            .ok()?;
        SectionHeader::parse(bytes, encoding).ok()
    }

    /// Write the section header table into `out` and return its file range.
    ///
    /// Move the table to the end of the file if it changed and does not fit at `e_shoff`.
    fn write_section_table(
        &self,
        out: &mut Vec<u8>,
        header: &mut FileHeader,
        zero: Option<SectionHeader>,
        program_range: &Range<u64>,
    ) -> Result<Range<u64>> {
        let sections = &self.headers.section_headers;
        if sections.is_empty() {
            return Ok(0..0);
        }
        let encoding = self.encoding();
        let write = |index: usize, section: &SectionHeader, buffer: &mut Vec<u8>| {
            let section = if index == 0 {
                zero.unwrap_or(*section)
            } else {
                *section
            };
            section.write(buffer, encoding)
        };
        if header.shoff != 0 {
            let image = table_image(out, header.shoff, header.shentsize, sections, write)?;
            let range = table_range(header.shoff, sections.len(), header.shentsize);
            if is_unchanged(out, header.shoff, &image) {
                return Ok(range);
            }
            if !self.section_table_blocked(&range, program_range) {
                write_bytes(out, header.shoff, &image)?;
                return Ok(range);
            }
        }
        let out_len = u64::try_from(out.len()).unwrap_or(u64::MAX);
        let program_end = if program_range.start <= out_len {
            program_range.end
        } else {
            0
        };
        let end = self.file_end().max(out_len).max(program_end);
        let addr_size = u64::try_from(self.encoding().addr_size()).unwrap_or(8);
        header.shoff = align_up(end, addr_size)?;
        let image = table_image(out, header.shoff, header.shentsize, sections, write)?;
        write_bytes(out, header.shoff, &image)?;
        Ok(table_range(header.shoff, sections.len(), header.shentsize))
    }

    /// Return `true` if a section header table at `range` overlaps the file header, the
    /// program header table, a section or a segment.
    fn section_table_blocked(&self, range: &Range<u64>, program_range: &Range<u64>) -> bool {
        overlaps(&self.header_range(), range)
            || overlaps(program_range, range)
            || self
                .section_ranges(None)
                .chain(self.segment_ranges())
                .any(|used| overlaps(&used, range))
    }

    /// Write the program header table into `out` at `e_phoff`.
    fn write_program_table(
        &self,
        out: &mut Vec<u8>,
        header: &FileHeader,
        section_range: &Range<u64>,
    ) -> Result<()> {
        let segments = &self.headers.program_headers;
        if segments.is_empty() {
            return Ok(());
        }
        let encoding = self.encoding();
        let image = table_image(
            out,
            header.phoff,
            header.phentsize,
            segments,
            |_, segment: &ProgramHeader, buffer: &mut Vec<u8>| segment.write(buffer, encoding),
        )?;
        if is_unchanged(out, header.phoff, &image) {
            return Ok(());
        }
        let range = table_range(header.phoff, segments.len(), header.phentsize);
        let blocked = overlaps(&self.header_range(), &range)
            || overlaps(section_range, &range)
            || self
                .section_ranges(None)
                .any(|used| overlaps(&used, &range))
            || segments
                .iter()
                .filter(|segment| !segment.is_load() && segment.segment_type != SegmentType::PHDR)
                .filter_map(ProgramHeader::file_range)
                .any(|used| overlaps(&used, &range));
        if blocked {
            return Err(Error::invalid_segment(
                "the program header table overlaps other data: use add_load_segment to add a segment",
            )
            .at_offset(header.phoff)
            .in_structure("program header table"));
        }
        write_bytes(out, header.phoff, &image)
    }
}

/// Serialize a header table at file offset `offset`.
///
/// Each entry takes `entry_size` bytes. The function starts from the bytes of `base` in the
/// table range, so that the bytes after each entry structure stay as they are. `write`
/// appends the structure of one entry to a buffer.
fn table_image<T>(
    base: &[u8],
    offset: u64,
    entry_size: u16,
    entries: &[T],
    write: impl Fn(usize, &T, &mut Vec<u8>) -> Result<()>,
) -> Result<Vec<u8>> {
    let stride = usize::from(entry_size);
    let len = entries
        .len()
        .checked_mul(stride)
        .ok_or_else(|| Error::value_out_of_range("the header table is too large"))?;
    let mut image = vec![0u8; len];
    if let Ok(start) = usize::try_from(offset)
        && let Some(current) = base.get(start..)
    {
        let count = current.len().min(len);
        image[..count].copy_from_slice(&current[..count]);
    }
    let mut buffer = Vec::with_capacity(stride);
    for (index, (entry, slot)) in entries
        .iter()
        .zip(image.chunks_exact_mut(stride))
        .enumerate()
    {
        buffer.clear();
        write(index, entry, &mut buffer)?;
        let target = slot
            .get_mut(..buffer.len())
            .ok_or_else(|| Error::value_out_of_range("the header table entry size is too small"))?;
        target.copy_from_slice(&buffer);
    }
    Ok(image)
}

/// Return `true` if `out` already has `image` at file offset `offset`.
fn is_unchanged(out: &[u8], offset: u64, image: &[u8]) -> bool {
    usize::try_from(offset)
        .ok()
        .and_then(|start| out.get(start..start.checked_add(image.len())?))
        == Some(image)
}

/// Copy `bytes` into `out` at file offset `offset`. Extend `out` with zeros if necessary.
fn write_bytes(out: &mut Vec<u8>, offset: u64, bytes: &[u8]) -> Result<()> {
    let too_large = || Error::generic("the output file is too large to allocate");
    let start = usize::try_from(offset).map_err(|_| too_large())?;
    let end = start.checked_add(bytes.len()).ok_or_else(too_large)?;
    if end > out.len() {
        out.try_reserve(end - out.len()).map_err(|_| too_large())?;
        out.resize(end, 0);
    }
    out[start..end].copy_from_slice(bytes);
    Ok(())
}
