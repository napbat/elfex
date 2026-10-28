//! The raw ELF file: [`ElfFile`].
//!
//! [`ElfFile`] keeps all bytes of the file and the parsed [`ElfHeaders`]. Use it to read
//! sections and segments, and to make patchelf-style edits:
//!
//! - Change the data of a section ([`ElfFile::set_section_data`]).
//! - Add or remove a section ([`ElfFile::add_section`], [`ElfFile::remove_section`]).
//! - Add a `PT_LOAD` segment ([`ElfFile::add_load_segment`]).
//! - Change the program interpreter ([`ElfFile::set_interpreter`]).
//!
//! The edits change the data buffer and the headers. [`ElfFile::try_build`] serializes the
//! headers into a copy of the data buffer. When nothing changes, the build returns the input
//! bytes. [`ElfFile::to_image`] gives the loader view ([`ElfImage`](crate::ElfImage)) of
//! the current file.
//!
//! The section accessors read the tables of a relocatable file or of a linked file:
//!
//! - [`ElfFile::symbol_list`] and [`ElfFile::lookup_symbol`] give the static symbols with
//!   their names and sections.
//! - [`ElfFile::relocation_sections`] gives all `SHT_REL` and `SHT_RELA` sections.
//! - [`ElfFile::section_groups`] gives all `SHT_GROUP` sections, for example COMDAT groups.
//! - [`ElfFile::section_data_by_name`] gives the bytes of a named section.
//!
//! # Examples
//!
//! ```
//! use elfex::section::SHF_ALLOC;
//! use elfex::{BuilderSection, ElfBuilder, ElfFile, Encoding, NewSection, SectionType};
//!
//! let bytes = ElfBuilder::new(Encoding::ELF64_LE)
//!     .add_section(BuilderSection::progbits(".rodata", SHF_ALLOC, b"hello\0".to_vec()))
//!     .add_section(BuilderSection::progbits(".comment", 0, b"GCC\0".to_vec()))
//!     .try_build()?
//!     .try_build()?;
//!
//! let mut file = ElfFile::parse(&bytes)?;
//! let comment = file.section_by_name(".comment").expect("the file has .comment").index;
//! file.set_section_data(comment, b"elfex\0".to_vec())?;
//! file.add_section(NewSection::new(".elfex", SectionType::PROGBITS, vec![1, 2, 3]))?;
//! file.set_entry_point(0x40_1000);
//!
//! let edited = ElfFile::parse(&file.try_build()?)?;
//! assert_eq!(edited.section_data_by_name(".comment")?, Some(&b"elfex\0"[..]));
//! assert_eq!(edited.section_data_by_name(".elfex")?, Some(&[1, 2, 3][..]));
//! assert_eq!(edited.entry_point(), 0x40_1000);
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::elf::{ElfHeaders, SourceLayout};
use crate::endian::Encoding;
use crate::header::{FileHeader, FileType, Machine};
use crate::prelude::*;
use crate::program::{PN_XNUM, ProgramHeader};
use crate::reader::{ReadAt, SliceReader};
use crate::section::{SHN_XINDEX, SectionHeader, SectionType};
use crate::validation::ValidationResult;
use crate::{Error, Result};
use core::ops::Range;

#[cfg(feature = "std")]
use std::path::Path;

mod build;
mod edit;
mod linking;
mod tables;
#[cfg(test)]
mod tests;

pub use edit::NewSection;
pub use tables::{RelocationSection, SectionGroup};

/// A raw ELF file that keeps all bytes.
///
/// The type owns the file bytes and the parsed headers. The header accessors give the headers
/// as they are now, with all edits. [`Self::as_bytes`] gives the data buffer, which holds the
/// headers as of the last parse. [`Self::try_build`] writes the current headers into a copy
/// of the buffer.
///
/// The round trip is lossless: for each input that parses, `ElfFile::parse(bytes)?.try_build()?`
/// is equal to `bytes`.
///
/// # Examples
///
/// ```
/// use elfex::section::{SHF_ALLOC, SHF_EXECINSTR};
/// use elfex::{BuilderSection, ElfBuilder, ElfFile, Encoding, Machine, SectionType};
///
/// let bytes = ElfBuilder::new(Encoding::ELF64_LE)
///     .machine(Machine::X86_64)
///     .interpreter("/lib64/ld-linux-x86-64.so.2")
///     .add_section(BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0xc3]))
///     .entry_in_section(".text", 0)
///     .try_build()?
///     .try_build()?;
///
/// let file = ElfFile::parse(&bytes)?;
/// assert_eq!(file.machine(), Machine::X86_64);
/// let text = file.section_by_name(".text").expect("the file has .text");
/// assert_eq!(text.header.section_type, SectionType::PROGBITS);
/// assert_eq!(text.data, [0xc3]);
/// assert_eq!(file.entry_point(), text.header.addr);
/// assert_eq!(file.interpreter()?.as_deref(), Some("/lib64/ld-linux-x86-64.so.2"));
///
/// // The round trip is lossless.
/// assert_eq!(file.try_build()?, bytes);
/// # Ok::<(), elfex::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfFile {
    data: Vec<u8>,
    headers: ElfHeaders,
}

/// A section of an [`ElfFile`]: its index, name, header and file bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SectionRef<'a> {
    /// The index of the section in the section header table.
    pub index: usize,
    /// The section name, or an empty string if the parser cannot read it.
    pub name: &'a str,
    /// The section header (`Elf32_Shdr` or `Elf64_Shdr`).
    pub header: &'a SectionHeader,
    /// The file bytes of the section.
    ///
    /// The slice is empty for a `SHT_NOBITS` or `SHT_NULL` section, and for a section with a
    /// file range outside the file. [`ElfFile::section_data`] reports the error for such a
    /// range.
    pub data: &'a [u8],
}

impl ElfFile {
    /// Parse a raw ELF file from a byte slice. The method copies the bytes.
    ///
    /// # Errors
    ///
    /// Return an error from [`ElfHeaders::read_from`] if the headers do not parse.
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::from_vec(data.to_vec())
    }

    /// Parse a raw ELF file and keep `data` as the data buffer.
    ///
    /// # Errors
    ///
    /// Return an error from [`ElfHeaders::read_from`] if the headers do not parse.
    pub fn from_vec(data: Vec<u8>) -> Result<Self> {
        let headers = ElfHeaders::read_from(&SliceReader::new(&data), 0, SourceLayout::File)?;
        Ok(Self { data, headers })
    }

    /// Read and parse a raw ELF file from a [`ReadAt`] source.
    ///
    /// The file starts at `base_offset` in the source. The method reads from `base_offset` to
    /// the end of the source. Thus the source must report its size.
    ///
    /// # Errors
    ///
    /// - Return a generic error if the source does not report its size.
    /// - Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if
    ///   `base_offset` is past the end of the source.
    /// - Return an error if a read fails or the headers do not parse.
    pub fn read_from<R: ReadAt>(reader: &R, base_offset: u64) -> Result<Self> {
        let source_size = reader
            .size()
            .ok_or_else(|| Error::generic("ElfFile needs a ReadAt source with a known size"))?;
        let length = source_size
            .checked_sub(base_offset)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or_else(|| Error::offset_out_of_bounds(base_offset, source_size))?;
        Self::from_vec(reader.read_bytes_at(base_offset, length)?)
    }

    /// Read and parse a raw ELF file from disk.
    ///
    /// # Errors
    ///
    /// Return an I/O error if the read fails. Return an error if the headers do not parse.
    #[cfg(feature = "std")]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::from_vec(std::fs::read(path)?)
    }

    /// Read and parse a raw ELF file from a sequential `nostdio` stream.
    ///
    /// # Errors
    ///
    /// Return an I/O error if a read from the stream fails. Return an error if the headers do
    /// not parse.
    pub fn from_stream<R: nostdio::Read>(stream: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        Self::from_vec(data)
    }

    /// Return the parsed headers, with all edits.
    #[must_use]
    pub const fn headers(&self) -> &ElfHeaders {
        &self.headers
    }

    /// Return the ELF file header (`Elf32_Ehdr` or `Elf64_Ehdr`).
    #[must_use]
    pub const fn header(&self) -> &FileHeader {
        &self.headers.header
    }

    /// Return the ELF file header for an edit. [`Self::try_build`] serializes the change.
    ///
    /// The build sets the count fields (`e_phnum`, `e_shnum`) from the header lists. It also
    /// sets `e_phoff` and `e_shoff` when a table moves.
    pub fn header_mut(&mut self) -> &mut FileHeader {
        &mut self.headers.header
    }

    /// Return the program headers (`Elf32_Phdr` or `Elf64_Phdr`).
    #[must_use]
    pub fn program_headers(&self) -> &[ProgramHeader] {
        &self.headers.program_headers
    }

    /// Return the program headers for an edit.
    ///
    /// The program header table stays at `e_phoff`. If you add an entry, the table can grow
    /// into bytes that other data uses. Then [`Self::try_build`] fails. To add a `PT_LOAD`
    /// segment, use [`Self::add_load_segment`].
    pub fn program_headers_mut(&mut self) -> &mut Vec<ProgramHeader> {
        &mut self.headers.program_headers
    }

    /// Return the section headers (`Elf32_Shdr` or `Elf64_Shdr`).
    #[must_use]
    pub fn section_headers(&self) -> &[SectionHeader] {
        &self.headers.section_headers
    }

    /// Return the section headers for an edit.
    ///
    /// [`Self::section_names`] does not change when you change the headers with this method.
    pub fn section_headers_mut(&mut self) -> &mut Vec<SectionHeader> {
        &mut self.headers.section_headers
    }

    /// Return the section names. The list has one entry for each section header.
    #[must_use]
    pub fn section_names(&self) -> &[String] {
        &self.headers.section_names
    }

    /// Return the class and the byte order of the file.
    #[must_use]
    pub const fn encoding(&self) -> Encoding {
        self.headers.encoding()
    }

    /// Return `true` for an ELF64 file.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.headers.is_64bit()
    }

    /// Return the object file type (`e_type`).
    #[must_use]
    pub const fn file_type(&self) -> FileType {
        self.headers.file_type()
    }

    /// Return the target architecture (`e_machine`).
    #[must_use]
    pub const fn machine(&self) -> Machine {
        self.headers.machine()
    }

    /// Return the virtual address of the entry point (`e_entry`).
    #[must_use]
    pub const fn entry_point(&self) -> u64 {
        self.headers.entry_point()
    }

    /// Set the virtual address of the entry point (`e_entry`).
    pub fn set_entry_point(&mut self, entry: u64) {
        self.headers.header.entry = entry;
    }

    /// Return the data buffer.
    ///
    /// The buffer holds the section and segment data with all edits. The header bytes in the
    /// buffer are as of the last parse. Use [`Self::try_build`] to get the file with the
    /// current headers.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return the data buffer for an edit. The length of the buffer cannot change.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Return the length of the data buffer in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the data buffer is empty. A parsed file always has a header, so the
    /// result is `false`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the section at `index`, or `None` if the index is out of range.
    #[must_use]
    pub fn section(&self, index: usize) -> Option<SectionRef<'_>> {
        let header = self.headers.section_headers.get(index)?;
        Some(SectionRef {
            index,
            name: self
                .headers
                .section_names
                .get(index)
                .map_or("", String::as_str),
            header,
            data: self.section_bytes(header).unwrap_or(&[]),
        })
    }

    /// Iterate over all sections in section header order.
    pub fn sections(&self) -> impl Iterator<Item = SectionRef<'_>> {
        (0..self.headers.section_headers.len()).filter_map(|index| self.section(index))
    }

    /// Return the first section named `name`.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<SectionRef<'_>> {
        let (index, _) = self.headers.section_by_name(name)?;
        self.section(index)
    }

    /// Return the first section of `section_type`.
    #[must_use]
    pub fn section_by_type(&self, section_type: SectionType) -> Option<SectionRef<'_>> {
        let (index, _) = self.headers.section_by_type(section_type)?;
        self.section(index)
    }

    /// Return the file bytes of the section at `index`.
    ///
    /// The slice is empty for a `SHT_NOBITS` or `SHT_NULL` section.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) if `index`
    ///   is out of range.
    /// - Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    ///   file range of the section is outside the file.
    pub fn section_data(&self, index: usize) -> Result<&[u8]> {
        let header = self.section_header(index)?;
        self.section_bytes(header)
            .map_err(|error| error.in_structure("section data"))
    }

    /// Return the file bytes of the section at `index` for an edit.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::section_data`].
    pub fn section_data_mut(&mut self, index: usize) -> Result<&mut [u8]> {
        let header = *self.section_header(index)?;
        if !header.has_file_data() {
            return Ok(&mut []);
        }
        let range = self
            .data_range(header.offset, header.size)
            .map_err(|error| error.in_structure("section data"))?;
        Ok(&mut self.data[range])
    }

    /// Return the file bytes of the segment of program header `index`: `p_filesz` bytes at
    /// file offset `p_offset`.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if `index`
    ///   is out of range.
    /// - Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    ///   file range of the segment is outside the file.
    pub fn segment_data(&self, index: usize) -> Result<&[u8]> {
        let header = self.headers.program_headers.get(index).ok_or_else(|| {
            Error::invalid_segment(format!("program header index {index} is out of range"))
        })?;
        let range = self
            .data_range(header.offset, header.filesz)
            .map_err(|error| error.in_structure("segment data"))?;
        Ok(&self.data[range])
    }

    /// Return `len` bytes at file offset `offset`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    /// range is outside the file.
    pub fn bytes_at(&self, offset: u64, len: usize) -> Result<&[u8]> {
        let range = self.data_range(offset, u64::try_from(len).unwrap_or(u64::MAX))?;
        Ok(&self.data[range])
    }

    /// Return `len` bytes at file offset `offset` for an edit.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    /// range is outside the file.
    pub fn bytes_at_mut(&mut self, offset: u64, len: usize) -> Result<&mut [u8]> {
        let range = self.data_range(offset, u64::try_from(len).unwrap_or(u64::MAX))?;
        Ok(&mut self.data[range])
    }

    /// Return `len` file bytes at virtual address `vaddr`.
    ///
    /// The range must be in the file bytes (`p_filesz`) of one `PT_LOAD` segment. The
    /// zero-filled tail of a segment has no file bytes.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no
    ///   `PT_LOAD` segment has the full range in its file bytes.
    /// - Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    ///   segment goes past the end of the file.
    pub fn read_vaddr(&self, vaddr: u64, len: usize) -> Result<&[u8]> {
        let range = self.vaddr_range(vaddr, len)?;
        Ok(&self.data[range])
    }

    /// Return the file bytes from virtual address `vaddr` to the end of the file bytes of its
    /// `PT_LOAD` segment.
    ///
    /// If the segment goes past the end of the file, the slice stops at the end of the file.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no `PT_LOAD`
    /// segment has file bytes at `vaddr`, or if the address is past the end of the file.
    pub fn slice_from_vaddr(&self, vaddr: u64) -> Result<&[u8]> {
        let (offset, available) = self.vaddr_location(vaddr)?;
        let start = usize::try_from(offset)
            .ok()
            .filter(|start| *start < self.data.len())
            .ok_or_else(|| Error::invalid_address(vaddr))?;
        let rest = &self.data[start..];
        let len = usize::try_from(available).map_or(rest.len(), |len| len.min(rest.len()));
        Ok(&rest[..len])
    }

    /// Write `bytes` at virtual address `vaddr`.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::read_vaddr`].
    pub fn write_vaddr(&mut self, vaddr: u64, bytes: &[u8]) -> Result<()> {
        let range = self.vaddr_range(vaddr, bytes.len())?;
        self.data[range].copy_from_slice(bytes);
        Ok(())
    }

    /// Check the headers against the file and return all issues.
    #[must_use]
    pub fn validate(&self) -> ValidationResult {
        let mut result = ValidationResult::new();
        crate::elf::validate::validate_headers(&self.headers, Some(self.file_size()), &mut result);
        result
    }

    /// Return the section header at `index`, or an `InvalidSection` error.
    fn section_header(&self, index: usize) -> Result<&SectionHeader> {
        self.headers
            .section_headers
            .get(index)
            .ok_or_else(|| Error::invalid_section(format!("section index {index} is out of range")))
    }

    /// Return the section header at `index` for an edit, or an `InvalidSection` error.
    fn section_header_mut(&mut self, index: usize) -> Result<&mut SectionHeader> {
        self.headers
            .section_headers
            .get_mut(index)
            .ok_or_else(|| Error::invalid_section(format!("section index {index} is out of range")))
    }

    /// Return the file bytes of a section, or an empty slice if it has no file bytes.
    fn section_bytes(&self, header: &SectionHeader) -> Result<&[u8]> {
        if !header.has_file_data() {
            return Ok(&[]);
        }
        let range = self.data_range(header.offset, header.size)?;
        Ok(&self.data[range])
    }

    /// Return the length of the data buffer as `u64`.
    fn file_size(&self) -> u64 {
        u64::try_from(self.data.len()).unwrap_or(u64::MAX)
    }

    /// Convert a file range to an index range in the data buffer.
    fn data_range(&self, offset: u64, len: u64) -> Result<Range<usize>> {
        let out_of_bounds = || Error::offset_out_of_bounds(offset, self.file_size());
        let end = offset.checked_add(len).ok_or_else(out_of_bounds)?;
        let start = usize::try_from(offset).map_err(|_| out_of_bounds())?;
        let end = usize::try_from(end).map_err(|_| out_of_bounds())?;
        if end > self.data.len() {
            return Err(out_of_bounds());
        }
        Ok(start..end)
    }

    /// Find the `PT_LOAD` segment with file bytes at `vaddr`. Return the file offset of
    /// `vaddr` and the number of segment file bytes from `vaddr` to the end of the segment.
    fn vaddr_location(&self, vaddr: u64) -> Result<(u64, u64)> {
        self.headers
            .load_segments()
            .find_map(|segment| {
                let delta = vaddr.checked_sub(segment.vaddr)?;
                if delta >= segment.filesz {
                    return None;
                }
                Some((segment.offset.checked_add(delta)?, segment.filesz - delta))
            })
            .ok_or_else(|| Error::invalid_address(vaddr))
    }

    /// Convert a virtual address range in the file bytes of one `PT_LOAD` segment to an index
    /// range in the data buffer.
    fn vaddr_range(&self, vaddr: u64, len: usize) -> Result<Range<usize>> {
        let (offset, available) = self.vaddr_location(vaddr)?;
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        if len > available {
            return Err(Error::invalid_address(vaddr));
        }
        self.data_range(offset, len)
            .map_err(|error| error.at_address(vaddr))
    }

    /// Return the index of the section name string table, resolved as the parser does: an
    /// `e_shstrndx` of `SHN_XINDEX` takes the index from `sh_link` of section header 0.
    fn shstrndx(&self) -> Option<usize> {
        let index = match (
            self.headers.header.shstrndx,
            self.headers.section_headers.first(),
        ) {
            (SHN_XINDEX, Some(zero)) => zero.link,
            (index, _) => u32::from(index),
        };
        usize::try_from(index).ok()
    }

    /// Return the file ranges of the sections with file bytes, except `exclude`.
    fn section_ranges(&self, exclude: Option<usize>) -> impl Iterator<Item = Range<u64>> {
        self.headers
            .section_headers
            .iter()
            .enumerate()
            .filter(move |(index, _)| Some(*index) != exclude)
            .filter_map(|(_, header)| header.file_range())
            .filter(|range| !range.is_empty())
    }

    /// Return the file ranges of the segments with file bytes.
    fn segment_ranges(&self) -> impl Iterator<Item = Range<u64>> {
        self.headers
            .program_headers
            .iter()
            .filter_map(ProgramHeader::file_range)
            .filter(|range| !range.is_empty())
    }

    /// Return the file range of the ELF file header.
    fn header_range(&self) -> Range<u64> {
        0..u64::try_from(FileHeader::size(self.encoding().class)).unwrap_or(u64::MAX)
    }

    /// Return the file range of the program header table, or an empty range.
    fn program_table_range(&self) -> Range<u64> {
        let header = &self.headers.header;
        table_range(
            header.phoff,
            self.headers.program_headers.len(),
            header.phentsize,
        )
    }

    /// Return the file range of the section header table, or an empty range.
    fn section_table_range(&self) -> Range<u64> {
        let header = &self.headers.header;
        table_range(
            header.shoff,
            self.headers.section_headers.len(),
            header.shentsize,
        )
    }

    /// Return the file range of the section header table that `e_shoff`, `e_shnum` and
    /// `e_shentsize` give, or an empty range. The end is `u64::MAX` if it overflows.
    ///
    /// The range is also known when the parser cannot read the table. The build keeps such a
    /// table in the file, so the edits must not write over it.
    fn raw_section_table_range(&self) -> Range<u64> {
        let header = &self.headers.header;
        if header.shoff == 0 {
            return 0..0;
        }
        let zero = self
            .headers
            .section_headers
            .first()
            .copied()
            .or_else(|| self.raw_section_zero());
        let end = resolved_shnum(header, zero.as_ref())
            .checked_mul(u64::from(header.shentsize))
            .and_then(|table_size| header.shoff.checked_add(table_size))
            .unwrap_or(u64::MAX);
        header.shoff..end
    }

    /// Return [`Self::raw_section_table_range`] clamped to the end of the file.
    fn raw_section_table_in_file(&self) -> Range<u64> {
        let size = self.file_size();
        let range = self.raw_section_table_range();
        range.start.min(size)..range.end.min(size)
    }

    /// Return the end of all data in the file: the end of the data buffer, or a larger end
    /// of a header table that starts in the file.
    ///
    /// A header table can go past the end of the data buffer after an edit adds entries.
    /// Sections and segments do not change the result: the part of a file range past the end
    /// of the data buffer holds no data, and a range with a bad offset must not make the
    /// file larger.
    fn file_end(&self) -> u64 {
        let size = self.file_size();
        [self.program_table_range(), self.section_table_range()]
            .into_iter()
            .filter(|range| range.start <= size)
            .map(|range| range.end)
            .fold(size, u64::max)
    }

    /// Return `true` if `range` overlaps a section other than `exclude`, a segment or a
    /// header table.
    fn range_is_used(&self, range: &Range<u64>, exclude: Option<usize>) -> bool {
        self.section_ranges(exclude)
            .chain(self.segment_ranges())
            .chain([
                self.header_range(),
                self.program_table_range(),
                self.section_table_range(),
                self.raw_section_table_in_file(),
            ])
            .any(|used| overlaps(&used, range))
    }
}

/// Return the file range of a header table with `count` entries of `entry_size` bytes at
/// `offset`, or an empty range if the table is absent or the end overflows.
fn table_range(offset: u64, count: usize, entry_size: u16) -> Range<u64> {
    let size = u64::try_from(count)
        .ok()
        .and_then(|count| count.checked_mul(u64::from(entry_size)));
    match size.and_then(|size| offset.checked_add(size)) {
        Some(end) if offset != 0 => offset..end,
        _ => 0..0,
    }
}

/// Return `true` if two non-empty ranges overlap.
fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

/// Round `value` up to a multiple of `align`. An alignment of 0 or 1 means no alignment.
fn align_up(value: u64, align: u64) -> Result<u64> {
    if align <= 1 {
        return Ok(value);
    }
    value
        .checked_next_multiple_of(align)
        .ok_or_else(|| Error::value_out_of_range(format!("the offset {value:#x} overflows")))
}

/// Return the program header count that the parser reads with `header`.
///
/// `zero` is section header 0. An `e_phoff` of 0 gives no program headers. An `e_phnum` of
/// `PN_XNUM` takes the count from `sh_info` of section header 0, if it is not 0.
fn resolved_phnum(header: &FileHeader, zero: Option<&SectionHeader>) -> u64 {
    if header.phoff == 0 {
        return 0;
    }
    match (header.phnum, zero) {
        (PN_XNUM, Some(zero)) if zero.info != 0 => u64::from(zero.info),
        (phnum, _) => u64::from(phnum),
    }
}

/// Return the section header count that the parser reads with `header`.
///
/// `zero` is section header 0. An `e_shoff` of 0 gives no section headers. An `e_shnum` of
/// 0 takes the count from `sh_size` of section header 0.
fn resolved_shnum(header: &FileHeader, zero: Option<&SectionHeader>) -> u64 {
    if header.shoff == 0 {
        return 0;
    }
    match (header.shnum, zero) {
        (0, Some(zero)) => zero.size,
        (shnum, _) => u64::from(shnum),
    }
}

/// Read the null-terminated string at `offset` in a string table, as lossy UTF-8. Return an
/// empty string if the offset is out of range.
fn string_at(table: &[u8], offset: u32) -> String {
    let Some(bytes) = usize::try_from(offset)
        .ok()
        .and_then(|offset| table.get(offset..))
    else {
        return String::new();
    };
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
