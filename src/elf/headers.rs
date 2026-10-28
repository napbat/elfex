//! Parse [`ElfHeaders`] and translate addresses with the program headers.

use super::validate::validate_headers;
use super::{ElfHeaders, MAX_UNSIZED_TABLE_ENTRIES, SourceLayout};
use crate::endian::Encoding;
use crate::header::{FileHeader, FileType, Machine};
use crate::ident::{EI_NIDENT, Ident};
use crate::prelude::*;
use crate::program::{PN_XNUM, ProgramHeader, SegmentType};
use crate::reader::{ReadAt, SliceReader};
use crate::section::{SHN_XINDEX, SectionHeader, SectionType};
use crate::validation::ValidationResult;
use crate::{Error, Result};

#[cfg(feature = "std")]
use crate::reader::FileReader;
#[cfg(feature = "std")]
use std::path::Path;

/// The maximum number of bytes in a header table that the parser reads from a source with an
/// unknown size: [`MAX_UNSIZED_TABLE_ENTRIES`] entries of 64 bytes.
const MAX_UNSIZED_TABLE_BYTES: u64 = MAX_UNSIZED_TABLE_ENTRIES * 64;

/// The maximum size of the section name string table that the parser reads from a source with
/// an unknown size (16 MiB).
const MAX_UNSIZED_NAME_TABLE_BYTES: u64 = 16 << 20;

/// The resolved table counts and the section name table index.
struct TableCounts {
    phnum: u64,
    shnum: u64,
    shstrndx: u32,
    section_zero: Option<SectionHeader>,
}

impl ElfHeaders {
    /// Parse the headers of a raw ELF file in a byte slice.
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from`].
    pub fn from_slice(data: &[u8]) -> Result<Self> {
        Self::read_from(&SliceReader::new(data), 0, SourceLayout::File)
    }

    /// Parse the headers of a loader-mapped ELF image in a byte slice.
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from`].
    pub fn from_mapped_slice(data: &[u8]) -> Result<Self> {
        Self::read_from(&SliceReader::new(data), 0, SourceLayout::Mapped)
    }

    /// Parse the headers of an ELF file on disk.
    ///
    /// # Errors
    ///
    /// Return an I/O error if the file does not open. Return an error for any condition listed
    /// on [`Self::read_from`].
    #[cfg(feature = "std")]
    #[must_use = "loading returns ELF headers that should be used"]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = FileReader::open(path)?;
        Self::read_from(&reader, 0, SourceLayout::File)
    }

    /// Parse the headers from a source. The ELF header is at `base_offset` in the source.
    ///
    /// In the file layout, the program header table and the section header table are at their
    /// file offsets from `base_offset`. In the mapped layout, the parser reads the program
    /// header table at `e_phoff` from the image origin, because the first `PT_LOAD` segment
    /// maps the start of the file. It reads the section header table only if a `PT_LOAD`
    /// segment maps it.
    ///
    /// The parser does not fail on a section header table that it cannot read. Then
    /// [`Self::section_headers`] is empty, and the file header keeps its values.
    ///
    /// For a source with an unknown size, the parser reads a header table only if it has at
    /// most [`MAX_UNSIZED_TABLE_ENTRIES`] entries and at most 64 MiB. It reads the section
    /// name string table only if it is at most 16 MiB. Otherwise, the section names are empty.
    ///
    /// # Errors
    ///
    /// - Return an error from [`FileHeader::parse`] for bad identification or header bytes.
    /// - Return [`ErrorKind::InvalidHeader`](crate::ErrorKind::InvalidHeader) if
    ///   `e_phentsize` is smaller than the program header structure.
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if the program
    ///   header table is too large or the parser cannot read it.
    pub fn read_from<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        layout: SourceLayout,
    ) -> Result<Self> {
        let mut ident_bytes = [0u8; EI_NIDENT];
        reader.read_exact_at(base_offset, &mut ident_bytes)?;
        let ident = Ident::parse(&ident_bytes)?;
        let header_size = FileHeader::size(ident.class);
        let header_bytes = reader
            .read_bytes_at(base_offset, header_size)
            .map_err(|error| error.in_structure("ELF header"))?;
        let header = FileHeader::parse(&header_bytes)?;
        let encoding = header.encoding();

        let section_zero = read_section_zero(reader, base_offset, &header, layout, encoding);
        let counts = resolve_counts(&header, section_zero);

        let program_headers = read_program_headers(reader, base_offset, &header, counts.phnum)?;
        let mut headers = Self {
            header,
            program_headers,
            section_headers: Vec::new(),
            section_names: Vec::new(),
        };
        if let Some(section_headers) =
            headers.read_section_headers(reader, base_offset, layout, &counts)
        {
            headers.section_headers = section_headers;
            headers.section_names =
                headers.read_section_names(reader, base_offset, layout, counts.shstrndx);
        }
        Ok(headers)
    }

    /// Read the section header table, or return `None` if it is absent or unreadable.
    fn read_section_headers<R: ReadAt>(
        &self,
        reader: &R,
        base_offset: u64,
        layout: SourceLayout,
        counts: &TableCounts,
    ) -> Option<Vec<SectionHeader>> {
        if self.header.shoff == 0 || counts.shnum == 0 {
            return None;
        }
        let encoding = self.encoding();
        let entry_size = usize::from(self.header.shentsize);
        if entry_size < SectionHeader::size(encoding.class) {
            return None;
        }
        let table_size = counts.shnum.checked_mul(u64::from(self.header.shentsize))?;
        let source_offset =
            self.file_range_to_source_offset(self.header.shoff, table_size, layout)?;
        let bytes = read_table(reader, base_offset, source_offset, counts.shnum, table_size)?;
        let mut section_headers: Vec<SectionHeader> = bytes
            .chunks_exact(entry_size)
            .map(|chunk| SectionHeader::parse(chunk, encoding))
            .collect::<Result<_>>()
            .ok()?;
        if let (Some(first), Some(zero)) = (section_headers.first_mut(), counts.section_zero) {
            *first = zero;
        }
        Some(section_headers)
    }

    /// Read the section names, or return empty names if the string table is unreadable, or
    /// if it is larger than [`MAX_UNSIZED_NAME_TABLE_BYTES`] in a source with an unknown size.
    fn read_section_names<R: ReadAt>(
        &self,
        reader: &R,
        base_offset: u64,
        layout: SourceLayout,
        shstrndx: u32,
    ) -> Vec<String> {
        let count = self.section_headers.len();
        let table = usize::try_from(shstrndx)
            .ok()
            .and_then(|index| self.section_headers.get(index))
            .filter(|header| index_is_string_table(header))
            .and_then(|header| {
                let source =
                    self.file_range_to_source_offset(header.offset, header.size, layout)?;
                let absolute = base_offset.checked_add(source)?;
                read_bounded(reader, absolute, header.size, MAX_UNSIZED_NAME_TABLE_BYTES)
            });
        let Some(table) = table else {
            return vec![String::new(); count];
        };
        self.section_headers
            .iter()
            .map(|header| string_at(&table, header.name))
            .collect()
    }

    /// Translate a file range to a source offset in `layout`, or return `None` if no segment
    /// maps the full range in the mapped layout.
    fn file_range_to_source_offset(
        &self,
        offset: u64,
        size: u64,
        layout: SourceLayout,
    ) -> Option<u64> {
        match layout {
            SourceLayout::File => Some(offset),
            SourceLayout::Mapped => {
                let end = offset.checked_add(size)?;
                let segment = self.load_segments().find(|segment| {
                    segment
                        .file_range()
                        .is_some_and(|range| range.start <= offset && end <= range.end)
                })?;
                let vaddr = segment.vaddr.checked_add(offset - segment.offset)?;
                vaddr.checked_sub(self.image_origin()?)
            }
        }
    }

    /// Return the class and the byte order of the file.
    #[must_use]
    pub const fn encoding(&self) -> Encoding {
        self.header.encoding()
    }

    /// Return `true` for an ELF64 file.
    #[must_use]
    pub const fn is_64bit(&self) -> bool {
        self.header.encoding().is_64bit()
    }

    /// Return the object file type (`e_type`).
    #[must_use]
    pub const fn file_type(&self) -> FileType {
        self.header.file_type
    }

    /// Return the target architecture (`e_machine`).
    #[must_use]
    pub const fn machine(&self) -> Machine {
        self.header.machine
    }

    /// Return the virtual address of the entry point (`e_entry`).
    #[must_use]
    pub const fn entry_point(&self) -> u64 {
        self.header.entry
    }

    /// Iterate over the `PT_LOAD` program headers.
    pub fn load_segments(&self) -> impl Iterator<Item = &ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|header| header.is_load())
    }

    /// Return the first program header of `segment_type`.
    #[must_use]
    pub fn segment(&self, segment_type: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .find(|header| header.segment_type == segment_type)
    }

    /// Return the index and the header of the first section named `name`.
    #[must_use]
    pub fn section_by_name(&self, name: &str) -> Option<(usize, &SectionHeader)> {
        let index = self
            .section_names
            .iter()
            .position(|candidate| candidate == name)?;
        Some((index, self.section_headers.get(index)?))
    }

    /// Return the index and the header of the first section of `section_type`.
    #[must_use]
    pub fn section_by_type(&self, section_type: SectionType) -> Option<(usize, &SectionHeader)> {
        self.section_headers
            .iter()
            .enumerate()
            .find(|(_, header)| header.section_type == section_type)
    }

    /// Return the image origin: the virtual address of file offset 0 in the `PT_LOAD` segment
    /// with the lowest virtual address.
    ///
    /// Source offset 0 of a mapped image is at this address. Return `None` if the file has no
    /// `PT_LOAD` segment, or if that segment has a file offset larger than its address.
    #[must_use]
    pub fn image_origin(&self) -> Option<u64> {
        let first = self.load_segments().min_by_key(|segment| segment.vaddr)?;
        first.vaddr.checked_sub(first.offset)
    }

    /// Return the end of the highest `PT_LOAD` memory range, or `None` if the file has no
    /// `PT_LOAD` segment or an end overflows.
    #[must_use]
    pub fn image_end(&self) -> Option<u64> {
        self.load_segments()
            .map(|segment| segment.memory_range().map(|range| range.end))
            .try_fold(None, |max: Option<u64>, end| {
                let end = end?;
                Some(Some(max.map_or(end, |max| max.max(end))))
            })?
    }

    /// Return the size of the mapped image: from the image origin to the end of the highest
    /// `PT_LOAD` memory range.
    #[must_use]
    pub fn mapped_size(&self) -> Option<u64> {
        self.image_end()?.checked_sub(self.image_origin()?)
    }

    /// Translate a virtual address to a file offset through the `PT_LOAD` segments.
    ///
    /// Return `None` if no segment has file bytes at `vaddr`. An address in the zero-filled
    /// tail of a segment (after `p_filesz`) has no file offset.
    #[must_use]
    pub fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<u64> {
        self.load_segments().find_map(|segment| {
            let delta = vaddr.checked_sub(segment.vaddr)?;
            (delta < segment.filesz).then(|| segment.offset.checked_add(delta))?
        })
    }

    /// Translate a file offset to a virtual address through the `PT_LOAD` segments.
    ///
    /// Return `None` if no segment maps the file offset.
    #[must_use]
    pub fn file_offset_to_vaddr(&self, offset: u64) -> Option<u64> {
        self.load_segments().find_map(|segment| {
            let delta = offset.checked_sub(segment.offset)?;
            (delta < segment.filesz).then(|| segment.vaddr.checked_add(delta))?
        })
    }

    /// Translate a virtual address to an offset in a source of `layout`.
    ///
    /// In the file layout, this is [`Self::vaddr_to_file_offset`]. In the mapped layout, the
    /// address must be in the memory range of a `PT_LOAD` segment, and the result is the
    /// address minus the image origin.
    #[must_use]
    pub fn vaddr_to_source_offset(&self, vaddr: u64, layout: SourceLayout) -> Option<u64> {
        match layout {
            SourceLayout::File => self.vaddr_to_file_offset(vaddr),
            SourceLayout::Mapped => {
                if !self
                    .load_segments()
                    .any(|segment| segment.contains_vaddr(vaddr))
                {
                    return None;
                }
                vaddr.checked_sub(self.image_origin()?)
            }
        }
    }

    /// Check the file header, the program headers and the section headers, and return all
    /// issues.
    ///
    /// `file_size` is the size of the raw file. With `None`, the checks against the end of the
    /// file do not occur: use `None` for headers from a loader-mapped image.
    /// [`ElfFile::validate`](crate::ElfFile::validate) and
    /// [`ElfImage::validate`](crate::ElfImage::validate) make the same checks.
    ///
    /// # Examples
    ///
    /// ```
    /// use elfex::{BuilderSection, ElfBuilder, ElfHeaders, Encoding};
    ///
    /// let bytes = ElfBuilder::new(Encoding::ELF64_LE)
    ///     .add_section(BuilderSection::progbits(".comment", 0, b"elfex\0".to_vec()))
    ///     .try_build()?
    ///     .try_build()?;
    /// let headers = ElfHeaders::from_slice(&bytes)?;
    /// let size = u64::try_from(bytes.len()).expect("the size fits in u64");
    /// assert!(headers.validate(Some(size)).is_ok());
    /// // The section header table is past the end of a shorter file.
    /// assert!(headers.validate(Some(size / 2)).has_errors());
    /// # Ok::<(), elfex::Error>(())
    /// ```
    #[must_use]
    pub fn validate(&self, file_size: Option<u64>) -> ValidationResult {
        let mut result = ValidationResult::new();
        validate_headers(self, file_size, &mut result);
        result
    }
}

/// Return `true` if a section header can hold section names.
fn index_is_string_table(header: &SectionHeader) -> bool {
    header.section_type == SectionType::STRTAB
}

/// Read the null-terminated string at `offset` in a string table, as lossy UTF-8.
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

/// Read section header 0, which holds the extended counts. Return `None` if it is unreadable.
fn read_section_zero<R: ReadAt>(
    reader: &R,
    base_offset: u64,
    header: &FileHeader,
    layout: SourceLayout,
    encoding: Encoding,
) -> Option<SectionHeader> {
    // Extended numbering applies only to a file layout source: a mapped image usually does
    // not contain the section header table.
    let needs_extended =
        header.shnum == 0 || header.shstrndx == SHN_XINDEX || header.phnum == PN_XNUM;
    if header.shoff == 0 || layout != SourceLayout::File || !needs_extended {
        return None;
    }
    let offset = base_offset.checked_add(header.shoff)?;
    let bytes = reader
        .read_bytes_at(offset, SectionHeader::size(encoding.class))
        .ok()?;
    SectionHeader::parse(&bytes, encoding).ok()
}

/// Resolve the extended numbering of `e_phnum`, `e_shnum` and `e_shstrndx`.
fn resolve_counts(header: &FileHeader, section_zero: Option<SectionHeader>) -> TableCounts {
    let phnum = match (header.phnum, section_zero) {
        (PN_XNUM, Some(zero)) if zero.info != 0 => u64::from(zero.info),
        (phnum, _) => u64::from(phnum),
    };
    let shnum = match (header.shnum, section_zero) {
        (0, Some(zero)) => zero.size,
        (shnum, _) => u64::from(shnum),
    };
    let shstrndx = match (header.shstrndx, section_zero) {
        (SHN_XINDEX, Some(zero)) => zero.link,
        (shstrndx, _) => u32::from(shstrndx),
    };
    TableCounts {
        phnum,
        shnum,
        shstrndx,
        section_zero,
    }
}

/// Read the program header table.
fn read_program_headers<R: ReadAt>(
    reader: &R,
    base_offset: u64,
    header: &FileHeader,
    phnum: u64,
) -> Result<Vec<ProgramHeader>> {
    if phnum == 0 || header.phoff == 0 {
        return Ok(Vec::new());
    }
    let encoding = header.encoding();
    let entry_size = usize::from(header.phentsize);
    if entry_size < ProgramHeader::size(encoding.class) {
        return Err(Error::invalid_header(format!(
            "e_phentsize {} is smaller than the program header structure",
            header.phentsize
        )));
    }
    // `phnum` is at most `u32::MAX` and `e_phentsize` is a `u16`: the product fits in 64 bits.
    let table_size = phnum.saturating_mul(u64::from(header.phentsize));
    let bytes =
        read_table(reader, base_offset, header.phoff, phnum, table_size).ok_or_else(|| {
            Error::invalid_segment("the program header table is outside the source")
                .at_offset(header.phoff)
                .in_structure("program header table")
        })?;
    bytes
        .chunks_exact(entry_size)
        .map(|chunk| ProgramHeader::parse(chunk, encoding))
        .collect()
}

/// Read a header table of `count` entries and `size` bytes at `offset` from `base_offset`.
///
/// Return `None` if the table is outside a source with a known size, if a source with an
/// unknown size would need more than [`MAX_UNSIZED_TABLE_ENTRIES`] entries or more than
/// [`MAX_UNSIZED_TABLE_BYTES`] bytes, or if the read fails.
fn read_table<R: ReadAt>(
    reader: &R,
    base_offset: u64,
    offset: u64,
    count: u64,
    size: u64,
) -> Option<Vec<u8>> {
    if reader.size().is_none() && count > MAX_UNSIZED_TABLE_ENTRIES {
        return None;
    }
    read_bounded(
        reader,
        base_offset.checked_add(offset)?,
        size,
        MAX_UNSIZED_TABLE_BYTES,
    )
}

/// Read `size` bytes at `absolute`.
///
/// Return `None` if the range is outside a source with a known size, if a source with an
/// unknown size would need more than `unsized_limit` bytes, or if the read fails.
fn read_bounded<R: ReadAt>(
    reader: &R,
    absolute: u64,
    size: u64,
    unsized_limit: u64,
) -> Option<Vec<u8>> {
    match reader.size() {
        Some(source_size) => {
            if absolute > source_size || size > source_size - absolute {
                return None;
            }
        }
        None => {
            if size > unsized_limit {
                return None;
            }
        }
    }
    reader
        .read_bytes_at(absolute, usize::try_from(size).ok()?)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::FileType;
    use crate::program::{PF_R, PF_X};
    use crate::section::SHF_ALLOC;
    use core::cell::Cell;

    /// Build a small ELF64 file: header, two program headers, three sections and the section
    /// name string table.
    fn sample(encoding: Encoding) -> Vec<u8> {
        let mut header = FileHeader::new(encoding, FileType::DYN, Machine::X86_64);
        let header_size = FileHeader::size(encoding.class);
        let ph_size = ProgramHeader::size(encoding.class);
        let sh_size = SectionHeader::size(encoding.class);
        header.phoff = u64::try_from(header_size).unwrap();
        header.phnum = 1;
        let names = b"\0.text\0.shstrtab\0";
        let text_offset = header_size + ph_size;
        let names_offset = text_offset + 16;
        let shoff = names_offset + names.len();
        header.shoff = u64::try_from(shoff).unwrap();
        header.shnum = 3;
        header.shstrndx = 2;
        header.entry = 0x1000 + u64::try_from(text_offset).unwrap();

        let mut out = header.to_bytes().unwrap();
        ProgramHeader {
            segment_type: SegmentType::LOAD,
            flags: PF_R | PF_X,
            offset: 0,
            vaddr: 0x1000,
            paddr: 0x1000,
            filesz: u64::try_from(names_offset).unwrap(),
            memsz: u64::try_from(names_offset).unwrap(),
            align: 0x1000,
        }
        .write(&mut out, encoding)
        .unwrap();
        out.extend_from_slice(&[0xcc; 16]);
        out.extend_from_slice(names);
        SectionHeader::default().write(&mut out, encoding).unwrap();
        SectionHeader {
            name: 1,
            section_type: SectionType::PROGBITS,
            flags: SHF_ALLOC,
            addr: 0x1000 + u64::try_from(text_offset).unwrap(),
            offset: u64::try_from(text_offset).unwrap(),
            size: 16,
            ..SectionHeader::default()
        }
        .write(&mut out, encoding)
        .unwrap();
        SectionHeader {
            name: 7,
            section_type: SectionType::STRTAB,
            offset: u64::try_from(names_offset).unwrap(),
            size: u64::try_from(names.len()).unwrap(),
            ..SectionHeader::default()
        }
        .write(&mut out, encoding)
        .unwrap();
        assert_eq!(out.len(), shoff + 3 * sh_size);
        out
    }

    #[test]
    fn parses_headers_and_names() {
        for encoding in [Encoding::ELF64_LE, Encoding::ELF32_BE] {
            let bytes = sample(encoding);
            let headers = ElfHeaders::from_slice(&bytes).unwrap();
            assert_eq!(headers.program_headers.len(), 1);
            assert_eq!(headers.section_names, ["", ".text", ".shstrtab"]);
            let (index, text) = headers.section_by_name(".text").unwrap();
            assert_eq!(index, 1);
            assert_eq!(headers.vaddr_to_file_offset(text.addr), Some(text.offset));
            assert_eq!(headers.file_offset_to_vaddr(text.offset), Some(text.addr));
            assert_eq!(headers.image_origin(), Some(0x1000));
            assert_eq!(
                headers.vaddr_to_source_offset(text.addr, SourceLayout::Mapped),
                Some(text.offset)
            );
        }
    }

    #[test]
    fn unreadable_section_table_is_empty() {
        let mut bytes = sample(Encoding::ELF64_LE);
        let shoff = usize::try_from(ElfHeaders::from_slice(&bytes).unwrap().header.shoff).unwrap();
        bytes.truncate(shoff + 10);
        let headers = ElfHeaders::from_slice(&bytes).unwrap();
        assert_eq!(headers.section_headers, []);
        assert_eq!(headers.header.shnum, 3);
        let reader = CountingReader::sized(bytes);
        let read = ElfHeaders::read_from(&reader, 0, SourceLayout::File).unwrap();
        assert_eq!(read, headers);
    }

    #[test]
    fn program_header_table_must_be_in_source() {
        let mut bytes = sample(Encoding::ELF64_LE);
        let past_end = u64::try_from(bytes.len()).unwrap();
        Encoding::ELF64_LE
            .put_u64(&mut bytes, 32, past_end)
            .unwrap();
        let error = ElfHeaders::from_slice(&bytes).unwrap_err();
        assert!(matches!(error.kind(), crate::ErrorKind::InvalidSegment(_)));
        assert_eq!(error.context().unwrap().file_offset, Some(past_end));
    }

    #[test]
    fn mapped_layout_skips_unmapped_section_table() {
        let bytes = sample(Encoding::ELF64_LE);
        let headers = ElfHeaders::from_mapped_slice(&bytes).unwrap();
        assert_eq!(headers.program_headers.len(), 1);
        assert_eq!(headers.section_headers, []);
    }

    #[test]
    fn resolves_extended_section_count() {
        let mut bytes = sample(Encoding::ELF64_LE);
        let encoding = Encoding::ELF64_LE;
        let headers = ElfHeaders::from_slice(&bytes).unwrap();
        let shoff = usize::try_from(headers.header.shoff).unwrap();
        // Move the counts into section header 0: `sh_size` = shnum, `sh_link` = shstrndx.
        encoding.put_u16(&mut bytes, 60, 0).unwrap();
        encoding.put_u16(&mut bytes, 62, SHN_XINDEX).unwrap();
        encoding.put_u64(&mut bytes, shoff + 32, 3).unwrap();
        encoding.put_u32(&mut bytes, shoff + 40, 2).unwrap();
        let extended = ElfHeaders::from_slice(&bytes).unwrap();
        assert_eq!(extended.section_headers.len(), 3);
        assert_eq!(extended.section_names[2], ".shstrtab");
    }

    #[test]
    fn rejects_short_program_header_entries() {
        let mut bytes = sample(Encoding::ELF64_LE);
        Encoding::ELF64_LE.put_u16(&mut bytes, 54, 8).unwrap();
        assert!(matches!(
            ElfHeaders::from_slice(&bytes).unwrap_err().kind(),
            crate::ErrorKind::InvalidHeader(_)
        ));
    }

    #[test]
    fn short_section_header_entries_give_no_sections() {
        let mut bytes = sample(Encoding::ELF64_LE);
        Encoding::ELF64_LE.put_u16(&mut bytes, 58, 32).unwrap();
        let headers = ElfHeaders::from_slice(&bytes).unwrap();
        assert_eq!(headers.section_headers, []);
        assert_eq!(headers.section_names, Vec::<String>::new());
        assert_eq!(headers.header.shnum, 3);
    }

    #[test]
    fn missing_program_header_table_gives_no_segments() {
        let encoding = Encoding::ELF64_LE;
        let mut no_phoff = sample(encoding);
        encoding.put_u64(&mut no_phoff, 32, 0).unwrap();
        let mut no_phnum = sample(encoding);
        encoding.put_u16(&mut no_phnum, 56, 0).unwrap();
        for bytes in [no_phoff, no_phnum] {
            let headers = ElfHeaders::from_slice(&bytes).unwrap();
            assert_eq!(headers.program_headers, []);
            assert_eq!(headers.image_origin(), None);
            assert_eq!(headers.section_headers.len(), 3);
        }
    }

    #[test]
    fn translates_to_source_offsets() {
        let mut headers = ElfHeaders::from_slice(&sample(Encoding::ELF64_LE)).unwrap();
        let end = headers.program_headers[0].vaddr + headers.program_headers[0].memsz;
        assert_eq!(headers.image_end(), Some(end));
        assert_eq!(headers.mapped_size(), Some(end - 0x1000));
        assert_eq!(
            headers.vaddr_to_source_offset(0x1010, SourceLayout::File),
            Some(0x10)
        );
        assert_eq!(
            headers.vaddr_to_source_offset(0x1000, SourceLayout::Mapped),
            Some(0)
        );
        assert_eq!(
            headers.vaddr_to_source_offset(0x800, SourceLayout::Mapped),
            None
        );
        assert_eq!(
            headers.vaddr_to_source_offset(end, SourceLayout::Mapped),
            None
        );

        // A memory range that ends past 2^64 has no end.
        headers.program_headers[0].memsz = u64::MAX;
        assert_eq!(headers.image_end(), None);
        assert_eq!(headers.mapped_size(), None);
    }

    /// A source that records the largest read request.
    struct CountingReader {
        data: Vec<u8>,
        sized: bool,
        largest: Cell<usize>,
    }

    impl CountingReader {
        /// Return a source with an unknown size.
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                sized: false,
                largest: Cell::new(0),
            }
        }

        /// Return a source with a known size.
        fn sized(data: Vec<u8>) -> Self {
            Self {
                sized: true,
                ..Self::new(data)
            }
        }
    }

    impl ReadAt for CountingReader {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize> {
            self.largest.set(self.largest.get().max(buf.len()));
            SliceReader::new(&self.data).read_at(offset, buf)
        }

        fn size(&self) -> Option<u64> {
            self.sized.then(|| u64::try_from(self.data.len()).unwrap())
        }
    }

    #[test]
    fn unsized_source_limits_table_bytes() {
        let mut bytes = sample(Encoding::ELF64_LE);
        // 2000 entries of 65535 bytes: fewer than the entry limit, but more than 64 MiB.
        Encoding::ELF64_LE
            .put_u16(&mut bytes, 58, u16::MAX)
            .unwrap();
        Encoding::ELF64_LE.put_u16(&mut bytes, 60, 2000).unwrap();
        let reader = CountingReader::new(bytes);
        let headers = ElfHeaders::read_from(&reader, 0, SourceLayout::File).unwrap();
        assert_eq!(headers.section_headers, []);
        assert!(reader.largest.get() < 0x1_0000, "{}", reader.largest.get());
    }

    #[test]
    fn unsized_source_limits_name_table() {
        let mut bytes = sample(Encoding::ELF64_LE);
        let shoff = usize::try_from(ElfHeaders::from_slice(&bytes).unwrap().header.shoff).unwrap();
        Encoding::ELF64_LE
            .put_u64(&mut bytes, shoff + 2 * 64 + 32, 32 << 20)
            .unwrap();
        let reader = CountingReader::new(bytes);
        let headers = ElfHeaders::read_from(&reader, 0, SourceLayout::File).unwrap();
        assert_eq!(headers.section_headers.len(), 3);
        assert_eq!(headers.section_names, ["", "", ""]);
        assert!(reader.largest.get() < 0x1_0000, "{}", reader.largest.get());
    }

    #[test]
    fn unsized_source_limits_extended_program_header_count() {
        let encoding = Encoding::ELF64_LE;
        let mut bytes = sample(encoding);
        let shoff = usize::try_from(ElfHeaders::from_slice(&bytes).unwrap().header.shoff).unwrap();
        // `e_phnum` is `PN_XNUM`: `sh_info` of section header 0 holds the count.
        encoding.put_u16(&mut bytes, 56, PN_XNUM).unwrap();
        let count = u32::try_from(MAX_UNSIZED_TABLE_ENTRIES + 1).unwrap();
        encoding.put_u32(&mut bytes, shoff + 44, count).unwrap();
        let reader = CountingReader::new(bytes);
        let error = ElfHeaders::read_from(&reader, 0, SourceLayout::File).unwrap_err();
        assert!(matches!(error.kind(), crate::ErrorKind::InvalidSegment(_)));
        let context = error.context().unwrap();
        assert_eq!(context.file_offset, Some(64));
        assert_eq!(context.structure.as_deref(), Some("program header table"));
        assert_eq!(reader.largest.get(), 64);
    }
}
