//! Edit the sections and segments of an [`ElfFile`].

use super::{ElfFile, align_up, overlaps, resolved_shnum, string_at};
use crate::prelude::*;
use crate::program::{PF_R, ProgramHeader, SegmentType};
use crate::section::{SHF_ALLOC, SHN_LORESERVE, SHN_XINDEX, SectionHeader, SectionType};
use crate::{Error, Result};
use core::ops::Range;

mod remove;

/// The smallest page size for a new `PT_LOAD` segment: 4 KiB.
const MIN_PAGE_SIZE: u64 = 0x1000;

/// The number of free entries that a relocated program header table keeps for later
/// segments.
const SPARE_PROGRAM_HEADERS: usize = 4;

/// The name of the section name string table that [`ElfFile::add_section`] creates.
const SHSTRTAB_NAME: &[u8] = b".shstrtab";

/// The largest number of zero bytes that one edit adds before appended data: 256 MiB.
///
/// An edit pads the file to align appended data, or to move the program header table past the
/// end of the memory image. A file with a very large `p_memsz` would need a very large padding.
/// An edit that needs more than this limit returns
/// [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange), and the file does not
/// change.
pub const MAX_APPEND_PADDING: u64 = 256 << 20;

/// A section to add with [`ElfFile::add_section`].
///
/// The fields give the values of the new section header (`Elf32_Shdr` or `Elf64_Shdr`). The
/// section does not have `SHF_ALLOC`, so it has no virtual address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSection {
    /// The section name. The method adds it to the section name string table.
    pub name: String,
    /// The section type (`sh_type`).
    pub section_type: SectionType,
    /// The section flags (`sh_flags`). `SHF_ALLOC` is not permitted.
    pub flags: u64,
    /// The section data. It must be empty for a `SHT_NOBITS` section.
    pub data: Vec<u8>,
    /// The section index link (`sh_link`).
    pub link: u32,
    /// The extra information (`sh_info`).
    pub info: u32,
    /// The alignment of the section data in the file (`sh_addralign`).
    pub addralign: u64,
    /// The size of one entry for a table section (`sh_entsize`), or 0.
    pub entsize: u64,
}

impl NewSection {
    /// Create a section with no flags, no links, an alignment of 1 and an entry size of 0.
    #[must_use]
    pub fn new(name: impl Into<String>, section_type: SectionType, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            section_type,
            flags: 0,
            data,
            link: 0,
            info: 0,
            addralign: 1,
            entsize: 0,
        }
    }
}

impl ElfFile {
    /// Replace the data of the section at `index`.
    ///
    /// - If `data` is not larger than the section (`sh_size`), the method writes it in place,
    ///   sets the remaining bytes of the old range to zero and sets `sh_size`.
    /// - If `data` is larger and the section does not have `SHF_ALLOC`, the method appends
    ///   `data` at the end of the file, aligned to `sh_addralign`. It sets `sh_offset` and
    ///   `sh_size`. If no other item uses the old range, the method sets it to zero. If the
    ///   section header table is at the end of the file, the data goes after it, and the
    ///   table stays where it is.
    /// - A `SHT_NOBITS` section has no file bytes. `data` must be empty, and the method sets
    ///   `sh_size` to 0.
    ///
    /// The method updates [`Self::section_names`] if the section is the section name string
    /// table.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) in these
    /// conditions:
    ///
    /// - `index` is out of range, or the section is `SHT_NULL`.
    /// - `data` is not empty for a `SHT_NOBITS` section.
    /// - `data` is larger than a section with `SHF_ALLOC`. Such a section has a fixed
    ///   address range in a segment.
    ///
    /// Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    /// old file range of the section is outside the file.
    pub fn set_section_data(&mut self, index: usize, data: Vec<u8>) -> Result<()> {
        let header = *self.section_header(index)?;
        if header.section_type == SectionType::NULL {
            return Err(Error::invalid_section("a SHT_NULL section has no data"));
        }
        if header.section_type == SectionType::NOBITS {
            if !data.is_empty() {
                return Err(Error::invalid_section(
                    "a SHT_NOBITS section has no file bytes: the data must be empty",
                ));
            }
            self.section_header_mut(index)?.size = 0;
            return Ok(());
        }
        let new_size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if new_size <= header.size {
            let range = self.data_range(header.offset, header.size)?;
            let (used, rest) = self.data[range].split_at_mut(data.len());
            used.copy_from_slice(&data);
            rest.fill(0);
        } else {
            if header.is_alloc() {
                return Err(Error::invalid_section(
                    "the data is larger than a SHF_ALLOC section: its address range cannot grow",
                ));
            }
            let offset = self.append(data, header.addralign)?;
            self.section_header_mut(index)?.offset = offset;
            if let Some(range) = header.file_range() {
                self.zero_if_unused(&range, None);
            }
        }
        self.section_header_mut(index)?.size = new_size;
        if self.shstrndx() == Some(index) {
            self.refresh_section_names();
        }
        Ok(())
    }

    /// Add a section without `SHF_ALLOC` and return its index.
    ///
    /// The method appends the section data at the end of the file, aligned to
    /// `sh_addralign`. It adds the name to the section name string table: it writes a new copy
    /// of the table (the old names and the new name) at the end of the file and points the
    /// table header at the copy.
    ///
    /// If the file has no section header table, the method creates the null section and a
    /// `.shstrtab` section. [`Self::try_build`] writes the section header table at the end of
    /// the file when the table is new or grows.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) in these
    /// conditions:
    ///
    /// - The section has `SHF_ALLOC`, or its name contains a NUL byte.
    /// - A `SHT_NOBITS` section has data.
    /// - The file has a section header table that the parser cannot read.
    /// - The section name string table is absent, is not `SHT_STRTAB`, has `SHF_ALLOC` or is
    ///   outside the file.
    pub fn add_section(&mut self, section: NewSection) -> Result<usize> {
        if section.flags & SHF_ALLOC != 0 {
            return Err(Error::invalid_section(
                "add_section cannot add a SHF_ALLOC section",
            ));
        }
        if section.name.as_bytes().contains(&0) {
            return Err(Error::invalid_section(
                "the section name contains a NUL byte",
            ));
        }
        let is_nobits = section.section_type == SectionType::NOBITS;
        if is_nobits && !section.data.is_empty() {
            return Err(Error::invalid_section(
                "a SHT_NOBITS section has no file bytes: the data must be empty",
            ));
        }
        let name = if self.headers.section_headers.is_empty() {
            self.create_section_table(&section.name)?
        } else {
            self.add_section_name(&section.name)?
        };
        let size = u64::try_from(section.data.len()).unwrap_or(u64::MAX);
        let offset = if is_nobits {
            self.file_end()
        } else {
            self.append(section.data, section.addralign)?
        };
        let index = self.headers.section_headers.len();
        self.headers.section_headers.push(SectionHeader {
            name,
            section_type: section.section_type,
            flags: section.flags,
            addr: 0,
            offset,
            size,
            link: section.link,
            info: section.info,
            addralign: section.addralign,
            entsize: section.entsize,
        });
        self.headers.section_names.resize(index, String::new());
        self.headers.section_names.push(section.name);
        Ok(index)
    }

    /// Add a `PT_LOAD` segment with `data` and return its virtual address.
    ///
    /// The page size is the largest `p_align` of the `PT_LOAD` segments, at least 0x1000.
    /// An `align` of 0 means the page size. The method appends `data` at the end of the file,
    /// at an offset aligned to `align`. The virtual address is the end of the highest
    /// `PT_LOAD` segment, rounded up to `align`. Thus the segment starts on a new page, and
    /// its offset and address agree modulo `align`. The new program header goes after the
    /// `PT_LOAD` program headers with a lower address, so the `PT_LOAD` entries stay sorted.
    ///
    /// The program header table must grow by one entry. The table grows in place if the bytes
    /// after it are free and in the same `PT_LOAD` segment, and the file has a section header
    /// table that the parser can read. Else the method moves the table to a new readable
    /// `PT_LOAD` segment at the end of the file, as patchelf does. The new segment has the
    /// same `p_vaddr - p_offset` as the lowest `PT_LOAD` segment, so the table is at the
    /// address that the loader expects for `e_phoff`. For this, the file grows to at least the
    /// size of the memory image (with a large `.bss`, much larger). The padding before the new
    /// table is limited to [`MAX_APPEND_PADDING`]. The new table has free
    /// entries for later segments. The method sets `e_phoff` and the `PT_PHDR` segment
    /// (offset, address and sizes) to the table.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if `align`
    ///   is not a power of two or is smaller than the page size, if the file has no `PT_LOAD`
    ///   segment, or if the program header table must move and the lowest `PT_LOAD` segment
    ///   has `p_offset` above `p_vaddr`.
    /// - Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) if the
    ///   section header table at `e_shoff` goes past the end of the file, so that the new
    ///   bytes would change it.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an
    ///   address or offset overflows, does not fit in 32 bits in an ELF32 file, or needs more
    ///   padding than [`MAX_APPEND_PADDING`].
    /// - Return a generic error if the file is too large to allocate.
    pub fn add_load_segment(&mut self, flags: u32, data: Vec<u8>, align: u64) -> Result<u64> {
        self.add_load_segment_at(flags, data, align)
            .map(|(_, vaddr)| vaddr)
    }

    /// Set the path of the program interpreter in the `PT_INTERP` segment.
    ///
    /// If the path and its NUL terminator fit in the current `PT_INTERP` segment, the method
    /// writes the path in place and sets the remaining bytes to zero. Else it puts the path
    /// in a new readable `PT_LOAD` segment ([`Self::add_load_segment`] with the default
    /// alignment) and points `PT_INTERP` at it. The method also sets the `.interp` section to
    /// the new path. It changes only a section with the same file range as `PT_INTERP`.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if the file
    ///   has no `PT_INTERP` segment or the path contains a NUL byte.
    /// - Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    ///   `PT_INTERP` segment is outside the file.
    /// - Return an error from [`Self::add_load_segment`] for a longer path.
    pub fn set_interpreter(&mut self, path: &str) -> Result<()> {
        if path.as_bytes().contains(&0) {
            return Err(Error::invalid_segment(
                "the interpreter path contains a NUL byte",
            ));
        }
        let interp = *self
            .headers
            .segment(SegmentType::INTERP)
            .ok_or_else(|| Error::invalid_segment("the file has no PT_INTERP segment"))?;
        let section = self.interp_section(&interp);
        let mut bytes = path.as_bytes().to_vec();
        bytes.push(0);
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);

        let (offset, vaddr) = if len <= interp.filesz {
            let range = self.data_range(interp.offset, interp.filesz)?;
            let (used, rest) = self.data[range].split_at_mut(bytes.len());
            used.copy_from_slice(&bytes);
            rest.fill(0);
            (interp.offset, interp.vaddr)
        } else {
            self.add_load_segment_at(PF_R, bytes, 0)?
        };
        if let Some(segment) = self
            .headers
            .program_headers
            .iter_mut()
            .find(|segment| segment.segment_type == SegmentType::INTERP)
        {
            if segment.offset != offset {
                segment.offset = offset;
                segment.vaddr = vaddr;
                segment.paddr = vaddr;
            }
            segment.filesz = len;
            segment.memsz = len;
        }
        if let Some(index) = section {
            let header = self.section_header_mut(index)?;
            if offset != interp.offset {
                header.offset = offset;
                if header.is_alloc() {
                    header.addr = vaddr;
                }
            }
            header.size = len;
        }
        Ok(())
    }

    /// Add a `PT_LOAD` segment with `data` and return its file offset and virtual address.
    fn add_load_segment_at(&mut self, flags: u32, data: Vec<u8>, align: u64) -> Result<(u64, u64)> {
        let page = self.load_page_size();
        let align = if align == 0 { page } else { align };
        if !align.is_power_of_two() || align < page {
            return Err(Error::invalid_segment(format!(
                "the segment alignment {align:#x} is not a power of two of at least the page size {page:#x}"
            )));
        }
        if self.headers.load_segments().next().is_none() {
            return Err(Error::invalid_segment("the file has no PT_LOAD segment"));
        }
        if !self.program_table_can_grow() {
            self.relocate_program_table()?;
        }
        let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let offset = align_up(self.file_end(), align)?;
        let vaddr = self.next_vaddr(align)?;
        self.check_range(offset, size)?;
        self.check_range(vaddr, size)?;
        let offset = self.append(data, align)?;
        self.insert_load(ProgramHeader {
            segment_type: SegmentType::LOAD,
            flags,
            offset,
            vaddr,
            paddr: vaddr,
            filesz: size,
            memsz: size,
            align,
        });
        self.update_phdr_segment();
        Ok((offset, vaddr))
    }

    /// Return `true` if the program header table can grow by one entry in place.
    ///
    /// The file must have a section header table that the parser can read: without it, the
    /// method cannot know which bytes after the table hold data. The new entry must be in the
    /// file and must not overlap the file header, the section header table, a section or a
    /// segment other than `PT_PHDR`. If a `PT_LOAD` segment maps the table, it must also map
    /// the new entry.
    fn program_table_can_grow(&self) -> bool {
        let header = &self.headers.header;
        let class = self.encoding().class;
        if header.phoff == 0
            || usize::from(header.phentsize) < ProgramHeader::size(class)
            || self.headers.section_headers.is_empty()
        {
            return false;
        }
        let table = self.program_table_range();
        let Some(new_end) = table.end.checked_add(u64::from(header.phentsize)) else {
            return false;
        };
        if new_end > self.file_size() {
            return false;
        }
        let growth = table.end..new_end;
        if [
            self.header_range(),
            self.section_table_range(),
            self.raw_section_table_in_file(),
        ]
        .iter()
        .any(|used| overlaps(used, &growth))
            || self
                .section_ranges(None)
                .any(|range| overlaps(&range, &growth))
        {
            return false;
        }
        self.headers.program_headers.iter().all(|segment| {
            if segment.segment_type == SegmentType::PHDR {
                return true;
            }
            let Some(range) = segment.file_range() else {
                return false;
            };
            if segment.is_load() && range.start <= table.start && table.end <= range.end {
                return new_end <= range.end;
            }
            !overlaps(&range, &growth)
        })
    }

    /// Move the program header table to a new readable `PT_LOAD` segment at the end of the
    /// file, and set `e_phoff` to it.
    ///
    /// The table gets room for the current entries, its own `PT_LOAD` entry, one more
    /// segment and [`SPARE_PROGRAM_HEADERS`] free entries.
    ///
    /// The new segment has `p_vaddr - p_offset` equal to the image origin (the address of
    /// file offset 0 in the lowest `PT_LOAD` segment). Thus the table is at the address
    /// `origin + e_phoff`. The mapped image parser reads the table there, and Linux before
    /// 5.18 gives this address in `AT_PHDR`. The offset is the larger of the end of the file
    /// and the end of the image minus the origin, rounded up to the page size. Thus a large
    /// zero-filled area (`.bss`) at the end of the image makes the file grow to the size of
    /// the image.
    fn relocate_program_table(&mut self) -> Result<()> {
        let origin = self.headers.image_origin().ok_or_else(|| {
            Error::invalid_segment(
                "the image origin is not defined: the lowest PT_LOAD segment has p_offset above p_vaddr",
            )
        })?;
        let image_size = self
            .headers
            .mapped_size()
            .ok_or_else(|| Error::invalid_segment("the end of the PT_LOAD segments overflows"))?;
        let class = self.encoding().class;
        let entry_size = usize::from(self.headers.header.phentsize).max(ProgramHeader::size(class));
        let count = self.headers.program_headers.len() + 2 + SPARE_PROGRAM_HEADERS;
        let table_size = count
            .checked_mul(entry_size)
            .ok_or_else(|| Error::value_out_of_range("the program header table is too large"))?;
        let size = u64::try_from(table_size).unwrap_or(u64::MAX);
        let page = self.load_page_size();
        let offset = align_up(self.file_end().max(image_size), page)?;
        let vaddr = origin
            .checked_add(offset)
            .ok_or_else(|| Error::value_out_of_range("the segment address overflows"))?;
        self.check_range(offset, size)?;
        self.check_range(vaddr, size)?;
        let table = offset..offset.saturating_add(size);
        let covered = self
            .section_ranges(None)
            .any(|range| overlaps(&range, &table))
            || self
                .headers
                .program_headers
                .iter()
                .filter(|segment| !segment.is_load() && segment.segment_type != SegmentType::PHDR)
                .filter_map(ProgramHeader::file_range)
                .any(|range| overlaps(&range, &table));
        if covered {
            return Err(Error::invalid_segment(
                "a section or segment goes past the end of the file and covers the new program header table",
            ));
        }
        self.append_at(offset, vec![0; table_size])?;
        if usize::from(self.headers.header.phentsize) < ProgramHeader::size(class) {
            self.headers.header.phentsize = ProgramHeader::standard_size(class);
        }
        self.insert_load(ProgramHeader {
            segment_type: SegmentType::LOAD,
            flags: PF_R,
            offset,
            vaddr,
            paddr: vaddr,
            filesz: size,
            memsz: size,
            align: page,
        });
        self.headers.header.phoff = offset;
        Ok(())
    }

    /// Return the virtual address for a new segment: the end of the highest `PT_LOAD`
    /// segment, rounded up to `align`. The file offset of the segment is a multiple of
    /// `align`, so the offset and the address agree modulo `align`.
    fn next_vaddr(&self, align: u64) -> Result<u64> {
        let end = self
            .headers
            .image_end()
            .ok_or_else(|| Error::invalid_segment("the end of the PT_LOAD segments overflows"))?;
        align_up(end, align)
    }

    /// Return the largest power-of-two `p_align` of the `PT_LOAD` segments, at least 0x1000.
    fn load_page_size(&self) -> u64 {
        self.headers
            .load_segments()
            .map(|segment| segment.align)
            .filter(|align| align.is_power_of_two())
            .fold(MIN_PAGE_SIZE, u64::max)
    }

    /// Check that the range of `size` bytes at `start` fits in the address space of the
    /// class.
    fn check_range(&self, start: u64, size: u64) -> Result<()> {
        let limit = if self.is_64bit() { u64::MAX } else { 1 << 32 };
        match start.checked_add(size) {
            Some(end) if end <= limit => Ok(()),
            _ => Err(Error::value_out_of_range(format!(
                "the range at {start:#x} with {size:#x} bytes does not fit in the file class"
            ))),
        }
    }

    /// Insert a `PT_LOAD` program header after the `PT_LOAD` headers with a lower or equal
    /// address. The address of a new segment is at or after the end of the image, so such a
    /// header exists if the file has a `PT_LOAD` segment. Else the header goes at the end.
    fn insert_load(&mut self, segment: ProgramHeader) {
        let headers = &mut self.headers.program_headers;
        let position = headers
            .iter()
            .rposition(|header| header.is_load() && header.vaddr <= segment.vaddr)
            .map_or(headers.len(), |index| index + 1);
        headers.insert(position, segment);
    }

    /// Set each `PT_PHDR` segment to the program header table at `e_phoff`.
    fn update_phdr_segment(&mut self) {
        let header = &self.headers.header;
        let offset = header.phoff;
        let size = u64::try_from(self.headers.program_headers.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::from(header.phentsize));
        let vaddr = self.headers.file_offset_to_vaddr(offset);
        for segment in &mut self.headers.program_headers {
            if segment.segment_type != SegmentType::PHDR {
                continue;
            }
            if segment.offset != offset {
                segment.offset = offset;
                if let Some(vaddr) = vaddr {
                    segment.vaddr = vaddr;
                    segment.paddr = vaddr;
                }
            }
            segment.filesz = size;
            segment.memsz = size;
        }
    }

    /// Return the index of the section with the same file range as `interp`: the `.interp`
    /// section. A section named `.interp` at a different range does not count.
    fn interp_section(&self, interp: &ProgramHeader) -> Option<usize> {
        self.headers.section_headers.iter().position(|header| {
            header.has_file_data() && header.offset == interp.offset && header.size == interp.filesz
        })
    }

    /// Create the null section and a `.shstrtab` section that holds `name`. Return the offset
    /// of `name` in the new string table.
    fn create_section_table(&mut self, name: &str) -> Result<u32> {
        let header = &self.headers.header;
        if header.shoff != 0 && resolved_shnum(header, self.raw_section_zero().as_ref()) != 0 {
            return Err(Error::invalid_section(
                "the section header table cannot be read",
            ));
        }
        let mut content = vec![0];
        content.extend_from_slice(SHSTRTAB_NAME);
        content.push(0);
        let name_offset = u32::try_from(content.len()).unwrap_or(u32::MAX);
        content.extend_from_slice(name.as_bytes());
        content.push(0);
        let size = u64::try_from(content.len()).unwrap_or(u64::MAX);
        let offset = self.append(content, 1)?;
        self.headers.section_headers = vec![
            SectionHeader::default(),
            SectionHeader {
                name: 1,
                section_type: SectionType::STRTAB,
                offset,
                size,
                addralign: 1,
                ..SectionHeader::default()
            },
        ];
        self.headers.section_names = vec![String::new(), String::from(".shstrtab")];
        self.headers.header.shoff = 0;
        self.set_shstrndx(1)?;
        Ok(name_offset)
    }

    /// Write a new copy of the section name string table with `name` at its end. Return the
    /// offset of `name` in the table.
    fn add_section_name(&mut self, name: &str) -> Result<u32> {
        let missing = || Error::invalid_section("the file has no section name string table");
        let index = self
            .shstrndx()
            .filter(|index| *index != 0 && *index < self.headers.section_headers.len())
            .ok_or_else(missing)?;
        let header = *self.section_header(index)?;
        if header.section_type != SectionType::STRTAB || header.is_alloc() {
            return Err(Error::invalid_section(
                "the section name string table is not a SHT_STRTAB section without SHF_ALLOC",
            ));
        }
        let mut content = self.section_bytes(&header)?.to_vec();
        if content.last().is_none_or(|byte| *byte != 0) {
            content.push(0);
        }
        let name_offset = u32::try_from(content.len())
            .map_err(|_| Error::value_out_of_range("the section name string table is too large"))?;
        content.extend_from_slice(name.as_bytes());
        content.push(0);
        let size = u64::try_from(content.len()).unwrap_or(u64::MAX);
        let offset = self.append(content, header.addralign)?;
        let table = self.section_header_mut(index)?;
        table.offset = offset;
        table.size = size;
        if let Some(range) = header.file_range() {
            self.zero_if_unused(&range, None);
        }
        Ok(name_offset)
    }

    /// Set `e_shstrndx` to `index`. Use `SHN_XINDEX` and `sh_link` of section header 0 for an
    /// index of `SHN_LORESERVE` or more.
    fn set_shstrndx(&mut self, index: usize) -> Result<()> {
        match u16::try_from(index) {
            Ok(value) if value < SHN_LORESERVE => {
                if self.headers.header.shstrndx == SHN_XINDEX
                    && let Some(zero) = self.headers.section_headers.first_mut()
                {
                    zero.link = 0;
                }
                self.headers.header.shstrndx = value;
            }
            _ => {
                let link = u32::try_from(index)
                    .map_err(|_| Error::value_out_of_range("the section index is too large"))?;
                let zero =
                    self.headers.section_headers.first_mut().ok_or_else(|| {
                        Error::invalid_section("the file has no section header 0")
                    })?;
                zero.link = link;
                self.headers.header.shstrndx = SHN_XINDEX;
            }
        }
        Ok(())
    }

    /// Read [`Self::section_names`] again from the section name string table.
    fn refresh_section_names(&mut self) {
        let table = self
            .shstrndx()
            .and_then(|index| self.headers.section_headers.get(index))
            .filter(|header| header.section_type == SectionType::STRTAB)
            .and_then(|header| self.section_bytes(header).ok());
        let names = self
            .headers
            .section_headers
            .iter()
            .map(|header| table.map_or_else(String::new, |table| string_at(table, header.name)))
            .collect();
        self.headers.section_names = names;
    }

    /// Append `data` at the end of the file, at an offset aligned to `align`. Return the file
    /// offset of the data.
    ///
    /// The end of the file is after the data buffer and the header tables. Thus the data
    /// does not overlap them.
    fn append(&mut self, data: Vec<u8>, align: u64) -> Result<u64> {
        let offset = align_up(self.file_end(), align)?;
        self.append_at(offset, data)?;
        Ok(offset)
    }

    /// Write `data` at file offset `offset`. Fill the bytes between the end of the data buffer
    /// and `offset` with zeros. The caller makes sure that `offset` is not before the end of
    /// the file ([`Self::file_end`]).
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) if the
    ///   section header table that `e_shoff` gives goes past the end of the data buffer and
    ///   the new bytes would be in it. The parser cannot read such a table, but it reads the
    ///   new bytes as section headers if the file grows.
    /// - Return a generic error if the file is too large to allocate.
    fn append_at(&mut self, offset: u64, data: Vec<u8>) -> Result<()> {
        let too_large = || Error::generic("the file is too large to allocate");
        let padding = offset.saturating_sub(self.file_size());
        if padding > MAX_APPEND_PADDING {
            return Err(Error::value_out_of_range(format!(
                "the edit needs {padding:#x} bytes of padding, more than MAX_APPEND_PADDING"
            )));
        }
        let start = usize::try_from(offset).map_err(|_| too_large())?;
        let end = start.checked_add(data.len()).ok_or_else(too_large)?;
        let new_bytes = self.file_size()..u64::try_from(end).unwrap_or(u64::MAX);
        if overlaps(&self.raw_section_table_range(), &new_bytes) {
            return Err(Error::invalid_section(
                "the section header table goes past the end of the file: appended bytes would change it",
            ));
        }
        self.data
            .try_reserve(end - self.data.len())
            .map_err(|_| too_large())?;
        self.data.resize(start, 0);
        self.data.extend(data);
        Ok(())
    }

    /// Set the bytes of `range` to zero if no section other than `exclude`, no segment and no
    /// header table uses them. Ignore the part of `range` outside the data buffer.
    fn zero_if_unused(&mut self, range: &Range<u64>, exclude: Option<usize>) {
        if range.is_empty() || self.range_is_used(range, exclude) {
            return;
        }
        let len = self.data.len();
        let start = usize::try_from(range.start).map_or(len, |start| start.min(len));
        let end = usize::try_from(range.end).map_or(len, |end| end.min(len));
        if start < end {
            self.data[start..end].fill(0);
        }
    }
}
