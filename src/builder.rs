//! Build a new ELF file: [`ElfBuilder`].
//!
//! Describe each section with a [`BuilderSection`]. The builder lays out the sections in
//! `PT_LOAD` segments and writes the headers. It returns an [`ElfFile`], which you can edit
//! further or serialize with [`ElfFile::try_build`].
//!
//! # Layout
//!
//! 1. The first `PT_LOAD` segment is readable. It holds the ELF header, the program header
//!    table (with `PT_PHDR`) and the read-only sections, for example `.interp`, notes and
//!    `.rodata`.
//! 2. A readable and executable `PT_LOAD` segment holds the sections with `SHF_EXECINSTR`.
//! 3. A readable and writable `PT_LOAD` segment holds the sections with `SHF_WRITE`. The
//!    `SHT_NOBITS` sections (for example `.bss`) go at its end, after the file bytes.
//! 4. The sections without `SHF_ALLOC`, `.shstrtab` and the section header table follow.
//!
//! Each `PT_LOAD` segment starts on a new page in memory. The file offset and the virtual
//! address of each segment agree modulo the page size. The sections in a segment keep the
//! order in which you added them.
//!
//! [`ElfBuilder::try_layout`] gives the address and the file offset of each section before
//! the build, as a [`BuilderLayout`]. Use it to make section data that holds addresses.
//!
//! # Example
//!
//! ```
//! use elfex::builder::{BuilderSection, ElfBuilder};
//! use elfex::section::{SHF_ALLOC, SHF_EXECINSTR};
//! use elfex::{Encoding, Machine};
//!
//! # fn main() -> elfex::Result<()> {
//! let elf = ElfBuilder::new(Encoding::ELF64_LE)
//!     .machine(Machine::X86_64)
//!     .add_section(BuilderSection::progbits(
//!         ".text",
//!         SHF_ALLOC | SHF_EXECINSTR,
//!         vec![0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05],
//!     ))
//!     .entry_in_section(".text", 0)
//!     .try_build()?;
//! assert!(!elf.validate().has_errors());
//! # Ok(())
//! # }
//! ```

use crate::Result;
use crate::elf_file::ElfFile;
use crate::endian::Encoding;
use crate::header::{FileType, Machine};
use crate::ident::OsAbi;
use crate::prelude::*;
use crate::program::{PF_R, PF_W, SegmentType};
use crate::section::{SHF_ALLOC, SectionType};

mod layout;
#[cfg(test)]
mod tests;

/// The default base address of an `ET_EXEC` file.
pub const DEFAULT_EXEC_BASE: u64 = 0x40_0000;

/// The default page size: 4 KiB.
pub const DEFAULT_PAGE_SIZE: u64 = 0x1000;

/// A section for [`ElfBuilder::add_section`].
///
/// The fields give the values of the section header (`Elf32_Shdr` or `Elf64_Shdr`). The
/// builder sets `sh_name`, `sh_addr`, `sh_offset` and `sh_link`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderSection {
    /// The section name.
    pub name: String,
    /// The section type (`sh_type`).
    pub section_type: SectionType,
    /// The section flags (`sh_flags`). `SHF_ALLOC`, `SHF_WRITE` and `SHF_EXECINSTR` select
    /// the segment of the section.
    pub flags: u64,
    /// The section data. A `SHT_NOBITS` section has no data.
    pub data: Vec<u8>,
    /// The size of a `SHT_NOBITS` section in memory. The builder ignores this field for other
    /// section types: their size is the length of [`Self::data`].
    pub size: u64,
    /// The alignment of the section (`sh_addralign`): 0 or a power of two.
    pub addralign: u64,
    /// The size of one entry for a table section (`sh_entsize`), or 0.
    pub entsize: u64,
    /// The name of the section that `sh_link` gives, or `None` for a `sh_link` of 0.
    pub link_name: Option<String>,
    /// The extra information (`sh_info`).
    pub info: u32,
}

impl BuilderSection {
    /// Create a `SHT_PROGBITS` section with an alignment of 1.
    #[must_use]
    pub fn progbits(name: impl Into<String>, flags: u64, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            section_type: SectionType::PROGBITS,
            flags,
            data,
            size: 0,
            addralign: 1,
            entsize: 0,
            link_name: None,
            info: 0,
        }
    }

    /// Create a `SHT_NOBITS` section of `size` bytes with an alignment of 1, for example
    /// `.bss`.
    #[must_use]
    pub fn nobits(name: impl Into<String>, flags: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            section_type: SectionType::NOBITS,
            flags,
            data: Vec::new(),
            size,
            addralign: 1,
            entsize: 0,
            link_name: None,
            info: 0,
        }
    }

    /// Create a `SHT_NOTE` section with `SHF_ALLOC` and an alignment of 4. `data` holds the
    /// note entries (`Elf32_Nhdr` or `Elf64_Nhdr` with name and descriptor).
    #[must_use]
    pub fn note(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            section_type: SectionType::NOTE,
            flags: SHF_ALLOC,
            data,
            size: 0,
            addralign: 4,
            entsize: 0,
            link_name: None,
            info: 0,
        }
    }

    /// Return the size of the section: [`Self::size`] for `SHT_NOBITS`, else the data length.
    fn section_size(&self) -> u64 {
        if self.section_type == SectionType::NOBITS {
            self.size
        } else {
            u64::try_from(self.data.len()).unwrap_or(u64::MAX)
        }
    }
}

/// The place of one section in the file that [`ElfBuilder::try_layout`] plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SectionPlacement {
    /// The index of the section in the section header table.
    pub index: usize,
    /// The virtual address of the section (`sh_addr`), or 0 for a section without
    /// `SHF_ALLOC`.
    pub addr: u64,
    /// The file offset of the section (`sh_offset`).
    pub offset: u64,
    /// The size of the section (`sh_size`).
    pub size: u64,
}

/// The layout of a file that [`ElfBuilder::try_layout`] plans: the place of each section and
/// the entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuilderLayout {
    /// The name and the place of each section, in section header order, without the null
    /// section.
    sections: Vec<(String, SectionPlacement)>,
    /// The entry point, if the builder has one.
    entry: Option<u64>,
}

impl BuilderLayout {
    /// Return the place of the first section with the name `name`.
    ///
    /// The layout also has the `.interp` section of an interpreter and the `.shstrtab`
    /// section that the builder adds.
    #[must_use]
    pub fn section(&self, name: &str) -> Option<SectionPlacement> {
        self.sections
            .iter()
            .find(|(section, _)| section == name)
            .map(|(_, placement)| *placement)
    }

    /// Return the name and the place of each section, in section header order, without the
    /// null section.
    pub fn sections(&self) -> impl Iterator<Item = (&str, SectionPlacement)> {
        self.sections
            .iter()
            .map(|(name, placement)| (name.as_str(), *placement))
    }

    /// Return the virtual address of the entry point (`e_entry`), or `None` if the builder
    /// has no entry point.
    #[must_use]
    pub const fn entry_point(&self) -> Option<u64> {
        self.entry
    }
}

/// The entry point of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EntryPoint {
    /// An `e_entry` of 0.
    None,
    /// An absolute virtual address.
    Address(u64),
    /// An offset in a named section.
    Section {
        /// The section name.
        name: String,
        /// The offset in the section.
        offset: u64,
    },
}

/// A builder for a new ELF executable or shared object.
///
/// Set the file properties and add the sections with the fluent methods. Then call
/// [`Self::try_build`]. The module documentation describes the layout.
///
/// # Examples
///
/// Build a shared object with a `PT_NOTE` segment, and read the note back.
///
/// ```
/// use elfex::note::{Note, NoteTable};
/// use elfex::program::SegmentType;
/// use elfex::{BuilderSection, ElfBuilder, ElfImage, Encoding, FileType, Machine};
///
/// let encoding = Encoding::ELF64_LE;
/// let notes = NoteTable { notes: vec![Note::gnu_build_id(vec![0xab; 20])] };
/// let file = ElfBuilder::new(encoding)
///     .file_type(FileType::DYN)
///     .machine(Machine::AARCH64)
///     .page_size(0x1_0000)
///     .add_section(BuilderSection::note(".note.gnu.build-id", notes.write(encoding, 4)?))
///     .add_segment_for_section(SegmentType::NOTE, ".note.gnu.build-id")
///     .try_build()?;
/// assert!(!file.validate().has_errors());
/// assert_eq!(file.build_id()?, Some(vec![0xab; 20]));
///
/// // A shared object starts at virtual address 0.
/// let bytes = file.try_build()?;
/// let image = ElfImage::parse(&bytes)?;
/// assert_eq!(image.image_origin(), Some(0));
/// assert!(image.load_segments().all(|segment| segment.header.align == 0x1_0000));
/// assert!(image.segment(SegmentType::NOTE).is_some());
/// # Ok::<(), elfex::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfBuilder {
    encoding: Encoding,
    file_type: FileType,
    machine: Machine,
    os_abi: OsAbi,
    flags: u32,
    base_address: Option<u64>,
    page_size: u64,
    entry: EntryPoint,
    sections: Vec<BuilderSection>,
    interpreters: Vec<String>,
    gnu_stack: Option<u32>,
    segments: Vec<(SegmentType, String)>,
}

impl ElfBuilder {
    /// Create a builder for an `ET_EXEC` file with `encoding`.
    ///
    /// The defaults are `EM_NONE`, the System V ABI, a page size of 0x1000, an entry point
    /// of 0 and a `PT_GNU_STACK` segment with `PF_R | PF_W`.
    #[must_use]
    pub fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            file_type: FileType::EXEC,
            machine: Machine::NONE,
            os_abi: OsAbi::SYSV,
            flags: 0,
            base_address: None,
            page_size: DEFAULT_PAGE_SIZE,
            entry: EntryPoint::None,
            sections: Vec::new(),
            interpreters: Vec::new(),
            gnu_stack: Some(PF_R | PF_W),
            segments: Vec::new(),
        }
    }

    /// Set the object file type (`e_type`), for example `ET_EXEC` or `ET_DYN`.
    #[must_use]
    pub fn file_type(mut self, file_type: FileType) -> Self {
        self.file_type = file_type;
        self
    }

    /// Set the target architecture (`e_machine`).
    #[must_use]
    pub fn machine(mut self, machine: Machine) -> Self {
        self.machine = machine;
        self
    }

    /// Set the operating system and ABI (`EI_OSABI`).
    #[must_use]
    pub fn os_abi(mut self, os_abi: OsAbi) -> Self {
        self.os_abi = os_abi;
        self
    }

    /// Set the processor-specific flags (`e_flags`).
    #[must_use]
    pub fn flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    /// Set the virtual address of file offset 0: the start of the first `PT_LOAD` segment.
    ///
    /// The address must be a multiple of the page size. The default is `0x40_0000` for
    /// `ET_EXEC` and 0 for other file types.
    #[must_use]
    pub fn base_address(mut self, base_address: u64) -> Self {
        self.base_address = Some(base_address);
        self
    }

    /// Set the page size: a power of two. The default is 0x1000. The builder uses it as
    /// `p_align` of each `PT_LOAD` segment.
    #[must_use]
    pub fn page_size(mut self, page_size: u64) -> Self {
        self.page_size = page_size;
        self
    }

    /// Set the virtual address of the entry point (`e_entry`).
    #[must_use]
    pub fn entry(mut self, entry: u64) -> Self {
        self.entry = EntryPoint::Address(entry);
        self
    }

    /// Set the entry point to `offset` bytes after the start of the section `section_name`.
    #[must_use]
    pub fn entry_in_section(mut self, section_name: impl Into<String>, offset: u64) -> Self {
        self.entry = EntryPoint::Section {
            name: section_name.into(),
            offset,
        };
        self
    }

    /// Add a section.
    #[must_use]
    pub fn add_section(mut self, section: BuilderSection) -> Self {
        self.sections.push(section);
        self
    }

    /// Set the path of the program interpreter. The builder adds a `.interp` section and a
    /// `PT_INTERP` segment.
    ///
    /// Call this method one time only. [`Self::try_build`] returns an error for a second
    /// interpreter.
    #[must_use]
    pub fn interpreter(mut self, path: impl Into<String>) -> Self {
        self.interpreters.push(path.into());
        self
    }

    /// Set the flags of the `PT_GNU_STACK` segment, for example `PF_R | PF_W` for a stack
    /// that is not executable. The default is `PF_R | PF_W`.
    #[must_use]
    pub fn gnu_stack(mut self, flags: u32) -> Self {
        self.gnu_stack = Some(flags);
        self
    }

    /// Add a segment of `segment_type` that covers the section `section_name`.
    ///
    /// Use this method for example for `PT_DYNAMIC` (`.dynamic`), `PT_NOTE`, `PT_TLS` or
    /// `PT_GNU_EH_FRAME` (`.eh_frame_hdr`). The section must have `SHF_ALLOC`. The segment
    /// flags follow the section flags.
    #[must_use]
    pub fn add_segment_for_section(
        mut self,
        segment_type: SegmentType,
        section_name: impl Into<String>,
    ) -> Self {
        self.segments.push((segment_type, section_name.into()));
        self
    }

    /// Lay out the file, and return the place of each section and the entry point. The
    /// method does not write the file.
    ///
    /// The layout depends on the builder settings and on the type, flags, size, alignment
    /// and order of the sections. It does not depend on the section data bytes. Thus, to get
    /// the final addresses, add placeholder data of the final size. Then use the addresses to
    /// make the final data (for example the `DT_*` values of `.dynamic` or the relocation
    /// addresses), put it into the sections, and call [`Self::try_build`].
    ///
    /// # Examples
    ///
    /// ```
    /// use elfex::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
    /// use elfex::{BuilderSection, ElfBuilder, Encoding};
    ///
    /// let text = |data| BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, data);
    /// let builder = ElfBuilder::new(Encoding::ELF64_LE)
    ///     .add_section(BuilderSection::progbits(".data", SHF_ALLOC | SHF_WRITE, vec![0; 8]))
    ///     .entry_in_section(".text", 0);
    ///
    /// // Plan with placeholder code of the final size.
    /// let layout = builder.clone().add_section(text(vec![0; 8])).try_layout()?;
    /// let data = layout.section(".data").expect("the layout has .data").addr;
    /// // The code holds the address of `.data`.
    /// let file = builder.add_section(text(data.to_le_bytes().to_vec())).try_build()?;
    ///
    /// let section = file.section_by_name(".data").expect("the file has .data");
    /// assert_eq!(section.header.addr, data);
    /// assert_eq!(Some(file.entry_point()), layout.entry_point());
    /// # Ok::<(), elfex::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::try_build`].
    pub fn try_layout(&self) -> Result<BuilderLayout> {
        layout::preview(self)
    }

    /// Build the file.
    ///
    /// The result parses with [`ElfFile::parse`], and its round trip is lossless.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) for an
    ///   unknown `link_name`, an unknown entry section, an unknown or non-`SHF_ALLOC` section
    ///   of a segment, more than one interpreter, an interpreter with a `.interp` section, a
    ///   `.shstrtab` section, data in a `SHT_NOBITS` section, or an alignment that is not 0
    ///   or a power of two.
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if the page
    ///   size is not a power of two, or if the base address is not a multiple of it.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an
    ///   address or offset overflows, or does not fit in 32 bits in an ELF32 file.
    pub fn try_build(&self) -> Result<ElfFile> {
        ElfFile::from_vec(layout::write(self)?)
    }

    /// Build the file, or panic if the input is not valid.
    ///
    /// # Panics
    ///
    /// Panic if [`Self::try_build`] returns an error. Use [`Self::try_build`] to handle
    /// invalid input.
    #[must_use]
    pub fn build(&self) -> ElfFile {
        self.try_build()
            .expect("ElfBuilder build failed: use try_build() to handle invalid input")
    }
}
