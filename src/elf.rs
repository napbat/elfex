//! Shared types of the image APIs, and [`ElfHeaders`].
//!
//! # Address spaces
//!
//! An ELF file has two address spaces:
//!
//! - The file offset: the position of a byte in the raw file.
//! - The virtual address: the address of a byte in memory, as the link editor gave it. The
//!   `PT_LOAD` program headers map file ranges to virtual address ranges.
//!
//! A loader-mapped image is a copy of the memory of a loaded module. [`SourceLayout::Mapped`]
//! source offset 0 is the image origin: the virtual address of file offset 0 in the `PT_LOAD`
//! segment with the lowest virtual address ([`ElfHeaders::image_origin`]). The ELF header and the
//! program header table are at the origin, because that segment maps the start of the file.
//!
//! A shared object or a position-independent executable can load at a different address. The
//! load bias is the difference between the runtime address and the virtual address in the file.

use crate::header::FileHeader;
use crate::prelude::*;
use crate::program::ProgramHeader;
use crate::section::SectionHeader;

mod headers;
pub(crate) mod validate;

/// The layout of the ELF bytes in their source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SourceLayout {
    /// Raw file layout, as on disk or in a byte-for-byte copy of the file. Segment data is at
    /// its file offset (`p_offset`).
    #[default]
    File,
    /// Loader-mapped image layout. Segment data is at its virtual address minus the image
    /// origin ([`ElfHeaders::image_origin`]).
    Mapped,
}

/// The policy for segment bytes that the parser cannot read from the source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum MissingSegmentData {
    /// Reject segment ranges that the parser cannot read.
    #[default]
    Error,
    /// Keep the program header, and fill the bytes that the parser cannot read with zeros.
    ///
    /// Use this for remote mapped images with pages that are not readable or not committed.
    Zero,
}

/// Options to parse an ELF image from any byte source.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ParseOptions {
    /// How each virtual address maps to an offset in the source.
    pub layout: SourceLayout,
    /// What to do with segment ranges that the parser cannot read.
    pub missing_segment_data: MissingSegmentData,
    /// The runtime address of the image origin in a mapped image, if it is known.
    ///
    /// The image origin is the address of the ELF header in memory. For a shared object that
    /// `dl_iterate_phdr` reports, this is `dlpi_addr` plus [`ElfHeaders::image_origin`].
    pub runtime_base: Option<u64>,
}

impl ParseOptions {
    /// Return the default options for a raw file.
    #[must_use]
    pub const fn file() -> Self {
        Self {
            layout: SourceLayout::File,
            missing_segment_data: MissingSegmentData::Error,
            runtime_base: None,
        }
    }

    /// Return the default options for a loader-mapped image.
    #[must_use]
    pub const fn mapped() -> Self {
        Self {
            layout: SourceLayout::Mapped,
            missing_segment_data: MissingSegmentData::Error,
            runtime_base: None,
        }
    }

    /// Fill segment bytes that the parser cannot read with zeros.
    #[must_use]
    pub const fn allow_missing_segment_data(mut self) -> Self {
        self.missing_segment_data = MissingSegmentData::Zero;
        self
    }

    /// Set the runtime address of the image origin of a mapped image.
    #[must_use]
    pub const fn runtime_base(mut self, runtime_base: u64) -> Self {
        self.runtime_base = Some(runtime_base);
        self
    }
}

/// The maximum number of program headers or section headers that the parser reads from a
/// source with an unknown size.
///
/// A source with a known size limits the tables to the bytes in the source.
pub const MAX_UNSIZED_TABLE_ENTRIES: u64 = 1 << 20;

/// The ELF headers without the segment and section data.
///
/// Use this type for a remote process, or when you need only the header data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeaders {
    /// The ELF file header (`Elf32_Ehdr` or `Elf64_Ehdr`).
    pub header: FileHeader,
    /// The program headers (`Elf32_Phdr` or `Elf64_Phdr`).
    pub program_headers: Vec<ProgramHeader>,
    /// The section headers (`Elf32_Shdr` or `Elf64_Shdr`).
    ///
    /// The list is empty if the file has no section header table, or if the parser cannot read
    /// it. A loader-mapped image usually does not contain the section header table.
    pub section_headers: Vec<SectionHeader>,
    /// The section names that the parser read from the section name string table.
    ///
    /// The list has one entry for each section header. A name that the parser cannot read is
    /// an empty string. A name that is not UTF-8 has replacement characters.
    pub section_names: Vec<String>,
}
