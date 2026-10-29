//! The loader view of an ELF image.
//!
//! [`ElfImage`] holds the ELF file header and one [`Segment`] for each program header. It has
//! no sections. Use it for a loader-mapped image, for the memory of a remote process, or to
//! read a raw file as the loader sees it. Use [`ElfFile`](crate::ElfFile) for sections and for
//! lossless edits of a raw file.
//!
//! # Examples
//!
//! ```
//! use elfex::elf_image::ElfImage;
//! # use elfex::section::{SHF_ALLOC, SHF_EXECINSTR};
//! # use elfex::{BuilderSection, ElfBuilder, Encoding};
//!
//! # let file_bytes = ElfBuilder::new(Encoding::ELF64_LE)
//! #     .interpreter("/lib/ld.so")
//! #     .add_section(BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0xc3]))
//! #     .entry_in_section(".text", 0)
//! #     .try_build()?
//! #     .try_build()?;
//! let image = ElfImage::parse(&file_bytes)?;
//! println!("Entry point: {:#x}", image.entry_point());
//! for segment in image.load_segments() {
//!     println!(
//!         "{} at {:#x}: {} bytes",
//!         segment.header.segment_type,
//!         segment.header.vaddr,
//!         segment.data.len()
//!     );
//! }
//! if let Some(interpreter) = image.interpreter()? {
//!     println!("Interpreter: {interpreter}");
//! }
//! let mapped = image.to_mapped_image()?;
//! let again = ElfImage::parse_mapped(&mapped)?;
//! assert_eq!(again.entry_point(), image.entry_point());
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::elf::{ElfHeaders, SourceLayout};
use crate::endian::Encoding;
use crate::header::{FileHeader, FileType, Machine};
use crate::prelude::*;
use crate::program::{ProgramHeader, SegmentType};
use crate::{Error, Result};

mod build;
mod linking;
mod memory;
mod parse;
mod relocate;
#[cfg(test)]
mod tests;

/// A segment of an [`ElfImage`]: a program header and the bytes that belong to it.
///
/// The content of [`Self::data`] depends on the segment type and the source layout:
///
/// - `PT_LOAD` from a raw file: the `p_filesz` bytes at the file offset `p_offset`.
/// - `PT_LOAD` from a loader-mapped image: up to `p_memsz` bytes of memory at `p_vaddr`. The
///   memory after `p_filesz` can hold data that the program wrote at run time.
/// - Other segments from a raw file, if no `PT_LOAD` file range contains their file range (for
///   example `PT_NOTE` in a core file): the `p_filesz` bytes at `p_offset`.
/// - All other segments: no bytes. Their bytes are in a `PT_LOAD` segment. Read them with
///   [`ElfImage::read_vaddr`].
///
/// The data borrows the source bytes when the parser reads a byte slice, and is a copy when
/// it reads a [`ReadAt`](crate::ReadAt) source. A write makes a copy of borrowed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment<'a> {
    /// The program header (`Elf32_Phdr` or `Elf64_Phdr`).
    pub header: ProgramHeader,
    /// The bytes of the segment. The bytes start at the virtual address `p_vaddr`.
    pub data: Cow<'a, [u8]>,
}

impl Segment<'_> {
    /// Return the size of the segment in memory (`p_memsz`).
    #[must_use]
    pub const fn memory_size(&self) -> u64 {
        self.header.memsz
    }

    /// Return `true` for a `PT_LOAD` segment.
    #[must_use]
    pub fn is_load(&self) -> bool {
        self.header.is_load()
    }

    /// Return a segment that owns a copy of its data.
    #[must_use]
    pub fn into_owned(self) -> Segment<'static> {
        Segment {
            header: self.header,
            data: Cow::Owned(self.data.into_owned()),
        }
    }

    /// Return the data bytes that are in the memory range: at most `p_memsz` bytes.
    pub(crate) fn memory_data(&self) -> &[u8] {
        let limit = usize::try_from(self.header.memsz)
            .map_or(self.data.len(), |size| size.min(self.data.len()));
        self.data.get(..limit).unwrap_or(&self.data)
    }
}

/// The loader view of an ELF file or a loader-mapped ELF image.
///
/// The image holds the file header and one [`Segment`] for each program header, in program
/// header order. It does not hold sections. The segments borrow the source bytes for the
/// lifetime `'a` when the parser reads a byte slice ([`Self::parse`]). Use
/// [`Self::into_owned`] to keep the image after the bytes go out of scope.
///
/// - Parse a raw file with [`Self::parse`], and a loader-mapped image with
///   [`Self::parse_mapped`]. Read from any [`ReadAt`](crate::ReadAt) source with
///   [`Self::read_from_with_options`].
/// - Read and write memory at virtual addresses with [`Self::read_vaddr`] and
///   [`Self::write_vaddr`].
/// - Make a loader-mapped image with [`Self::to_mapped_image`], and a raw file without
///   sections with [`Self::try_build`].
///
/// # Examples
///
/// ```
/// use elfex::program::SegmentType;
/// use elfex::section::{SHF_ALLOC, SHF_WRITE};
/// use elfex::{BuilderSection, ElfBuilder, ElfImage, Encoding, SourceLayout};
///
/// let file = ElfBuilder::new(Encoding::ELF64_LE)
///     .add_section(BuilderSection::progbits(".data", SHF_ALLOC | SHF_WRITE, vec![1, 2, 3, 4]))
///     .try_build()?;
/// let data = file.section_by_name(".data").expect("the file has .data").header.addr;
///
/// let bytes = file.try_build()?;
/// let image = ElfImage::parse(&bytes)?;
/// assert_eq!(image.source_layout(), SourceLayout::File);
/// assert_eq!(image.read_vaddr(data, 4)?, [1, 2, 3, 4]);
/// assert!(image.segment(SegmentType::GNU_STACK).is_some());
///
/// // Make the bytes that a loader maps, and parse them again.
/// let mapped_bytes = image.to_mapped_image()?;
/// let mapped = ElfImage::parse_mapped(&mapped_bytes)?;
/// assert_eq!(mapped.source_layout(), SourceLayout::Mapped);
/// assert_eq!(mapped.read_vaddr(data, 4)?, [1, 2, 3, 4]);
/// # Ok::<(), elfex::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfImage<'a> {
    /// The ELF file header (`Elf32_Ehdr` or `Elf64_Ehdr`).
    pub header: FileHeader,
    /// The segments, one for each program header, in program header order.
    pub segments: Vec<Segment<'a>>,
    /// The layout of the source that the parser read.
    source_layout: SourceLayout,
    /// The runtime address of the image origin, if it is known.
    runtime_base: Option<u64>,
}

impl<'a> ElfImage<'a> {
    /// Create an image from a file header and segments.
    ///
    /// The image has the file layout and no runtime base.
    #[must_use]
    pub fn new(header: FileHeader, segments: Vec<Segment<'a>>) -> Self {
        Self {
            header,
            segments,
            source_layout: SourceLayout::File,
            runtime_base: None,
        }
    }

    /// Return an image that owns copies of all segment data.
    #[must_use]
    pub fn into_owned(self) -> ElfImage<'static> {
        ElfImage {
            header: self.header,
            segments: self.segments.into_iter().map(Segment::into_owned).collect(),
            source_layout: self.source_layout,
            runtime_base: self.runtime_base,
        }
    }

    /// Return the class and the byte order of the image.
    #[must_use]
    pub const fn encoding(&self) -> Encoding {
        self.header.encoding()
    }

    /// Return `true` for an ELF64 image.
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

    /// Return the layout of the source that the parser read.
    ///
    /// An image that [`Self::new`] creates has the file layout.
    #[must_use]
    pub const fn source_layout(&self) -> SourceLayout {
        self.source_layout
    }

    /// Return the runtime address of the image origin, if the parse options gave it.
    #[must_use]
    pub const fn runtime_base(&self) -> Option<u64> {
        self.runtime_base
    }

    /// Iterate over the program headers, in program header order.
    pub fn program_headers(&self) -> impl ExactSizeIterator<Item = &ProgramHeader> {
        self.segments.iter().map(|segment| &segment.header)
    }

    /// Return the headers of the image: the file header and the program headers.
    ///
    /// The result has no section headers, because the image has no sections.
    #[must_use]
    pub fn headers(&self) -> ElfHeaders {
        ElfHeaders {
            header: self.header,
            program_headers: self.program_headers().copied().collect(),
            section_headers: Vec::new(),
            section_names: Vec::new(),
        }
    }

    /// Iterate over the `PT_LOAD` segments.
    pub fn load_segments(&self) -> impl Iterator<Item = &Segment<'a>> {
        self.segments.iter().filter(|segment| segment.is_load())
    }

    /// Return the first segment of `segment_type`.
    #[must_use]
    pub fn segment(&self, segment_type: SegmentType) -> Option<&Segment<'a>> {
        self.segments
            .iter()
            .find(|segment| segment.header.segment_type == segment_type)
    }

    /// Return the image origin: the virtual address of file offset 0 in the `PT_LOAD` segment
    /// with the lowest virtual address.
    ///
    /// Offset 0 of a loader-mapped image is at this address. Return `None` if the image has no
    /// `PT_LOAD` segment, or if that segment has a file offset larger than its address.
    #[must_use]
    pub fn image_origin(&self) -> Option<u64> {
        let first = self
            .load_segments()
            .min_by_key(|segment| segment.header.vaddr)?;
        first.header.vaddr.checked_sub(first.header.offset)
    }

    /// Return the end of the highest `PT_LOAD` memory range, or `None` if the image has no
    /// `PT_LOAD` segment or an end overflows.
    #[must_use]
    pub fn image_end(&self) -> Option<u64> {
        self.load_segments()
            .map(|segment| segment.header.memory_range().map(|range| range.end))
            .try_fold(None, |max: Option<u64>, end| {
                let end = end?;
                Some(Some(max.map_or(end, |max| max.max(end))))
            })?
    }

    /// Return the load bias: the runtime base minus the image origin, with wrapping
    /// arithmetic.
    ///
    /// Add the load bias to a virtual address of the file to get the runtime address. Return
    /// `None` if the runtime base or the image origin is unknown.
    #[must_use]
    pub fn load_bias(&self) -> Option<u64> {
        Some(self.runtime_base?.wrapping_sub(self.image_origin()?))
    }

    /// Translate a virtual address of the file to a runtime address, with wrapping
    /// arithmetic.
    ///
    /// Return `None` if the load bias is unknown. The function does not check that a segment
    /// contains the address.
    #[must_use]
    pub fn vaddr_to_runtime(&self, vaddr: u64) -> Option<u64> {
        Some(vaddr.wrapping_add(self.load_bias()?))
    }

    /// Translate a runtime address to a virtual address of the file, with wrapping
    /// arithmetic.
    ///
    /// Return `None` if the load bias is unknown. The function does not check that a segment
    /// contains the address.
    #[must_use]
    pub fn runtime_to_vaddr(&self, address: u64) -> Option<u64> {
        Some(address.wrapping_sub(self.load_bias()?))
    }
}

/// Allocate `len` zero bytes. Return an error if the allocation fails.
fn zeroed(len: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| Error::generic(format!("cannot allocate {len} bytes")))?;
    bytes.resize(len, 0);
    Ok(bytes)
}
