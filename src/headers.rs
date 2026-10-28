//! The ELF headers and their common value types.
//!
//! This facade module re-exports the header types from their modules:
//!
//! - [`ElfHeaders`]: all headers of a file, without the segment and section data.
//! - [`FileHeader`], [`Ident`] and [`Encoding`]: the file header and its identification.
//! - [`ProgramHeader`] and [`SegmentType`]: the program headers.
//! - [`SectionHeader`], [`SectionType`] and [`CompressionHeader`]: the section headers.
//!
//! The constants (for example `PF_R` and `SHF_ALLOC`) stay in [`crate::program`] and
//! [`crate::section`].

pub use crate::elf::ElfHeaders;
pub use crate::endian::{Class, Encoding, Endian};
pub use crate::header::{FileHeader, FileType, Machine};
pub use crate::ident::{Ident, OsAbi};
pub use crate::program::{ProgramHeader, SegmentType};
pub use crate::section::{CompressionHeader, CompressionType, SectionHeader, SectionType};
