//! ELF headers and their common enums.

pub use crate::elf::ElfHeaders;
pub use crate::endian::{Class, Encoding, Endian};
pub use crate::header::{FileHeader, FileType, Machine};
pub use crate::ident::{Ident, OsAbi};
pub use crate::program::{ProgramHeader, SegmentType};
pub use crate::section::{CompressionHeader, CompressionType, SectionHeader, SectionType};
