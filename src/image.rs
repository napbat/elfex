//! APIs that parse, edit and build a full image.
//!
//! Use [`ElfFile`] for a raw file: it keeps all bytes and gives access to the sections. Use
//! [`ElfImage`] for the loader view of a raw file or of a loader-mapped image. Use
//! [`ElfBuilder`] to build a new file.

pub use crate::builder::{BuilderSection, ElfBuilder};
pub use crate::elf::{ElfHeaders, MissingSegmentData, ParseOptions, SourceLayout};
pub use crate::elf_file::{ElfFile, NewSection, SectionRef};
pub use crate::elf_image::{ElfImage, Segment};
pub use crate::validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};
