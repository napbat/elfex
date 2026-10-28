//! APIs that parse, edit and build a full image.
//!
//! This facade module re-exports the main entry points:
//!
//! - Use [`ElfFile`] for a raw file. It keeps all bytes and gives access to the sections.
//! - Use [`ElfImage`] for the loader view of a raw file or of a loader-mapped image.
//! - Use [`ElfHeaders`] to read only the headers.
//! - Use [`ElfBuilder`] and [`BuilderSection`] to build a new file. [`BuilderLayout`] and
//!   [`SectionPlacement`] give the planned layout before the build.
//! - Use [`ParseOptions`] and [`SourceLayout`] to select how the parser reads a source.
//! - `validate()` returns a [`ValidationResult`] with the problems of a file or an image.

pub use crate::builder::{BuilderLayout, BuilderSection, ElfBuilder, SectionPlacement};
pub use crate::elf::{ElfHeaders, MissingSegmentData, ParseOptions, SourceLayout};
pub use crate::elf_file::{ElfFile, NewSection, SectionRef};
pub use crate::elf_image::{ElfImage, Segment};
pub use crate::validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};
