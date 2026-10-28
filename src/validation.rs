//! Validation results: the structural problems of an ELF file or image.
//!
//! [`ElfFile::validate`](crate::ElfFile::validate) and
//! [`ElfImage::validate`](crate::ElfImage::validate) check the headers and return a
//! [`ValidationResult`]. Each [`ValidationIssue`] has a [`ValidationLevel`] and a
//! [`ValidationCode`].
//!
//! # Examples
//!
//! ```
//! use elfex::section::{SHF_ALLOC, SHF_EXECINSTR};
//! use elfex::{BuilderSection, ElfBuilder, Encoding, ValidationCode};
//!
//! let mut file = ElfBuilder::new(Encoding::ELF64_LE)
//!     .add_section(BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0xc3]))
//!     .entry_in_section(".text", 0)
//!     .try_build()?;
//! assert!(!file.validate().has_errors());
//!
//! // Move the entry point out of the executable segment.
//! file.set_entry_point(0x10);
//! let issues = file.validate();
//! for issue in &issues {
//!     println!("{}: {}", issue.level, issue.message);
//! }
//! assert!(issues.contains(ValidationCode::EntryPointOutOfBounds));
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::prelude::*;
use core::fmt;

/// Severity level of a validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValidationLevel {
    /// Warning: the ELF can be valid, but it has suspicious characteristics.
    Warning,
    /// Error: the ELF has structural problems that probably make it invalid.
    Error,
}

impl fmt::Display for ValidationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationLevel::Warning => write!(f, "Warning"),
            ValidationLevel::Error => write!(f, "Error"),
        }
    }
}

/// Type of validation issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ValidationCode {
    /// `EI_VERSION` or `e_version` is not `EV_CURRENT`.
    UnsupportedVersion,
    /// `e_ehsize`, `e_phentsize` or `e_shentsize` is not the size of the structure.
    InvalidHeaderSize,
    /// The file type does not agree with the content, for example `ET_EXEC` without
    /// `PT_LOAD` segments.
    InconsistentFileType,
    /// The entry point is not in an executable `PT_LOAD` segment.
    EntryPointOutOfBounds,
    /// A segment or the program header table goes past the end of the file.
    SegmentOutOfFile,
    /// A `PT_LOAD` segment has `p_filesz` larger than `p_memsz`.
    SegmentFileSizeTooLarge,
    /// A segment alignment is not a power of 2, or `p_offset` and `p_vaddr` do not agree
    /// modulo the alignment.
    MisalignedSegment,
    /// Two `PT_LOAD` segments overlap in memory.
    OverlappingSegments,
    /// The `PT_LOAD` segments are not sorted by virtual address.
    UnsortedSegments,
    /// The file has more than one segment of a type that must be unique, for example
    /// `PT_INTERP`, `PT_DYNAMIC` or `PT_PHDR`.
    DuplicateSegment,
    /// A segment that the loader reads, for example `PT_DYNAMIC` or `PT_PHDR`, is not in a
    /// `PT_LOAD` segment.
    SegmentNotLoaded,
    /// The `PT_INTERP` segment is not a null-terminated path.
    InvalidInterpreter,
    /// A section or the section header table goes past the end of the file.
    SectionOutOfFile,
    /// A section with `SHF_ALLOC` is not in a `PT_LOAD` segment, or its file offset and
    /// address do not agree with the segment.
    SectionOutsideSegment,
    /// A section `sh_link` or `sh_info` index is out of range.
    InvalidSectionLink,
    /// `e_shstrndx` does not name a `SHT_STRTAB` section.
    InvalidStringTableIndex,
    /// A section alignment is not 0 or a power of 2, or the section address is not aligned.
    MisalignedSection,
    /// The dynamic table is malformed, or a dynamic entry refers to an unmapped address.
    InvalidDynamic,
    /// A symbol, string, relocation, note, hash or version table is malformed.
    InvalidTable,
}

impl fmt::Display for ValidationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A single validation issue.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidationIssue {
    /// Severity of the issue.
    pub level: ValidationLevel,
    /// Type of issue.
    pub code: ValidationCode,
    /// Description for humans.
    pub message: String,
    /// Optional context (for example, a section name or an address).
    pub context: Option<String>,
}

impl ValidationIssue {
    /// Create a new error.
    pub fn error(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Error,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Create a new warning.
    pub fn warning(code: ValidationCode, message: impl Into<String>) -> Self {
        Self {
            level: ValidationLevel::Warning,
            code,
            message: message.into(),
            context: None,
        }
    }

    /// Add context to this issue.
    #[must_use]
    pub fn with_context(mut self, context: impl Into<String>) -> Self {
        self.context = Some(context.into());
        self
    }

    /// Check if this is an error.
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.level == ValidationLevel::Error
    }

    /// Check if this is a warning.
    #[must_use]
    pub fn is_warning(&self) -> bool {
        self.level == ValidationLevel::Warning
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.level, self.code, self.message)?;
        if let Some(ctx) = &self.context {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

/// Collection of validation issues.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ValidationResult {
    /// All validation issues found.
    pub issues: Vec<ValidationIssue>,
}

impl ValidationResult {
    /// Create an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self { issues: Vec::new() }
    }

    /// Add an issue.
    pub fn push(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    /// Check if there are any errors.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.issues.iter().any(ValidationIssue::is_error)
    }

    /// Check if there are any warnings.
    #[must_use]
    pub fn has_warnings(&self) -> bool {
        self.issues.iter().any(ValidationIssue::is_warning)
    }

    /// Check if there are no issues.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.issues.is_empty()
    }

    /// Get only errors.
    pub fn errors(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|i| i.is_error())
    }

    /// Get only warnings.
    pub fn warnings(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter().filter(|i| i.is_warning())
    }

    /// Iterate over all issues.
    pub fn iter(&self) -> core::slice::Iter<'_, ValidationIssue> {
        self.issues.iter()
    }

    /// Number of issues.
    #[must_use]
    pub fn len(&self) -> usize {
        self.issues.len()
    }

    /// Check if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    /// Count of errors.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_error()).count()
    }

    /// Count of warnings.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.issues.iter().filter(|i| i.is_warning()).count()
    }

    /// Return `true` if an issue has `code`.
    #[must_use]
    pub fn contains(&self, code: ValidationCode) -> bool {
        self.issues.iter().any(|issue| issue.code == code)
    }
}

impl IntoIterator for ValidationResult {
    type Item = ValidationIssue;
    type IntoIter = vec::IntoIter<ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.into_iter()
    }
}

impl<'a> IntoIterator for &'a ValidationResult {
    type Item = &'a ValidationIssue;
    type IntoIter = core::slice::Iter<'a, ValidationIssue>;

    fn into_iter(self) -> Self::IntoIter {
        self.issues.iter()
    }
}
