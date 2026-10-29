//! Error types for ELF parsing and writing.
//!
//! Each fallible function returns a [`Result`] with an [`Error`]. [`Error::kind`] gives the
//! [`ErrorKind`]. An error can also have an [`ErrorContext`]: a file offset, a virtual
//! address, a structure name and details. Use the context to find the cause of a problem when
//! you parse or write an ELF file.
//!
//! # Examples
//!
//! ```
//! use elfex::{ElfFile, ErrorKind};
//!
//! let error = ElfFile::parse(&[0; 64]).expect_err("zeros are not an ELF file");
//! assert!(matches!(error.kind(), ErrorKind::InvalidMagic));
//!
//! let error = ElfFile::parse(b"\x7fELF\x02\x01\x01").expect_err("the file is truncated");
//! assert!(matches!(error.kind(), ErrorKind::BufferTooSmall { .. }));
//! if let Some(context) = error.context() {
//!     println!("{error}: {context}");
//! }
//! ```

use crate::prelude::*;
use core::fmt;

/// Result type alias for elfex operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Information about the location of an error.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct ErrorContext {
    /// Source offset where the error occurred (if known).
    pub file_offset: Option<u64>,
    /// Virtual address where the error occurred (if known).
    pub address: Option<u64>,
    /// Name of the structure that the parser was reading (if known).
    pub structure: Option<String>,
    /// Additional details about the error.
    pub details: Option<String>,
}

impl ErrorContext {
    /// Create an empty context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the source offset.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        self.file_offset = Some(offset);
        self
    }

    /// Set the virtual address.
    #[must_use]
    pub fn at_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    /// Set the structure name.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        self.structure = Some(name.into());
        self
    }

    /// Set additional details.
    #[must_use]
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Return `true` if the context has no information.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.file_offset.is_none()
            && self.address.is_none()
            && self.structure.is_none()
            && self.details.is_none()
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(offset) = self.file_offset {
            parts.push(format!("offset {offset:#x}"));
        }
        if let Some(address) = self.address {
            parts.push(format!("address {address:#x}"));
        }
        if let Some(structure) = &self.structure {
            parts.push(format!("in {structure}"));
        }
        if let Some(details) = &self.details {
            parts.push(details.clone());
        }
        write!(f, "{}", parts.join(", "))
    }
}

/// An error from parsing or writing an ELF file.
#[derive(Debug)]
pub struct Error {
    /// The error kind.
    pub kind: ErrorKind,
    /// Optional context about where the error occurred.
    pub context: Option<ErrorContext>,
}

/// The kind of error that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ErrorKind {
    /// I/O error from a `nostdio` stream. With the `std` feature, this is `std::io::Error`.
    Io(nostdio::IoError),
    /// The identification bytes do not start with `\x7fELF`.
    InvalidMagic,
    /// The `EI_CLASS` byte is not `ELFCLASS32` or `ELFCLASS64`.
    InvalidClass(u8),
    /// The `EI_DATA` byte is not `ELFDATA2LSB` or `ELFDATA2MSB`.
    InvalidDataEncoding(u8),
    /// The buffer is too small for the expected data.
    BufferTooSmall {
        /// Number of bytes required.
        expected: usize,
        /// Number of bytes available.
        actual: usize,
    },
    /// Invalid ELF file header (`Elf32_Ehdr` or `Elf64_Ehdr`).
    InvalidHeader(String),
    /// Invalid program header or segment data.
    InvalidSegment(String),
    /// Invalid section header or section data.
    InvalidSection(String),
    /// Invalid table: dynamic, symbol, string, relocation, note, hash or version data.
    InvalidTable(String),
    /// Offset out of bounds.
    OffsetOutOfBounds {
        /// The offset that is out of bounds.
        offset: u64,
        /// Size of the region that the check used.
        size: u64,
    },
    /// Invalid virtual address (no segment maps the data at this address).
    InvalidAddress(u64),
    /// A value does not fit in the field that must hold it, for example a 64-bit address in an
    /// ELF32 field.
    ValueOutOfRange(String),
    /// Invalid UTF-8 string.
    InvalidUtf8,
    /// Generic error with a message.
    Generic(String),
}

impl Error {
    /// Create a new error with the given kind.
    #[must_use]
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
        }
    }

    /// Add context to this error.
    #[must_use]
    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Add source offset context.
    #[must_use]
    pub fn at_offset(mut self, offset: u64) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.at_offset(offset));
        self
    }

    /// Add virtual address context.
    #[must_use]
    pub fn at_address(mut self, address: u64) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.at_address(address));
        self
    }

    /// Add structure name context.
    #[must_use]
    pub fn in_structure(mut self, name: impl Into<String>) -> Self {
        let ctx = self.context.take().unwrap_or_default();
        self.context = Some(ctx.in_structure(name));
        self
    }

    /// Get the context if present.
    #[must_use]
    pub fn context(&self) -> Option<&ErrorContext> {
        self.context.as_ref()
    }

    /// Get the error kind.
    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// Return a copy of the error. An I/O error becomes a generic error with the same text,
    /// because an I/O error cannot be copied.
    #[must_use]
    pub(crate) fn duplicate(&self) -> Self {
        let kind = match &self.kind {
            ErrorKind::Io(error) => ErrorKind::Generic(format!("I/O error: {error}")),
            ErrorKind::InvalidMagic => ErrorKind::InvalidMagic,
            ErrorKind::InvalidClass(class) => ErrorKind::InvalidClass(*class),
            ErrorKind::InvalidDataEncoding(data) => ErrorKind::InvalidDataEncoding(*data),
            ErrorKind::BufferTooSmall { expected, actual } => ErrorKind::BufferTooSmall {
                expected: *expected,
                actual: *actual,
            },
            ErrorKind::InvalidHeader(message) => ErrorKind::InvalidHeader(message.clone()),
            ErrorKind::InvalidSegment(message) => ErrorKind::InvalidSegment(message.clone()),
            ErrorKind::InvalidSection(message) => ErrorKind::InvalidSection(message.clone()),
            ErrorKind::InvalidTable(message) => ErrorKind::InvalidTable(message.clone()),
            ErrorKind::OffsetOutOfBounds { offset, size } => ErrorKind::OffsetOutOfBounds {
                offset: *offset,
                size: *size,
            },
            ErrorKind::InvalidAddress(address) => ErrorKind::InvalidAddress(*address),
            ErrorKind::ValueOutOfRange(message) => ErrorKind::ValueOutOfRange(message.clone()),
            ErrorKind::InvalidUtf8 => ErrorKind::InvalidUtf8,
            ErrorKind::Generic(message) => ErrorKind::Generic(message.clone()),
        };
        Self {
            kind,
            context: self.context.clone(),
        }
    }

    /// Create an `InvalidMagic` error.
    #[must_use]
    pub fn invalid_magic() -> Self {
        Self::new(ErrorKind::InvalidMagic)
    }

    /// Create a `BufferTooSmall` error.
    #[must_use]
    pub fn buffer_too_small(expected: usize, actual: usize) -> Self {
        Self::new(ErrorKind::BufferTooSmall { expected, actual })
    }

    /// Create an `InvalidHeader` error.
    #[must_use]
    pub fn invalid_header(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidHeader(msg.into()))
    }

    /// Create an `InvalidSegment` error.
    #[must_use]
    pub fn invalid_segment(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidSegment(msg.into()))
    }

    /// Create an `InvalidSection` error.
    #[must_use]
    pub fn invalid_section(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidSection(msg.into()))
    }

    /// Create an `InvalidTable` error.
    #[must_use]
    pub fn invalid_table(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidTable(msg.into()))
    }

    /// Create an `OffsetOutOfBounds` error.
    #[must_use]
    pub fn offset_out_of_bounds(offset: u64, size: u64) -> Self {
        Self::new(ErrorKind::OffsetOutOfBounds { offset, size })
    }

    /// Create an `InvalidAddress` error.
    #[must_use]
    pub fn invalid_address(address: u64) -> Self {
        Self::new(ErrorKind::InvalidAddress(address))
    }

    /// Create a `ValueOutOfRange` error.
    #[must_use]
    pub fn value_out_of_range(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::ValueOutOfRange(msg.into()))
    }

    /// Create an `InvalidUtf8` error.
    #[must_use]
    pub fn invalid_utf8() -> Self {
        Self::new(ErrorKind::InvalidUtf8)
    }

    /// Create a `Generic` error with a message.
    #[must_use]
    pub fn generic(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::Generic(msg.into()))
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io(e) => write!(f, "I/O error: {e}"),
            ErrorKind::InvalidMagic => write!(f, "Invalid ELF magic (expected '\\x7fELF')"),
            ErrorKind::InvalidClass(class) => write!(f, "Invalid ELF class: {class}"),
            ErrorKind::InvalidDataEncoding(data) => {
                write!(f, "Invalid ELF data encoding: {data}")
            }
            ErrorKind::BufferTooSmall { expected, actual } => {
                write!(
                    f,
                    "Buffer too small: expected {expected} bytes, got {actual}"
                )
            }
            ErrorKind::InvalidHeader(msg) => write!(f, "Invalid ELF header: {msg}"),
            ErrorKind::InvalidSegment(msg) => write!(f, "Invalid segment: {msg}"),
            ErrorKind::InvalidSection(msg) => write!(f, "Invalid section: {msg}"),
            ErrorKind::InvalidTable(msg) => write!(f, "Invalid table: {msg}"),
            ErrorKind::OffsetOutOfBounds { offset, size } => {
                write!(f, "Offset {offset:#x} out of bounds (size: {size})")
            }
            ErrorKind::InvalidAddress(address) => {
                write!(f, "Invalid virtual address: {address:#x}")
            }
            ErrorKind::ValueOutOfRange(msg) => write!(f, "Value out of range: {msg}"),
            ErrorKind::InvalidUtf8 => write!(f, "Invalid UTF-8 string"),
            ErrorKind::Generic(msg) => write!(f, "{msg}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.kind)?;
        if let Some(ctx) = &self.context
            && !ctx.is_empty()
        {
            write!(f, " ({ctx})")?;
        }
        Ok(())
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<nostdio::IoError> for Error {
    fn from(e: nostdio::IoError) -> Self {
        Self::new(ErrorKind::Io(e))
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::error::Error as _;

    #[test]
    fn context_setters_fill_the_context_in_order() {
        let error = Error::invalid_table("bad entry")
            .at_offset(0x40)
            .at_address(0x1000)
            .in_structure("Elf64_Sym");
        let context = error.context().unwrap();
        assert_eq!(context.file_offset, Some(0x40));
        assert_eq!(context.address, Some(0x1000));
        assert_eq!(context.structure.as_deref(), Some("Elf64_Sym"));
        assert_eq!(context.details, None);
        assert_eq!(
            error.to_string(),
            "Invalid table: bad entry (offset 0x40, address 0x1000, in Elf64_Sym)"
        );

        let details = ErrorContext::new()
            .in_structure("NT_FILE")
            .with_details("entry 3");
        assert_eq!(details.to_string(), "in NT_FILE, entry 3");
        let error = Error::generic("stop").with_context(details.clone());
        assert_eq!(error.context(), Some(&details));
        assert_eq!(error.to_string(), "stop (in NT_FILE, entry 3)");
    }

    #[test]
    fn empty_context_is_not_displayed() {
        assert!(ErrorContext::new().is_empty());
        assert!(!ErrorContext::new().at_offset(0).is_empty());
        assert!(!ErrorContext::new().with_details("x").is_empty());
        let error = Error::invalid_utf8().with_context(ErrorContext::new());
        assert_eq!(error.to_string(), ErrorKind::InvalidUtf8.to_string());
        assert_eq!(Error::invalid_utf8().to_string(), error.to_string());
    }

    #[test]
    fn kind_display_reports_the_values() {
        let cases = [
            (ErrorKind::InvalidClass(7), "7"),
            (ErrorKind::InvalidDataEncoding(9), "9"),
            (
                ErrorKind::BufferTooSmall {
                    expected: 64,
                    actual: 12,
                },
                "expected 64 bytes, got 12",
            ),
            (ErrorKind::InvalidHeader("e_ehsize".into()), "e_ehsize"),
            (ErrorKind::InvalidSegment("p_align".into()), "p_align"),
            (ErrorKind::InvalidSection("sh_link".into()), "sh_link"),
            (ErrorKind::InvalidTable("DT_HASH".into()), "DT_HASH"),
            (
                ErrorKind::OffsetOutOfBounds {
                    offset: 0x123,
                    size: 16,
                },
                "0x123",
            ),
            (ErrorKind::InvalidAddress(0xbeef), "0xbeef"),
            (ErrorKind::ValueOutOfRange("e_entry".into()), "e_entry"),
            (ErrorKind::Generic("custom".into()), "custom"),
        ];
        for (kind, value) in cases {
            let error = Error::from(kind).at_offset(5);
            let text = error.to_string();
            assert!(text.contains(value), "{text} does not contain {value}");
            let copy = error.duplicate();
            assert_eq!(copy.to_string(), text);
            assert_eq!(copy.context, error.context);
        }
        assert!(Error::invalid_magic().to_string().contains("\\x7fELF"));
        for error in [Error::invalid_magic(), Error::invalid_utf8()] {
            assert_eq!(error.duplicate().to_string(), error.to_string());
        }
    }

    #[test]
    fn io_errors_keep_their_source() {
        let error = Error::from(nostdio::interrupted());
        assert!(matches!(error.kind(), ErrorKind::Io(io) if nostdio::is_interrupted(io)));
        assert!(error.source().is_some());
        assert!(error.to_string().starts_with("I/O error: "));
        assert!(Error::invalid_address(0).source().is_none());
        // An I/O error cannot be copied, so the copy is a generic error with the same text.
        let copy = error.duplicate();
        assert!(matches!(copy.kind(), ErrorKind::Generic(_)));
        assert_eq!(copy.to_string(), error.to_string());
    }
}
