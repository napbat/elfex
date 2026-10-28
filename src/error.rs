//! Error types for ELF parsing and writing.
//!
//! An error can have a context: a file offset, a virtual address, a structure name and details.
//! Use the context to find the cause of a problem when you parse or write an ELF file.
//!
//! # Example
//!
//! ```no_run
//! use elfex::ElfFile;
//!
//! # let file_bytes: &[u8] = &[];
//! match ElfFile::parse(file_bytes) {
//!     Ok(_elf) => println!("Loaded ELF"),
//!     Err(e) => {
//!         eprintln!("Error: {}", e);
//!         if let Some(ctx) = e.context() {
//!             eprintln!("  Context: {}", ctx);
//!         }
//!     }
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
    pub fn invalid_header(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidHeader(msg.into()))
    }

    /// Create an `InvalidSegment` error.
    pub fn invalid_segment(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidSegment(msg.into()))
    }

    /// Create an `InvalidSection` error.
    pub fn invalid_section(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidSection(msg.into()))
    }

    /// Create an `InvalidTable` error.
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
    pub fn value_out_of_range(msg: impl Into<String>) -> Self {
        Self::new(ErrorKind::ValueOutOfRange(msg.into()))
    }

    /// Create an `InvalidUtf8` error.
    #[must_use]
    pub fn invalid_utf8() -> Self {
        Self::new(ErrorKind::InvalidUtf8)
    }

    /// Create a `Generic` error with a message.
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
