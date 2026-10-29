//! # Elfex
//!
//! A `no_std`-friendly library that reads, edits and writes ELF (Executable and Linkable
//! Format) files and images.
//!
//! The library keeps raw files and loader-mapped images separate, because each layout
//! translates a virtual address to a source offset in a different way.
//!
//! ## Features
//!
//! - **ELF32 and ELF64, both byte orders**: [`Encoding`] decodes all multi-byte values.
//! - **Multiple loading modes**: Load raw files or loader-mapped images from memory slices. For
//!   a custom source (for example, remote process memory), implement the [`ReadAt`] trait.
//! - **Partial loading**: Use [`ElfHeaders`] to parse only the headers.
//! - **Self-contained**: The crate defines all ELF structures itself.
//! - **`no_std` mode**: Disable the `std` feature for `no_std + alloc` builds. Only the file
//!   system helpers and `FileReader` need `std`.
//! - **Stream I/O**: `nostdio` supplies the `Read`, `Write` and `Seek` traits and the
//!   `nostdio::IoError` type. With the `std` feature, these are the `std::io` items.
//! - **Targets**: The crate needs a `usize` of at least 32 bits. A compile-time check rejects
//!   a target with a smaller `usize`.
//!
//! ## Architecture
//!
//! The library uses the same two-tier pattern for all tables:
//!
//! 1. **Raw structures** use `parse(&[u8], Encoding)` to parse one fixed-size structure, and
//!    `write(&mut Vec<u8>, Encoding)` to serialize it.
//! 2. **Tables** use `parse(&[u8], Encoding, ...)` to parse the contiguous bytes of a table.
//!    The bytes come from a section or from a range that the dynamic table names.
//!
//! Each table builder serializes a table into bytes. Each `build` method panics on invalid
//! input. Use the matching `try_build` method to get a `Result`.
//!
//! `ElfFile` and `ElfImage` also read the tables for you, for example
//! [`ElfFile::dynamic_symbol_list`], [`ElfFile::notes`] and [`ElfImage::core_file_mappings`].
//! Each of these accessors parses its tables again. [`ElfFile::linking`] and
//! [`ElfImage::linking`] give a [`LinkingView`] that parses each dynamic linking table only
//! once. `ElfFile` also reads the section tables of a relocatable file:
//!
//! - [`ElfFile::symbol_list`] and [`ElfFile::lookup_symbol`] give each symbol as a
//!   [`NamedSymbol`] with its name and its section.
//! - [`ElfFile::relocation_sections`] gives each [`RelocationSection`] with its target section.
//! - [`ElfFile::section_groups`] gives each [`SectionGroup`], for example a COMDAT group.
//!
//! ## Example
//!
//! ```
//! use elfex::section::{SHF_ALLOC, SHF_EXECINSTR};
//! use elfex::{BuilderSection, ElfBuilder, ElfFile, ElfHeaders, ElfImage, Encoding, Machine};
//!
//! // Build a small x86-64 executable. The code is `xor edi, edi; mov eax, 60; syscall`.
//! let bytes = ElfBuilder::new(Encoding::ELF64_LE)
//!     .machine(Machine::X86_64)
//!     .add_section(BuilderSection::progbits(
//!         ".text",
//!         SHF_ALLOC | SHF_EXECINSTR,
//!         vec![0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05],
//!     ))
//!     .entry_in_section(".text", 0)
//!     .try_build()?
//!     .try_build()?;
//!
//! // ElfFile keeps all bytes and gives the sections.
//! let file = ElfFile::parse(&bytes)?;
//! assert!(file.is_64bit());
//! assert!(file.section_by_name(".text").is_some());
//!
//! // ElfImage gives the loader view: the segments.
//! let image = ElfImage::parse(&bytes)?;
//! assert_eq!(image.load_segments().count(), 2);
//!
//! // ElfHeaders reads only the headers.
//! let headers = ElfHeaders::from_slice(&bytes)?;
//! assert_eq!(headers.entry_point(), file.entry_point());
//! # Ok::<(), elfex::Error>(())
//! ```
//!
//! The `examples/` directory of the repository has four command line tools: `elfdump`,
//! `elfpatch`, `dump-process` and `build-tiny`.

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// The crate converts many 32-bit ELF values to `usize`. A smaller `usize` cannot hold them.
const _: () = assert!(
    usize::BITS >= 32,
    "elfex needs a target with a `usize` of at least 32 bits"
);

/// Internal prelude. Each source file uses `use crate::prelude::*;` to get the `alloc`
/// types and macros that the code needs.
///
/// With this prelude, the import header of each module is one line. It also keeps the
/// `no_std` imports in one location, so modules do not repeat `#[cfg]` blocks. All items
/// are `alloc` re-exports. Under the `std` feature, they shadow prelude items of the same
/// type, and this causes no problem.
pub(crate) mod prelude {
    pub use alloc::borrow::Cow;
    pub use alloc::collections::BTreeMap;
    pub use alloc::format;
    pub use alloc::string::{String, ToString};
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

/// Define a newtype for an ELF value with named constants.
///
/// The newtype keeps unknown values. It implements `name()`, which returns the specification
/// name of a known value, and `Display`, which prints the name or the hexadecimal value.
///
/// Write constants that share a value with another constant (for example processor-specific
/// values) in a separate `impl` block. Then `name()` does not return their names.
macro_rules! elf_value_type {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident($inner:ty);
        $(
            $(#[$const_meta:meta])*
            $constant:ident = $value:expr, $text:literal;
        )*
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
        $vis struct $name(pub $inner);

        impl $name {
            $(
                $(#[$const_meta])*
                pub const $constant: Self = Self($value);
            )*

            /// Return the specification name of the value, or `None` for an unknown value.
            #[must_use]
            pub const fn name(self) -> Option<&'static str> {
                $(
                    if self.0 == $value {
                        return Some($text);
                    }
                )*
                None
            }
        }

        impl From<$inner> for $name {
            fn from(value: $inner) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $inner {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, "{:#x}", self.0),
                }
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }
    };
}

pub mod builder;
pub mod dynamic;
pub mod eh_frame;
pub mod elf;
pub mod elf_file;
pub mod elf_image;
pub mod endian;
pub mod error;
pub mod group;
pub mod hash;
pub mod header;
pub mod headers;
pub mod ident;
pub mod image;
pub mod io;
pub mod linking;
pub mod note;
pub mod program;
pub mod reader;
pub mod reloc;
pub mod section;
pub mod strtab;
pub mod symbol;
pub mod tables;
pub mod validation;
pub mod version;

pub use builder::{BuilderLayout, BuilderSection, ElfBuilder, SectionPlacement};
pub use dynamic::{DynamicEntry, DynamicInfo, DynamicTable, DynamicTag};
pub use eh_frame::{Cie, EhFrame, EhFrameEntry, EhFrameHdr, EhFrameHdrEntry, Fde, PointerBases};
pub use elf::{ElfHeaders, MissingSegmentData, ParseOptions, SourceLayout};
pub use elf_file::{ElfFile, NewSection, RelocationSection, SectionGroup, SectionRef};
pub use elf_image::{ElfImage, Segment};
pub use endian::{Class, Encoding, Endian};
pub use error::{Error, ErrorContext, ErrorKind, Result};
pub use group::GroupTable;
pub use hash::{GnuHashTable, SysvHashTable};
pub use header::{FileHeader, FileType, Machine};
pub use ident::{Ident, OsAbi};
pub use linking::{DynamicRelocations, LinkingView, VersionTables};
pub use note::{AuxvEntry, FileMapping, GnuAbiTag, GnuProperty, Note, NoteTable};
pub use program::{ProgramHeader, SegmentType};
#[cfg(feature = "std")]
pub use reader::FileReader;
pub use reader::{BaseAddressReader, ReadAt, SeekReader, SliceReader, VecReader};
pub use reloc::{Relocation, RelocationTable, RelrTable};
pub use section::{CompressionHeader, CompressionType, SectionHeader, SectionType};
pub use strtab::{StringTable, StringTableBuilder};
pub use symbol::{
    BuiltSymbolTable, NamedSymbol, NewSymbol, Symbol, SymbolBinding, SymbolSectionIndexTable,
    SymbolTable, SymbolTableBuilder, SymbolType, SymbolVisibility,
};
pub use validation::{ValidationCode, ValidationIssue, ValidationLevel, ValidationResult};
pub use version::{
    SymbolVersion, VersionDefinition, VersionDefinitionTable, VersionMap, VersionName,
    VersionNeedEntry, VersionRequirement, VersionRequirementTable, VersymTable,
};

// Compile the Rust examples in the README as doctests, so that they follow the API. The
// quick start uses the `std` file helpers.
#[cfg(all(doctest, feature = "std"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
