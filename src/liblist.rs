//! The prelink library list: `Elf32_Lib` and `Elf64_Lib` entries (`DT_GNU_LIBLIST`,
//! `SHT_GNU_LIBLIST`).
//!
//! The prelink tool writes one entry for each library of the dependency list of an object
//! that it prelinked. The loader compares the time stamp and the checksum of each entry with
//! the library that it loads, to know if the prelinked addresses are still valid.
//!
//! An entry has five `Elf32_Word` values in both classes, so an entry is 20 bytes. Use
//! [`LibraryTable`] to parse and write the entries. The linking accessors
//! ([`LinkingView::library_list`](crate::LinkingView::library_list),
//! [`ElfFile::library_list`](crate::ElfFile::library_list) and
//! [`ElfImage::library_list`](crate::ElfImage::library_list)) give each entry with its name, as
//! a [`LibraryListEntry`].
//!
//! # Examples
//!
//! ```
//! use elfex::Encoding;
//! use elfex::liblist::{LL_EXACT_MATCH, Library, LibraryTable};
//!
//! let table = LibraryTable {
//!     libraries: vec![Library {
//!         name: 1,
//!         time_stamp: 0x6000_0000,
//!         checksum: 0x1234_5678,
//!         version: 0,
//!         flags: LL_EXACT_MATCH,
//!     }],
//! };
//! let bytes = table.write(Encoding::ELF64_LE);
//! assert_eq!(bytes.len(), 20);
//! assert_eq!(LibraryTable::parse(&bytes, Encoding::ELF64_LE)?, table);
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};

/// `LL_NONE`: the entry has no flags.
pub const LL_NONE: u32 = 0;
/// `LL_EXACT_MATCH`: the library must match the time stamp and the checksum exactly.
pub const LL_EXACT_MATCH: u32 = 0x1;
/// `LL_IGNORE_INT_VER`: ignore the interface version of the library.
pub const LL_IGNORE_INT_VER: u32 = 0x2;
/// `LL_REQUIRE_MINOR`: the library needs a minor version.
pub const LL_REQUIRE_MINOR: u32 = 0x4;
/// `LL_EXPORTS`: the library exports symbols.
pub const LL_EXPORTS: u32 = 0x8;
/// `LL_DELAY_LOAD`: load the library on first use.
pub const LL_DELAY_LOAD: u32 = 0x10;
/// `LL_DELTA`: the entry is a delta.
pub const LL_DELTA: u32 = 0x20;

/// One prelink library list entry (`Elf32_Lib` or `Elf64_Lib`), as it is in the file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Library {
    /// `l_name`: the offset of the library name in the dynamic string table.
    pub name: u32,
    /// `l_time_stamp`: the time stamp of the library.
    pub time_stamp: u32,
    /// `l_checksum`: the checksum of the library.
    pub checksum: u32,
    /// `l_version`: the interface version of the library.
    pub version: u32,
    /// `l_flags`: the `LL_*` flags, for example [`LL_EXACT_MATCH`].
    pub flags: u32,
}

impl Library {
    /// The size of an entry in bytes: five `Elf32_Word` values in both classes.
    pub const SIZE: usize = 20;
}

/// The entries of a prelink library list.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LibraryTable {
    /// The entries, in table order.
    pub libraries: Vec<Library>,
}

impl LibraryTable {
    /// Parse the entries from all of `bytes`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is not a multiple of [`Library::SIZE`].
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        if !bytes.len().is_multiple_of(Library::SIZE) {
            return Err(Error::invalid_table(format!(
                "the library list size {} is not a multiple of {}",
                bytes.len(),
                Library::SIZE
            ))
            .in_structure("Elf_Lib"));
        }
        let entries = bytes
            .as_chunks::<{ Library::SIZE }>()
            .0
            .iter()
            .map(|chunk| {
                Ok(Library {
                    name: encoding.read_u32(chunk, 0)?,
                    time_stamp: encoding.read_u32(chunk, 4)?,
                    checksum: encoding.read_u32(chunk, 8)?,
                    version: encoding.read_u32(chunk, 12)?,
                    flags: encoding.read_u32(chunk, 16)?,
                })
            });
        let libraries = crate::collect_exact(entries)?;
        Ok(Self { libraries })
    }

    /// Serialize the entries.
    #[must_use]
    pub fn write(&self, encoding: Encoding) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.libraries.len().saturating_mul(Library::SIZE));
        for library in &self.libraries {
            for word in [
                library.name,
                library.time_stamp,
                library.checksum,
                library.version,
                library.flags,
            ] {
                encoding.write_u32(&mut out, word);
            }
        }
        out
    }
}

/// One prelink library list entry with its name.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct LibraryListEntry {
    /// The library name from the dynamic string table, as lossy UTF-8.
    pub name: String,
    /// `l_time_stamp`: the time stamp of the library.
    pub time_stamp: u32,
    /// `l_checksum`: the checksum of the library.
    pub checksum: u32,
    /// `l_version`: the interface version of the library.
    pub version: u32,
    /// `l_flags`: the `LL_*` flags, for example [`LL_EXACT_MATCH`].
    pub flags: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn round_trips_both_byte_orders() {
        let table = LibraryTable {
            libraries: vec![
                Library {
                    name: 1,
                    time_stamp: 2,
                    checksum: 3,
                    version: 4,
                    flags: LL_EXPORTS | LL_DELAY_LOAD,
                },
                Library::default(),
            ],
        };
        for encoding in [Encoding::ELF32_BE, Encoding::ELF64_LE] {
            let bytes = table.write(encoding);
            assert_eq!(bytes.len(), 2 * Library::SIZE);
            assert_eq!(LibraryTable::parse(&bytes, encoding).unwrap(), table);
        }
        assert_eq!(table.write(Encoding::ELF32_BE)[..4], [0, 0, 0, 1]);
    }

    #[test]
    fn rejects_a_partial_entry() {
        let error = LibraryTable::parse(&[0; 30], Encoding::ELF64_LE).unwrap_err();
        assert!(
            matches!(error.kind(), ErrorKind::InvalidTable(_)),
            "{error}"
        );
    }
}
