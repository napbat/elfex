//! Symbol versions: the GNU symbol versioning tables.
//!
//! Three tables give the versions of the dynamic symbols:
//!
//! - [`VersymTable`]: the `SHT_GNU_versym` section (`DT_VERSYM`). It has one `Elf_Versym`
//!   value for each dynamic symbol.
//! - [`VersionDefinitionTable`]: the `SHT_GNU_verdef` section (`DT_VERDEF`). It has the
//!   versions that the file defines.
//! - [`VersionRequirementTable`]: the `SHT_GNU_verneed` section (`DT_VERNEED`). It has the
//!   versions that the file needs from other files.
//!
//! Use [`VersionMap`] to find the version name of a dynamic symbol from its `Elf_Versym` value.
//! All names in these tables are offsets in the dynamic string table (`DT_STRTAB`).
//!
//! # Examples
//!
//! ```
//! use elfex::strtab::{StringTable, StringTableBuilder};
//! use elfex::version::{
//!     VER_NDX_GLOBAL, VersionMap, VersionNeedEntry, VersionRequirement,
//!     VersionRequirementTable, VersymTable,
//! };
//! use elfex::Encoding;
//!
//! let encoding = Encoding::ELF64_LE;
//! let mut strings = StringTableBuilder::new();
//! let libc = strings.add("libc.so.6")?;
//! let glibc = strings.add("GLIBC_2.34")?;
//!
//! // The file needs version index 2 (GLIBC_2.34) from libc.so.6.
//! let needed = VersionNeedEntry::from_name(2, 0, glibc, b"GLIBC_2.34");
//! let requirements = VersionRequirementTable {
//!     requirements: vec![VersionRequirement::new(libc).with_entry(needed)],
//! };
//! let bytes = requirements.write(encoding)?;
//! let requirements = VersionRequirementTable::parse(&bytes, encoding, Some(1))?;
//!
//! // Symbol 0 is the null symbol. Symbol 1 has the base version. Symbol 2 needs GLIBC_2.34.
//! let versym = VersymTable { entries: vec![0, VER_NDX_GLOBAL, 2] };
//! let versym = VersymTable::parse(&versym.write(encoding), encoding)?;
//!
//! let map = VersionMap::new(None, Some(&requirements));
//! let strings = StringTable::parse(strings.as_bytes());
//! let version = map.symbol_version(versym.entries[2]).expect("symbol 2 has a version");
//! assert_eq!(strings.get(version.name)?, "GLIBC_2.34");
//! assert_eq!(version.file, Some(libc));
//! assert!(map.symbol_version(versym.entries[1]).is_none());
//! # Ok::<(), elfex::Error>(())
//! ```

mod definition;
mod requirement;

pub use definition::{VersionDefinition, VersionDefinitionTable};
pub use requirement::{VersionNeedEntry, VersionRequirement, VersionRequirementTable};

use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};

/// `VER_NDX_LOCAL`: the symbol is local and has no version.
pub const VER_NDX_LOCAL: u16 = 0;
/// `VER_NDX_GLOBAL`: the symbol is global and has the base version of the file.
pub const VER_NDX_GLOBAL: u16 = 1;
/// `VER_NDX_LORESERVE`: the start of the reserved version indexes.
pub const VER_NDX_LORESERVE: u16 = 0xff00;
/// `VER_NDX_ELIMINATE`: the link editor removes the symbol.
pub const VER_NDX_ELIMINATE: u16 = 0xff01;
/// `VERSYM_HIDDEN`: the bit in an `Elf_Versym` value that marks a hidden (non-default) version.
pub const VERSYM_HIDDEN: u16 = 0x8000;
/// `VERSYM_VERSION`: the mask of the version index in an `Elf_Versym` value.
pub const VERSYM_VERSION: u16 = 0x7fff;
/// `VER_DEF_CURRENT`: the current `vd_version` value of an `Elf_Verdef` entry.
pub const VER_DEF_CURRENT: u16 = 1;
/// `VER_NEED_CURRENT`: the current `vn_version` value of an `Elf_Verneed` entry.
pub const VER_NEED_CURRENT: u16 = 1;
/// `VER_FLG_BASE`: the version definition is the base version of the file.
pub const VER_FLG_BASE: u16 = 1;
/// `VER_FLG_WEAK`: the version is a weak version.
pub const VER_FLG_WEAK: u16 = 2;
/// `VER_FLG_INFO`: the version reference is for information only.
pub const VER_FLG_INFO: u16 = 4;

/// Return the version index of an `Elf_Versym` value (the value without [`VERSYM_HIDDEN`]).
#[must_use]
pub const fn version_index(raw: u16) -> u16 {
    raw & VERSYM_VERSION
}

/// Return `true` if the [`VERSYM_HIDDEN`] bit is set in an `Elf_Versym` value.
#[must_use]
pub const fn is_hidden(raw: u16) -> bool {
    raw & VERSYM_HIDDEN != 0
}

/// The symbol version table: the `SHT_GNU_versym` section or the `DT_VERSYM` table.
///
/// Each entry is an `Elf_Versym` (`u16`) value. Entry `i` is the version of dynamic symbol
/// `i`. The layout is the same in ELF32 and ELF64.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersymTable {
    /// The raw `Elf_Versym` values, one for each dynamic symbol.
    pub entries: Vec<u16>,
}

impl VersymTable {
    /// Parse all `Elf_Versym` values in `bytes`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is not a multiple of 2.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        if !bytes.len().is_multiple_of(2) {
            return Err(Error::invalid_table(format!(
                "the symbol version table size {} is not a multiple of 2",
                bytes.len()
            ))
            .in_structure("Elf_Versym"));
        }
        Self::parse_entries(bytes, encoding, bytes.len() / 2)
    }

    /// Parse `count` `Elf_Versym` values from the start of `bytes`.
    ///
    /// Use this function for a `DT_VERSYM` table, where the number of dynamic symbols gives
    /// the count. The function ignores the bytes after the last value.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` is
    /// smaller than `count` values.
    pub fn parse_count(bytes: &[u8], encoding: Encoding, count: u64) -> Result<Self> {
        let size = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(2))
            .unwrap_or(usize::MAX);
        if size > bytes.len() {
            return Err(Error::buffer_too_small(size, bytes.len()).in_structure("Elf_Versym"));
        }
        let count = size / 2;
        Self::parse_entries(bytes, encoding, count)
    }

    /// Parse `count` values. The caller makes sure that `bytes` holds `count` values.
    fn parse_entries(bytes: &[u8], encoding: Encoding, count: usize) -> Result<Self> {
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            entries.push(encoding.read_u16(bytes, index * 2)?);
        }
        Ok(Self { entries })
    }

    /// Serialize the table: one `Elf_Versym` value for each entry.
    #[must_use]
    pub fn write(&self, encoding: Encoding) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * 2);
        for &entry in &self.entries {
            encoding.write_u16(&mut out, entry);
        }
        out
    }

    /// Return the raw `Elf_Versym` value of dynamic symbol `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<u16> {
        self.entries.get(index).copied()
    }
}

/// A version name that a version index refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct VersionName {
    /// The offset of the version name in the dynamic string table (`vda_name` or `vna_name`).
    pub name: u32,
    /// For a version requirement, the offset of the file name in the dynamic string table
    /// (`vn_file`). For a version definition, `None`.
    pub file: Option<u32>,
    /// The version flags (`vd_flags` or `vna_flags`), for example [`VER_FLG_WEAK`].
    pub flags: u16,
}

/// The version of one dynamic symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SymbolVersion {
    /// The version index (the `Elf_Versym` value without [`VERSYM_HIDDEN`]).
    pub index: u16,
    /// `true` if the [`VERSYM_HIDDEN`] bit is set. A hidden version is not the default version
    /// of the symbol.
    pub hidden: bool,
    /// The offset of the version name in the dynamic string table.
    pub name: u32,
    /// For a version requirement, the offset of the file name (`vn_file`) in the dynamic string
    /// table. For a version definition, `None`.
    pub file: Option<u32>,
}

/// A map from version indexes to version names.
///
/// The map combines the version definitions (`vd_ndx`) and the version requirements
/// (`vna_other`). If two entries have the same index, the map keeps the first entry. The
/// version definitions come first.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionMap {
    names: BTreeMap<u16, VersionName>,
}

impl VersionMap {
    /// Create a map from the version definitions and the version requirements of a file.
    ///
    /// The map ignores a version definition that has no names.
    #[must_use]
    pub fn new(
        definitions: Option<&VersionDefinitionTable>,
        requirements: Option<&VersionRequirementTable>,
    ) -> Self {
        let mut names = BTreeMap::new();
        for definition in definitions.into_iter().flat_map(|table| &table.definitions) {
            if let Some(&name) = definition.names.first() {
                names
                    .entry(version_index(definition.index))
                    .or_insert(VersionName {
                        name,
                        file: None,
                        flags: definition.flags,
                    });
            }
        }
        for requirement in requirements
            .into_iter()
            .flat_map(|table| &table.requirements)
        {
            for entry in &requirement.entries {
                names
                    .entry(version_index(entry.index))
                    .or_insert(VersionName {
                        name: entry.name,
                        file: Some(requirement.file),
                        flags: entry.flags,
                    });
            }
        }
        Self { names }
    }

    /// Return the version name of a version index.
    ///
    /// The function ignores the [`VERSYM_HIDDEN`] bit of `index`.
    #[must_use]
    pub fn get(&self, index: u16) -> Option<&VersionName> {
        self.names.get(&version_index(index))
    }

    /// Return an iterator over the version indexes and their names, in index order.
    pub fn iter(&self) -> impl Iterator<Item = (u16, &VersionName)> {
        self.names.iter().map(|(&index, name)| (index, name))
    }

    /// Return the version of a dynamic symbol from its raw `Elf_Versym` value.
    ///
    /// Return `None` for [`VER_NDX_LOCAL`], for [`VER_NDX_GLOBAL`] and for an index that is
    /// not in the map.
    #[must_use]
    pub fn symbol_version(&self, versym_raw: u16) -> Option<SymbolVersion> {
        let index = version_index(versym_raw);
        if index == VER_NDX_LOCAL || index == VER_NDX_GLOBAL {
            return None;
        }
        let name = self.names.get(&index)?;
        Some(SymbolVersion {
            index,
            hidden: is_hidden(versym_raw),
            name: name.name,
            file: name.file,
        })
    }
}

/// Convert a slice offset to `u64` for error context.
fn offset_u64(offset: usize) -> u64 {
    u64::try_from(offset).unwrap_or(u64::MAX)
}

/// Return the `size` bytes at `offset` in `bytes`, or an `OffsetOutOfBounds` error.
fn entry_at<'a>(bytes: &'a [u8], offset: usize, size: usize, structure: &str) -> Result<&'a [u8]> {
    offset
        .checked_add(size)
        .and_then(|end| bytes.get(offset..end))
        .ok_or_else(|| {
            Error::offset_out_of_bounds(offset_u64(offset), offset_u64(bytes.len()))
                .in_structure(structure)
        })
}

/// Add a relative offset from the file to `offset`, or return an `OffsetOutOfBounds` error.
fn advance(offset: usize, delta: u32, len: usize, structure: &str) -> Result<usize> {
    usize::try_from(delta)
        .ok()
        .and_then(|delta| offset.checked_add(delta))
        .ok_or_else(|| {
            Error::offset_out_of_bounds(
                offset_u64(offset).saturating_add(u64::from(delta)),
                offset_u64(len),
            )
            .in_structure(structure)
        })
}

/// Walk a chain of version entries (`Elf_Verdef` or `Elf_Verneed`) from offset 0.
///
/// `parse_one` parses the entry at an offset and returns the entry and its relative next
/// offset (`vd_next` or `vn_next`).
///
/// - If `count` is `Some`, parse exactly `count` entries and ignore the next offset of the last
///   entry. Return an error if the chain ends before `count` entries.
/// - If `count` is `None`, parse entries until the next offset is 0.
///
/// The number of entries cannot be more than the number of entries that fit in `bytes`. This
/// stops a chain of overlapping entries.
fn walk_chain<T>(
    bytes: &[u8],
    count: Option<u64>,
    entry_size: usize,
    structure: &str,
    mut parse_one: impl FnMut(usize) -> Result<(T, u32)>,
) -> Result<Vec<T>> {
    let max_entries = bytes.len() / entry_size;
    let limit = match count {
        Some(0) => return Ok(Vec::new()),
        Some(count) => match usize::try_from(count) {
            Ok(limit) if limit <= max_entries => Some(limit),
            _ => {
                return Err(Error::invalid_table(format!(
                    "the entry count {count} needs more than {} bytes",
                    bytes.len()
                ))
                .in_structure(structure));
            }
        },
        None if bytes.is_empty() => return Ok(Vec::new()),
        None => None,
    };
    let mut items = Vec::new();
    let mut offset = 0usize;
    loop {
        let (item, next) = parse_one(offset)?;
        items.push(item);
        if limit == Some(items.len()) {
            break;
        }
        if next == 0 {
            if let Some(limit) = limit {
                return Err(Error::invalid_table(format!(
                    "the chain ends after {} entries, but the entry count is {limit}",
                    items.len()
                ))
                .in_structure(structure)
                .at_offset(offset_u64(offset)));
            }
            break;
        }
        if items.len() >= max_entries {
            return Err(Error::invalid_table(format!(
                "the chain has more entries than fit in {} bytes",
                bytes.len()
            ))
            .in_structure(structure)
            .at_offset(offset_u64(offset)));
        }
        offset = advance(offset, next, bytes.len(), structure)?;
    }
    Ok(items)
}

/// Walk a chain of auxiliary entries (`Elf_Verdaux` or `Elf_Vernaux`).
///
/// The first entry is at `base + first`. `parse_one` parses one entry and returns the item and
/// its relative next offset (`vda_next` or `vna_next`). `budget` is the number of auxiliary
/// entries that the complete table can still have. It stops overlapping chains.
fn walk_aux<T, const SIZE: usize>(
    bytes: &[u8],
    base: usize,
    first: u32,
    count: u16,
    structure: &str,
    budget: &mut usize,
    mut parse_one: impl FnMut(&[u8]) -> Result<(T, u32)>,
) -> Result<Vec<T>> {
    let mut items = Vec::new();
    if count == 0 {
        return Ok(items);
    }
    let mut offset = advance(base, first, bytes.len(), structure)?;
    for number in 1..=count {
        *budget = budget.checked_sub(1).ok_or_else(|| {
            Error::invalid_table(format!(
                "the table has more entries than fit in {} bytes",
                bytes.len()
            ))
            .in_structure(structure)
            .at_offset(offset_u64(offset))
        })?;
        let entry = entry_at(bytes, offset, SIZE, structure)?;
        let (item, next) = parse_one(entry)?;
        items.push(item);
        if number < count {
            if next == 0 {
                return Err(Error::invalid_table(format!(
                    "the chain ends after {number} entries, but the entry count is {count}"
                ))
                .in_structure(structure)
                .at_offset(offset_u64(offset)));
            }
            offset = advance(offset, next, bytes.len(), structure)?;
        }
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versym_parse_and_write() {
        for encoding in [Encoding::ELF32_LE, Encoding::ELF64_BE] {
            let table = VersymTable {
                entries: vec![0, 1, 2, 0x8003],
            };
            let bytes = table.write(encoding);
            assert_eq!(bytes.len(), 8);
            assert_eq!(VersymTable::parse(&bytes, encoding).unwrap(), table);
            assert_eq!(table.get(3), Some(0x8003));
            assert_eq!(table.get(4), None);
        }
        let le = VersymTable::parse(&[2, 0, 3, 0x80], Encoding::ELF64_LE).unwrap();
        let be = VersymTable::parse(&[0, 2, 0x80, 3], Encoding::ELF64_BE).unwrap();
        assert_eq!(le.entries, [2, 0x8003]);
        assert_eq!(be.entries, [2, 0x8003]);
    }

    #[test]
    fn versym_rejects_odd_length() {
        assert!(VersymTable::parse(&[1, 0, 2], Encoding::ELF64_LE).is_err());
    }

    #[test]
    fn versym_parse_count() {
        let bytes = [1, 0, 2, 0, 3, 0, 0xff];
        let table = VersymTable::parse_count(&bytes, Encoding::ELF64_LE, 2).unwrap();
        assert_eq!(table.entries, [1, 2]);
        let table = VersymTable::parse_count(&bytes, Encoding::ELF64_LE, 0).unwrap();
        assert_eq!(table.entries, []);
        assert!(VersymTable::parse_count(&bytes, Encoding::ELF64_LE, 4).is_err());
        assert!(VersymTable::parse_count(&bytes, Encoding::ELF64_LE, u64::MAX).is_err());
    }

    #[test]
    fn versym_helpers() {
        assert_eq!(version_index(0x8005), 5);
        assert!(is_hidden(0x8005));
        assert!(!is_hidden(5));
    }

    fn sample_map() -> VersionMap {
        let definitions = VersionDefinitionTable {
            definitions: vec![
                VersionDefinition {
                    version: VER_DEF_CURRENT,
                    flags: VER_FLG_BASE,
                    index: 1,
                    hash: 0x1111,
                    names: vec![1],
                },
                VersionDefinition {
                    version: VER_DEF_CURRENT,
                    flags: 0,
                    index: 2,
                    hash: 0x2222,
                    names: vec![10, 20],
                },
            ],
        };
        let requirements = VersionRequirementTable {
            requirements: vec![VersionRequirement {
                version: VER_NEED_CURRENT,
                file: 30,
                entries: vec![
                    VersionNeedEntry {
                        hash: 0x3333,
                        flags: VER_FLG_WEAK,
                        index: 3,
                        name: 40,
                    },
                    // The index of this entry is the same as a definition index.
                    VersionNeedEntry {
                        hash: 0x4444,
                        flags: 0,
                        index: 2,
                        name: 50,
                    },
                ],
            }],
        };
        VersionMap::new(Some(&definitions), Some(&requirements))
    }

    #[test]
    fn version_map_get() {
        let map = sample_map();
        assert_eq!(
            map.get(2),
            Some(&VersionName {
                name: 10,
                file: None,
                flags: 0,
            })
        );
        assert_eq!(map.get(0x8002), map.get(2));
        assert_eq!(
            map.get(3),
            Some(&VersionName {
                name: 40,
                file: Some(30),
                flags: VER_FLG_WEAK,
            })
        );
        assert_eq!(map.get(4), None);
        let indexes: Vec<u16> = map.iter().map(|(index, _)| index).collect();
        assert_eq!(indexes, [1, 2, 3]);
    }

    #[test]
    fn version_map_symbol_version() {
        let map = sample_map();
        assert_eq!(map.symbol_version(VER_NDX_LOCAL), None);
        assert_eq!(map.symbol_version(VER_NDX_GLOBAL), None);
        assert_eq!(map.symbol_version(VER_NDX_GLOBAL | VERSYM_HIDDEN), None);
        assert_eq!(map.symbol_version(7), None);
        assert_eq!(
            map.symbol_version(2),
            Some(SymbolVersion {
                index: 2,
                hidden: false,
                name: 10,
                file: None,
            })
        );
        assert_eq!(
            map.symbol_version(0x8002),
            Some(SymbolVersion {
                index: 2,
                hidden: true,
                name: 10,
                file: None,
            })
        );
        assert_eq!(
            map.symbol_version(0x8003),
            Some(SymbolVersion {
                index: 3,
                hidden: true,
                name: 40,
                file: Some(30),
            })
        );
    }

    #[test]
    fn version_map_empty() {
        let map = VersionMap::new(None, None);
        assert_eq!(map.get(2), None);
        assert_eq!(map.symbol_version(2), None);
    }
}
