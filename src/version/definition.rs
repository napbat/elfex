//! Version definitions: the `SHT_GNU_verdef` section and the `DT_VERDEF` table.

use super::{VER_DEF_CURRENT, entry_at, walk_aux, walk_chain};
use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};

/// The size of an `Elf_Verdef` entry in bytes.
const VERDEF_SIZE: usize = 20;
/// The size of an `Elf_Verdaux` entry in bytes.
const VERDAUX_SIZE: usize = 8;
/// The `vd_aux` value of a canonical `Elf_Verdef` entry: the auxiliary entries follow the entry.
const VERDEF_AUX: u32 = 20;
/// The `vda_next` value of a canonical `Elf_Verdaux` entry that is not the last entry.
const VERDAUX_NEXT: u32 = 8;

/// One version definition: an `Elf32_Verdef` or `Elf64_Verdef` entry and its `Elf_Verdaux`
/// entries.
///
/// The layout is the same in ELF32 and ELF64.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionDefinition {
    /// The structure version (`vd_version`). The current value is
    /// [`VER_DEF_CURRENT`](super::VER_DEF_CURRENT).
    pub version: u16,
    /// The version flags (`vd_flags`), for example [`VER_FLG_BASE`](super::VER_FLG_BASE).
    pub flags: u16,
    /// The version index (`vd_ndx`) that `Elf_Versym` values refer to.
    pub index: u16,
    /// The System V ELF hash of the version name (`vd_hash`).
    pub hash: u32,
    /// The `vda_name` values: offsets in the dynamic string table. The first name is the name
    /// of the version. The other names are the parent versions.
    pub names: Vec<u32>,
}

impl VersionDefinition {
    /// Create a version definition with one name and [`VER_DEF_CURRENT`](super::VER_DEF_CURRENT).
    ///
    /// `name_offset` is the offset of the version name in the dynamic string table. `hash` is
    /// the System V ELF hash of the name. Use [`VersionDefinition::from_name`] to calculate
    /// the hash.
    #[must_use]
    pub fn new(index: u16, flags: u16, name_offset: u32, hash: u32) -> Self {
        Self {
            version: VER_DEF_CURRENT,
            flags,
            index,
            hash,
            names: vec![name_offset],
        }
    }

    /// Create a version definition with one name, and calculate the hash from `name`.
    ///
    /// `name_offset` is the offset of `name` in the dynamic string table.
    #[must_use]
    pub fn from_name(index: u16, flags: u16, name_offset: u32, name: &[u8]) -> Self {
        Self::new(index, flags, name_offset, crate::hash::sysv_hash(name))
    }

    /// Add a parent version name (an offset in the dynamic string table).
    #[must_use]
    pub fn with_parent(mut self, parent_offset: u32) -> Self {
        self.names.push(parent_offset);
        self
    }

    /// Return the offset of the version name in the dynamic string table.
    #[must_use]
    pub fn name(&self) -> Option<u32> {
        self.names.first().copied()
    }

    /// Return the offsets of the parent version names in the dynamic string table.
    #[must_use]
    pub fn parents(&self) -> &[u32] {
        self.names.get(1..).unwrap_or(&[])
    }

    /// Parse the `Elf_Verdef` entry at `offset` and its `Elf_Verdaux` entries.
    ///
    /// Return the definition and the `vd_next` value.
    fn parse_at(
        bytes: &[u8],
        encoding: Encoding,
        offset: usize,
        aux_budget: &mut usize,
    ) -> Result<(Self, u32)> {
        let entry = entry_at(bytes, offset, VERDEF_SIZE, "Elf_Verdef")?;
        let version = encoding.read_u16(entry, 0)?;
        let flags = encoding.read_u16(entry, 2)?;
        let index = encoding.read_u16(entry, 4)?;
        let count = encoding.read_u16(entry, 6)?;
        let hash = encoding.read_u32(entry, 8)?;
        let aux = encoding.read_u32(entry, 12)?;
        let next = encoding.read_u32(entry, 16)?;
        let names = walk_aux::<_, VERDAUX_SIZE>(
            bytes,
            offset,
            aux,
            count,
            "Elf_Verdaux",
            aux_budget,
            |aux_entry| {
                Ok((
                    encoding.read_u32(aux_entry, 0)?,
                    encoding.read_u32(aux_entry, 4)?,
                ))
            },
        )?;
        let definition = Self {
            version,
            flags,
            index,
            hash,
            names,
        };
        Ok((definition, next))
    }
}

/// The version definition table: the `SHT_GNU_verdef` section or the `DT_VERDEF` table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionDefinitionTable {
    /// The version definitions in chain order.
    pub definitions: Vec<VersionDefinition>,
}

impl VersionDefinitionTable {
    /// Parse a chain of `Elf_Verdef` entries that starts at offset 0 of `bytes`.
    ///
    /// The parser follows the relative offsets `vd_aux`, `vda_next` and `vd_next` from each
    /// entry. Any offset in `bytes` is valid. The function ignores the bytes that the chain
    /// does not use.
    ///
    /// `count` is the number of entries: `DT_VERDEFNUM` or the `sh_info` value of the section.
    ///
    /// - If `count` is `Some`, the function parses exactly `count` entries. It ignores the
    ///   `vd_next` value of the last entry.
    /// - If `count` is `None`, the function parses entries until `vd_next` is 0. It returns an
    ///   empty table for empty `bytes`.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if an
    ///   entry is not fully in `bytes`.
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `count` entries
    ///   do not fit in `bytes`, if a chain ends (a next offset is 0) before its count, or if a
    ///   chain has more entries than fit in `bytes` (overlapping entries).
    pub fn parse(bytes: &[u8], encoding: Encoding, count: Option<u64>) -> Result<Self> {
        let mut aux_budget = bytes.len() / VERDAUX_SIZE;
        let definitions = walk_chain(bytes, count, VERDEF_SIZE, "Elf_Verdef", |offset| {
            VersionDefinition::parse_at(bytes, encoding, offset, &mut aux_budget)
        })?;
        Ok(Self { definitions })
    }

    /// Serialize the table in the canonical layout.
    ///
    /// Each `Elf_Verdef` entry comes immediately before its `Elf_Verdaux` entries. The
    /// function sets `vd_cnt` to the number of names, `vd_aux` to 20, `vda_next` to 8 (0 for
    /// the last name), and `vd_next` to the offset of the next entry (0 for the last entry).
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if a
    /// definition has more than 65535 names.
    pub fn write(&self, encoding: Encoding) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let last = self.definitions.len().saturating_sub(1);
        for (position, definition) in self.definitions.iter().enumerate() {
            let count = u16::try_from(definition.names.len()).map_err(|_| {
                Error::value_out_of_range(format!(
                    "the version definition {} has more than 65535 names",
                    definition.index
                ))
                .in_structure("Elf_Verdef")
            })?;
            let next = if position == last {
                0
            } else {
                VERDEF_AUX + VERDAUX_NEXT * u32::from(count)
            };
            encoding.write_u16(&mut out, definition.version);
            encoding.write_u16(&mut out, definition.flags);
            encoding.write_u16(&mut out, definition.index);
            encoding.write_u16(&mut out, count);
            encoding.write_u32(&mut out, definition.hash);
            encoding.write_u32(&mut out, VERDEF_AUX);
            encoding.write_u32(&mut out, next);
            let last_name = definition.names.len().saturating_sub(1);
            for (name_position, &name) in definition.names.iter().enumerate() {
                encoding.write_u32(&mut out, name);
                let name_next = if name_position == last_name {
                    0
                } else {
                    VERDAUX_NEXT
                };
                encoding.write_u32(&mut out, name_next);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use crate::version::VER_FLG_BASE;

    /// Append an `Elf_Verdef` entry with `vd_version` 1.
    ///
    /// `half` is `vd_flags`, `vd_ndx` and `vd_cnt`. `words` is `vd_hash`, `vd_aux` and `vd_next`.
    fn verdef(out: &mut Vec<u8>, encoding: Encoding, half: [u16; 3], words: [u32; 3]) {
        encoding.write_u16(out, 1);
        for value in half {
            encoding.write_u16(out, value);
        }
        for value in words {
            encoding.write_u32(out, value);
        }
    }

    /// Append an `Elf_Verdaux` entry.
    fn verdaux(out: &mut Vec<u8>, encoding: Encoding, name: u32, next: u32) {
        encoding.write_u32(out, name);
        encoding.write_u32(out, next);
    }

    /// Build a canonical table: the base version `libfoo.so` and `FOO_2` with parent `FOO_1`.
    fn sample_bytes(encoding: Encoding) -> Vec<u8> {
        let mut out = Vec::new();
        verdef(
            &mut out,
            encoding,
            [VER_FLG_BASE, 1, 1],
            [0x0aaa_aaaa, 20, 28],
        );
        verdaux(&mut out, encoding, 1, 0);
        verdef(&mut out, encoding, [0, 2, 2], [0x0bbb_bbbb, 20, 0]);
        verdaux(&mut out, encoding, 10, 8);
        verdaux(&mut out, encoding, 20, 0);
        out
    }

    fn sample_table() -> VersionDefinitionTable {
        VersionDefinitionTable {
            definitions: vec![
                VersionDefinition::new(1, VER_FLG_BASE, 1, 0x0aaa_aaaa),
                VersionDefinition::new(2, 0, 10, 0x0bbb_bbbb).with_parent(20),
            ],
        }
    }

    #[test]
    fn parse_little_and_big_endian() {
        for encoding in [
            Encoding::ELF32_LE,
            Encoding::ELF32_BE,
            Encoding::ELF64_LE,
            Encoding::ELF64_BE,
        ] {
            let bytes = sample_bytes(encoding);
            assert_eq!(bytes.len(), 64);
            let table = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap();
            assert_eq!(table, sample_table());
            let table = VersionDefinitionTable::parse(&bytes, encoding, Some(2)).unwrap();
            assert_eq!(table, sample_table());
            assert_eq!(table.definitions[1].name(), Some(10));
            assert_eq!(table.definitions[1].parents(), [20]);
            assert_eq!(table.definitions[0].parents(), []);
        }
        let le = sample_bytes(Encoding::ELF64_LE);
        let be = sample_bytes(Encoding::ELF64_BE);
        assert_eq!(le[..8], [1, 0, 1, 0, 1, 0, 1, 0]);
        assert_eq!(be[..8], [0, 1, 0, 1, 0, 1, 0, 1]);
    }

    #[test]
    fn write_parse_round_trip() {
        for encoding in [Encoding::ELF32_LE, Encoding::ELF64_BE] {
            let bytes = sample_table().write(encoding).unwrap();
            assert_eq!(bytes, sample_bytes(encoding));
            let table = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap();
            assert_eq!(table, sample_table());
        }
        let empty = VersionDefinitionTable::default();
        assert_eq!(empty.write(Encoding::ELF64_LE).unwrap(), []);
        let table = VersionDefinitionTable::parse(&[], Encoding::ELF64_LE, None).unwrap();
        assert_eq!(table, empty);
    }

    #[test]
    fn parse_non_canonical_layout() {
        // Put both `Elf_Verdef` entries first and all `Elf_Verdaux` entries after them, and
        // add trailing bytes.
        let encoding = Encoding::ELF64_LE;
        let mut bytes = Vec::new();
        verdef(
            &mut bytes,
            encoding,
            [VER_FLG_BASE, 1, 1],
            [0x0aaa_aaaa, 40, 20],
        );
        verdef(&mut bytes, encoding, [0, 2, 2], [0x0bbb_bbbb, 28, 0]);
        verdaux(&mut bytes, encoding, 1, 0);
        verdaux(&mut bytes, encoding, 10, 8);
        verdaux(&mut bytes, encoding, 20, 0);
        bytes.extend_from_slice(&[0xff; 7]);
        let table = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap();
        assert_eq!(table, sample_table());
    }

    #[test]
    fn count_mismatch() {
        let encoding = Encoding::ELF64_LE;
        let bytes = sample_bytes(encoding);
        // A smaller count stops the parse and ignores `vd_next`.
        let table = VersionDefinitionTable::parse(&bytes, encoding, Some(1)).unwrap();
        assert_eq!(table.definitions, sample_table().definitions[..1]);
        let table = VersionDefinitionTable::parse(&bytes, encoding, Some(0)).unwrap();
        assert_eq!(table.definitions, []);
        // A larger count than the chain is an error.
        let error = VersionDefinitionTable::parse(&bytes, encoding, Some(3)).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
        // A count that does not fit in the bytes is an error.
        let error = VersionDefinitionTable::parse(&bytes, encoding, Some(4)).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
        let error = VersionDefinitionTable::parse(&bytes, encoding, Some(u64::MAX)).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn reject_out_of_range_offsets() {
        let encoding = Encoding::ELF64_LE;
        // `vd_next` points after the end.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 16, 60).unwrap();
        let error = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::OffsetOutOfBounds { .. }));
        // `vd_aux` points after the end.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 12, u32::MAX).unwrap();
        let error = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::OffsetOutOfBounds { .. }));
        // `vda_next` points after the end.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 52, 100).unwrap();
        let error = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::OffsetOutOfBounds { .. }));
        // `vda_next` is 0 before `vd_cnt` names.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 52, 0).unwrap();
        let error = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
        // The table is truncated.
        let bytes = sample_bytes(encoding);
        assert!(VersionDefinitionTable::parse(&bytes[..60], encoding, None).is_err());
        assert!(VersionDefinitionTable::parse(&bytes[..10], encoding, None).is_err());
    }

    #[test]
    fn reject_vd_next_loop() {
        // The offsets are unsigned, so a chain cannot go back. Each entry has `vd_next` 4 and
        // `vd_cnt` 0, so the chain walks through overlapping entries. The parser stops after
        // the number of entries that fit in the bytes.
        let bytes = [4_u8, 0, 0, 0].repeat(20);
        let error = VersionDefinitionTable::parse(&bytes, Encoding::ELF64_LE, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn reject_aux_loop() {
        // `vd_cnt` is 0xffff and each `Elf_Verdaux` entry points 4 bytes forward, so the
        // entries overlap. The parser stops after the number of auxiliary entries that fit in
        // the bytes (100 / 8 = 12).
        let encoding = Encoding::ELF64_LE;
        let mut bytes = Vec::new();
        verdef(&mut bytes, encoding, [0, 2, 0xffff], [0, 20, 0]);
        bytes.extend_from_slice(&[4_u8, 0, 0, 0].repeat(20));
        assert_eq!(bytes.len(), 100);
        let error = VersionDefinitionTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn write_rejects_too_many_names() {
        let mut definition = VersionDefinition::new(2, 0, 1, 0);
        definition.names = vec![0; 0x1_0000];
        let table = VersionDefinitionTable {
            definitions: vec![definition],
        };
        let error = table.write(Encoding::ELF64_LE).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ValueOutOfRange(_)));
    }

    #[test]
    fn from_name_uses_sysv_hash() {
        let definition = VersionDefinition::from_name(2, 0, 5, b"GLIBC_2.2.5");
        assert_eq!(definition.hash, 0x0969_1a75);
        assert_eq!(definition.names, [5]);
        assert_eq!(definition.version, VER_DEF_CURRENT);
    }
}
