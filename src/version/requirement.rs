//! Version requirements: the `SHT_GNU_verneed` section and the `DT_VERNEED` table.

use super::{VER_NEED_CURRENT, entry_at, walk_aux, walk_chain};
use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};

/// The size of an `Elf_Verneed` entry in bytes.
const VERNEED_SIZE: usize = 16;
/// The size of an `Elf_Vernaux` entry in bytes.
const VERNAUX_SIZE: usize = 16;
/// The `vn_aux` value of a canonical `Elf_Verneed` entry: the auxiliary entries follow the entry.
const VERNEED_AUX: u32 = 16;
/// The `vna_next` value of a canonical `Elf_Vernaux` entry that is not the last entry.
const VERNAUX_NEXT: u32 = 16;

/// One version that a file needs: an `Elf32_Vernaux` or `Elf64_Vernaux` entry.
///
/// The layout is the same in ELF32 and ELF64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct VersionNeedEntry {
    /// The System V ELF hash of the version name (`vna_hash`).
    pub hash: u32,
    /// The version flags (`vna_flags`), for example [`VER_FLG_WEAK`](super::VER_FLG_WEAK).
    pub flags: u16,
    /// The version index (`vna_other`) that `Elf_Versym` values refer to.
    pub index: u16,
    /// The offset of the version name in the dynamic string table (`vna_name`).
    pub name: u32,
}

impl VersionNeedEntry {
    /// Create a version need entry.
    ///
    /// `name_offset` is the offset of the version name in the dynamic string table. `hash` is
    /// the System V ELF hash of the name. Use [`VersionNeedEntry::from_name`] to calculate the
    /// hash.
    #[must_use]
    pub const fn new(index: u16, flags: u16, name_offset: u32, hash: u32) -> Self {
        Self {
            hash,
            flags,
            index,
            name: name_offset,
        }
    }

    /// Create a version need entry, and calculate the hash from `name`.
    ///
    /// `name_offset` is the offset of `name` in the dynamic string table.
    #[must_use]
    pub fn from_name(index: u16, flags: u16, name_offset: u32, name: &[u8]) -> Self {
        Self::new(index, flags, name_offset, crate::hash::sysv_hash(name))
    }
}

/// The versions that a file needs from one other file: an `Elf32_Verneed` or `Elf64_Verneed`
/// entry and its `Elf_Vernaux` entries.
///
/// The layout is the same in ELF32 and ELF64.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionRequirement {
    /// The structure version (`vn_version`). The current value is
    /// [`VER_NEED_CURRENT`](super::VER_NEED_CURRENT).
    pub version: u16,
    /// The offset of the file name in the dynamic string table (`vn_file`). The name is a
    /// `DT_NEEDED` name.
    pub file: u32,
    /// The versions that the file needs (the `Elf_Vernaux` entries).
    pub entries: Vec<VersionNeedEntry>,
}

impl VersionRequirement {
    /// Create a version requirement with no entries and
    /// [`VER_NEED_CURRENT`](super::VER_NEED_CURRENT).
    ///
    /// `file_offset` is the offset of the file name in the dynamic string table.
    #[must_use]
    pub const fn new(file_offset: u32) -> Self {
        Self {
            version: VER_NEED_CURRENT,
            file: file_offset,
            entries: Vec::new(),
        }
    }

    /// Add a version need entry.
    #[must_use]
    pub fn with_entry(mut self, entry: VersionNeedEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Parse the `Elf_Verneed` entry at `offset` and its `Elf_Vernaux` entries.
    ///
    /// Return the requirement and the `vn_next` value.
    fn parse_at(
        bytes: &[u8],
        encoding: Encoding,
        offset: usize,
        aux_budget: &mut usize,
    ) -> Result<(Self, u32)> {
        let entry = entry_at(bytes, offset, VERNEED_SIZE, "Elf_Verneed")?;
        let version = encoding.read_u16(entry, 0)?;
        let count = encoding.read_u16(entry, 2)?;
        let file = encoding.read_u32(entry, 4)?;
        let aux = encoding.read_u32(entry, 8)?;
        let next = encoding.read_u32(entry, 12)?;
        let entries = walk_aux::<_, VERNAUX_SIZE>(
            bytes,
            offset,
            aux,
            count,
            "Elf_Vernaux",
            aux_budget,
            |aux_entry| {
                let need = VersionNeedEntry {
                    hash: encoding.read_u32(aux_entry, 0)?,
                    flags: encoding.read_u16(aux_entry, 4)?,
                    index: encoding.read_u16(aux_entry, 6)?,
                    name: encoding.read_u32(aux_entry, 8)?,
                };
                Ok((need, encoding.read_u32(aux_entry, 12)?))
            },
        )?;
        let requirement = Self {
            version,
            file,
            entries,
        };
        Ok((requirement, next))
    }
}

/// The version requirement table: the `SHT_GNU_verneed` section or the `DT_VERNEED` table.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionRequirementTable {
    /// The version requirements in chain order.
    pub requirements: Vec<VersionRequirement>,
}

impl VersionRequirementTable {
    /// Parse a chain of `Elf_Verneed` entries that starts at offset 0 of `bytes`.
    ///
    /// The parser follows the relative offsets `vn_aux`, `vna_next` and `vn_next` from each
    /// entry. Any offset in `bytes` is valid. The function ignores the bytes that the chain
    /// does not use.
    ///
    /// `count` is the number of entries: `DT_VERNEEDNUM` or the `sh_info` value of the section.
    ///
    /// - If `count` is `Some`, the function parses exactly `count` entries. It ignores the
    ///   `vn_next` value of the last entry.
    /// - If `count` is `None`, the function parses entries until `vn_next` is 0. It returns an
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
        let mut aux_budget = bytes.len() / VERNAUX_SIZE;
        let requirements = walk_chain(bytes, count, VERNEED_SIZE, "Elf_Verneed", |offset| {
            VersionRequirement::parse_at(bytes, encoding, offset, &mut aux_budget)
        })?;
        Ok(Self { requirements })
    }

    /// Serialize the table in the canonical layout.
    ///
    /// Each `Elf_Verneed` entry comes immediately before its `Elf_Vernaux` entries. The
    /// function sets `vn_cnt` to the number of entries, `vn_aux` to 16, `vna_next` to 16 (0
    /// for the last entry), and `vn_next` to the offset of the next requirement (0 for the
    /// last requirement).
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if a
    /// requirement has more than 65535 entries.
    pub fn write(&self, encoding: Encoding) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let last = self.requirements.len().saturating_sub(1);
        for (position, requirement) in self.requirements.iter().enumerate() {
            let count = u16::try_from(requirement.entries.len()).map_err(|_| {
                Error::value_out_of_range(format!(
                    "the version requirement for file name offset {} has more than 65535 entries",
                    requirement.file
                ))
                .in_structure("Elf_Verneed")
            })?;
            let next = if position == last {
                0
            } else {
                VERNEED_AUX + VERNAUX_NEXT * u32::from(count)
            };
            encoding.write_u16(&mut out, requirement.version);
            encoding.write_u16(&mut out, count);
            encoding.write_u32(&mut out, requirement.file);
            encoding.write_u32(&mut out, VERNEED_AUX);
            encoding.write_u32(&mut out, next);
            let last_entry = requirement.entries.len().saturating_sub(1);
            for (entry_position, entry) in requirement.entries.iter().enumerate() {
                encoding.write_u32(&mut out, entry.hash);
                encoding.write_u16(&mut out, entry.flags);
                encoding.write_u16(&mut out, entry.index);
                encoding.write_u32(&mut out, entry.name);
                let entry_next = if entry_position == last_entry {
                    0
                } else {
                    VERNAUX_NEXT
                };
                encoding.write_u32(&mut out, entry_next);
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use crate::version::VER_FLG_WEAK;

    /// Append an `Elf_Verneed` entry with `vn_version` 1.
    ///
    /// `words` is `vn_file`, `vn_aux` and `vn_next`.
    fn verneed(out: &mut Vec<u8>, encoding: Encoding, count: u16, words: [u32; 3]) {
        encoding.write_u16(out, 1);
        encoding.write_u16(out, count);
        for value in words {
            encoding.write_u32(out, value);
        }
    }

    /// Append an `Elf_Vernaux` entry from a [`VersionNeedEntry`] and a `vna_next` value.
    fn vernaux(out: &mut Vec<u8>, encoding: Encoding, entry: VersionNeedEntry, next: u32) {
        encoding.write_u32(out, entry.hash);
        encoding.write_u16(out, entry.flags);
        encoding.write_u16(out, entry.index);
        encoding.write_u32(out, entry.name);
        encoding.write_u32(out, next);
    }

    const NEED_A: VersionNeedEntry = VersionNeedEntry::new(2, 0, 10, 0x0aaa_aaaa);
    const NEED_B: VersionNeedEntry = VersionNeedEntry::new(3, VER_FLG_WEAK, 30, 0x0bbb_bbbb);
    const NEED_C: VersionNeedEntry = VersionNeedEntry::new(4, 0, 40, 0x0ccc_cccc);

    /// Build a canonical table: file 1 needs one version, file 20 needs two versions.
    fn sample_bytes(encoding: Encoding) -> Vec<u8> {
        let mut out = Vec::new();
        verneed(&mut out, encoding, 1, [1, 16, 32]);
        vernaux(&mut out, encoding, NEED_A, 0);
        verneed(&mut out, encoding, 2, [20, 16, 0]);
        vernaux(&mut out, encoding, NEED_B, 16);
        vernaux(&mut out, encoding, NEED_C, 0);
        out
    }

    fn sample_table() -> VersionRequirementTable {
        VersionRequirementTable {
            requirements: vec![
                VersionRequirement::new(1).with_entry(NEED_A),
                VersionRequirement::new(20)
                    .with_entry(NEED_B)
                    .with_entry(NEED_C),
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
            assert_eq!(bytes.len(), 80);
            let table = VersionRequirementTable::parse(&bytes, encoding, None).unwrap();
            assert_eq!(table, sample_table());
            let table = VersionRequirementTable::parse(&bytes, encoding, Some(2)).unwrap();
            assert_eq!(table, sample_table());
        }
        let le = sample_bytes(Encoding::ELF64_LE);
        let be = sample_bytes(Encoding::ELF64_BE);
        assert_eq!(le[..8], [1, 0, 1, 0, 1, 0, 0, 0]);
        assert_eq!(be[..8], [0, 1, 0, 1, 0, 0, 0, 1]);
    }

    #[test]
    fn write_parse_round_trip() {
        for encoding in [Encoding::ELF32_BE, Encoding::ELF64_LE] {
            let bytes = sample_table().write(encoding).unwrap();
            assert_eq!(bytes, sample_bytes(encoding));
            let table = VersionRequirementTable::parse(&bytes, encoding, None).unwrap();
            assert_eq!(table, sample_table());
        }
        let empty = VersionRequirementTable::default();
        assert_eq!(empty.write(Encoding::ELF64_LE).unwrap(), []);
        let table = VersionRequirementTable::parse(&[], Encoding::ELF64_LE, None).unwrap();
        assert_eq!(table, empty);
    }

    #[test]
    fn parse_non_canonical_layout() {
        // Put both `Elf_Verneed` entries first and all `Elf_Vernaux` entries after them, and
        // add trailing bytes.
        let encoding = Encoding::ELF32_BE;
        let mut bytes = Vec::new();
        verneed(&mut bytes, encoding, 1, [1, 32, 16]);
        verneed(&mut bytes, encoding, 2, [20, 32, 0]);
        vernaux(&mut bytes, encoding, NEED_A, 0);
        vernaux(&mut bytes, encoding, NEED_B, 16);
        vernaux(&mut bytes, encoding, NEED_C, 0);
        bytes.extend_from_slice(&[0xff; 5]);
        let table = VersionRequirementTable::parse(&bytes, encoding, None).unwrap();
        assert_eq!(table, sample_table());
    }

    #[test]
    fn count_mismatch() {
        let encoding = Encoding::ELF64_LE;
        let bytes = sample_bytes(encoding);
        // A smaller count stops the parse and ignores `vn_next`.
        let table = VersionRequirementTable::parse(&bytes, encoding, Some(1)).unwrap();
        assert_eq!(table.requirements, sample_table().requirements[..1]);
        let table = VersionRequirementTable::parse(&bytes, encoding, Some(0)).unwrap();
        assert_eq!(table.requirements, []);
        // A larger count than the chain is an error.
        let error = VersionRequirementTable::parse(&bytes, encoding, Some(3)).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
        // A count that does not fit in the bytes is an error.
        let error = VersionRequirementTable::parse(&bytes, encoding, Some(6)).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn reject_out_of_range_offsets() {
        let encoding = Encoding::ELF64_LE;
        // `vn_next` points after the end.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 12, 70).unwrap();
        let error = VersionRequirementTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::OffsetOutOfBounds { .. }));
        // `vn_aux` points after the end.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 8, u32::MAX).unwrap();
        let error = VersionRequirementTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::OffsetOutOfBounds { .. }));
        // `vna_next` points after the end.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 60, 32).unwrap();
        let error = VersionRequirementTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::OffsetOutOfBounds { .. }));
        // `vna_next` is 0 before `vn_cnt` entries.
        let mut bytes = sample_bytes(encoding);
        encoding.put_u32(&mut bytes, 60, 0).unwrap();
        let error = VersionRequirementTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
        // The table is truncated.
        let bytes = sample_bytes(encoding);
        assert!(VersionRequirementTable::parse(&bytes[..70], encoding, None).is_err());
        assert!(VersionRequirementTable::parse(&bytes[..10], encoding, None).is_err());
    }

    #[test]
    fn reject_vn_next_loop() {
        // The offsets are unsigned, so a chain cannot go back. Each entry has `vn_next` 4 and
        // `vn_cnt` 0, so the chain walks through overlapping entries. The parser stops after
        // the number of entries that fit in the bytes.
        let bytes = [4_u8, 0, 0, 0].repeat(16);
        let error = VersionRequirementTable::parse(&bytes, Encoding::ELF32_LE, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn reject_aux_loop() {
        // `vn_cnt` is 0xffff and each `Elf_Vernaux` entry points 4 bytes forward, so the
        // entries overlap. The parser stops after the number of auxiliary entries that fit in
        // the bytes (96 / 16 = 6).
        let encoding = Encoding::ELF64_LE;
        let mut bytes = Vec::new();
        verneed(&mut bytes, encoding, 0xffff, [1, 16, 0]);
        bytes.extend_from_slice(&[4_u8, 0, 0, 0].repeat(20));
        assert_eq!(bytes.len(), 96);
        let error = VersionRequirementTable::parse(&bytes, encoding, None).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn write_rejects_too_many_entries() {
        let table = VersionRequirementTable {
            requirements: vec![VersionRequirement {
                version: VER_NEED_CURRENT,
                file: 1,
                entries: vec![NEED_A; 0x1_0000],
            }],
        };
        let error = table.write(Encoding::ELF64_LE).unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ValueOutOfRange(_)));
    }

    #[test]
    fn from_name_uses_sysv_hash() {
        let entry = VersionNeedEntry::from_name(3, 0, 7, b"GLIBC_2.2.5");
        assert_eq!(entry, VersionNeedEntry::new(3, 0, 7, 0x0969_1a75));
    }
}
