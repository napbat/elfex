//! Section group tables (`SHT_GROUP` sections).
//!
//! The data of a section group is a sequence of `Elf32_Word` values in all classes. The first
//! word holds the group flags, for example [`GRP_COMDAT`]. Each other word is the section index
//! of a member.
//!
//! Use [`GroupTable`] to parse and write these words.
//! [`ElfFile::section_groups`](crate::ElfFile::section_groups) gives each group of a file with
//! its signature, as a [`SectionGroup`](crate::SectionGroup).
//!
//! # Examples
//!
//! ```
//! use elfex::Encoding;
//! use elfex::group::{GRP_COMDAT, GroupTable};
//!
//! let table = GroupTable {
//!     flags: GRP_COMDAT,
//!     members: vec![3, 4],
//! };
//! let bytes = table.write(Encoding::ELF64_BE);
//! assert_eq!(bytes, [0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 4]);
//! assert_eq!(GroupTable::parse(&bytes, Encoding::ELF64_BE)?, table);
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};

/// `GRP_COMDAT`: the section group is a COMDAT group.
pub const GRP_COMDAT: u32 = 0x1;

/// The parsed data of a section group (`SHT_GROUP` section).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct GroupTable {
    /// The group flags: the first word of the section, for example [`GRP_COMDAT`].
    pub flags: u32,
    /// The section indices of the members, in table order.
    pub members: Vec<u32>,
}

impl GroupTable {
    /// Parse the table from all of `bytes`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is 0 or not a multiple of 4.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        if bytes.is_empty() || !bytes.len().is_multiple_of(4) {
            return Err(Error::invalid_table(format!(
                "SHT_GROUP size {} is 0 or not a multiple of 4",
                bytes.len()
            )));
        }
        let mut words = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| encoding.read_u32(chunk, 0));
        let flags = words.next().transpose()?.unwrap_or(0);
        let members = words.collect::<Result<Vec<_>>>()?;
        Ok(Self { flags, members })
    }

    /// Serialize the flag word and the member indices.
    #[must_use]
    pub fn write(&self, encoding: Encoding) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.members.len().saturating_add(1).saturating_mul(4));
        encoding.write_u32(&mut out, self.flags);
        for &member in &self.members {
            encoding.write_u32(&mut out, member);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn round_trips_both_byte_orders() {
        let table = GroupTable {
            flags: GRP_COMDAT,
            members: vec![1, 0x0001_0002],
        };
        for encoding in [Encoding::ELF32_LE, Encoding::ELF64_BE] {
            let bytes = table.write(encoding);
            assert_eq!(bytes.len(), 12);
            assert_eq!(GroupTable::parse(&bytes, encoding).unwrap(), table);
        }
        let little = table.write(Encoding::ELF32_LE);
        assert_eq!(little[..8], [1, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn parses_a_group_without_members() {
        let table = GroupTable::parse(&[0; 4], Encoding::ELF64_LE).unwrap();
        assert_eq!(table, GroupTable::default());
    }

    #[test]
    fn rejects_an_empty_or_partial_table() {
        for bytes in [&[][..], &[1, 0, 0, 0, 2][..]] {
            let error = GroupTable::parse(bytes, Encoding::ELF64_LE).unwrap_err();
            assert!(
                matches!(error.kind(), ErrorKind::InvalidTable(_)),
                "{error}"
            );
        }
    }
}
