//! The relative relocation table `Elf32_Relr` / `Elf64_Relr` (`SHT_RELR`, `DT_RELR`).

use crate::endian::Encoding;
use crate::prelude::*;
use crate::{Error, Result};

/// A relative relocation table (`SHT_RELR` section or `DT_RELR` range) in decoded form.
///
/// Each address is the virtual address (or the section offset in `ET_REL`) of one word that
/// gets the load base added, like the relative relocation type of the machine.
///
/// The encoded table is a list of class-sized words (`Elf32_Relr` or `Elf64_Relr`):
///
/// - A word with bit 0 clear is an address. It relocates that address, and the next bitmap
///   starts at the word after it.
/// - A word with bit 0 set is a bitmap. Bit `i` (for `i` from 1) relocates the word at
///   `base + (i - 1) * word_size`. Each bitmap covers `word_size * 8 - 1` words, and moves the
///   base forward by that number of words.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelrTable {
    /// The decoded addresses, in table order.
    pub addresses: Vec<u64>,
}

impl RelrTable {
    /// Create a table from addresses in any order: sort them and remove duplicates.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if an address is not
    /// aligned to the word size of `encoding`.
    pub fn from_addresses(mut addresses: Vec<u64>, encoding: Encoding) -> Result<Self> {
        let word = word_size(encoding);
        if let Some(bad) = addresses.iter().find(|a| **a % word != 0) {
            return Err(Error::invalid_table(format!(
                "RELR address {bad:#x} is not aligned to {word} bytes"
            ))
            .in_structure(structure_name(encoding)));
        }
        addresses.sort_unstable();
        addresses.dedup();
        Ok(Self { addresses })
    }

    /// Decode a table.
    ///
    /// The decoder returns at most `bytes.len() * 64` addresses. All addresses fit in the
    /// class: an ELF32 address is less than 2^32.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is not a multiple of the word size, if a bitmap has no preceding address, or if
    /// a bitmap address is past the end of the address space of the class.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        let size = encoding.addr_size();
        let word = word_size(encoding);
        let structure = structure_name(encoding);
        if !bytes.len().is_multiple_of(size) {
            return Err(Error::invalid_table(format!(
                "RELR table size {} is not a multiple of {size}",
                bytes.len()
            ))
            .in_structure(structure));
        }
        let cap = bytes.len().saturating_mul(64);
        let span = word.saturating_mul(word * 8 - 1);
        // The highest address of the class.
        let limit = if encoding.is_64bit() {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        };
        let advance =
            |start: u64, delta: u64| start.checked_add(delta).filter(|address| *address <= limit);
        let mut addresses = Vec::new();
        let mut base = BitmapBase::Missing;
        let mut offset = 0;
        while offset < bytes.len() {
            let at_offset = u64::try_from(offset).unwrap_or(u64::MAX);
            let entry = encoding.read_addr(bytes, offset)?;
            if entry & 1 == 0 {
                addresses.push(entry);
                base = advance(entry, word).map_or(BitmapBase::End, BitmapBase::At);
            } else {
                let start = match base {
                    BitmapBase::At(start) => start,
                    BitmapBase::Missing => {
                        return Err(Error::invalid_table(
                            "RELR bitmap without a preceding address",
                        )
                        .in_structure(structure)
                        .at_offset(at_offset));
                    }
                    BitmapBase::End => {
                        return Err(Error::invalid_table(
                            "RELR bitmap after the end of the address space",
                        )
                        .in_structure(structure)
                        .at_offset(at_offset));
                    }
                };
                let mut bitmap = entry >> 1;
                let mut index = 0u64;
                while bitmap != 0 {
                    if bitmap & 1 != 0 {
                        let address = index
                            .checked_mul(word)
                            .and_then(|delta| advance(start, delta))
                            .ok_or_else(|| {
                                Error::invalid_table("RELR address overflows")
                                    .in_structure(structure)
                                    .at_offset(at_offset)
                            })?;
                        addresses.push(address);
                    }
                    bitmap >>= 1;
                    index += 1;
                }
                base = advance(start, span).map_or(BitmapBase::End, BitmapBase::At);
            }
            if addresses.len() > cap {
                return Err(
                    Error::invalid_table("RELR table decodes to too many addresses")
                        .in_structure(structure),
                );
            }
            offset += size;
        }
        Ok(Self { addresses })
    }

    /// Encode the table.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the addresses
    ///   are not strictly increasing or not aligned to the word size. Use
    ///   [`from_addresses`](Self::from_addresses) to sort them.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an address
    ///   does not fit in an ELF32 word.
    pub fn write(&self, encoding: Encoding) -> Result<Vec<u8>> {
        let word = word_size(encoding);
        let bits = word * 8 - 1;
        let structure = structure_name(encoding);
        for (index, address) in self.addresses.iter().enumerate() {
            if address % word != 0 {
                return Err(Error::invalid_table(format!(
                    "RELR address {address:#x} is not aligned to {word} bytes"
                ))
                .in_structure(structure));
            }
            if index > 0 && self.addresses[index - 1] >= *address {
                return Err(Error::invalid_table(format!(
                    "RELR address {address:#x} is not larger than the previous address"
                ))
                .in_structure(structure));
            }
        }
        let mut out = Vec::new();
        let addresses = &self.addresses;
        let mut i = 0;
        while i < addresses.len() {
            let first = addresses[i];
            encoding.write_addr(&mut out, first)?;
            i += 1;
            let mut base = first.checked_add(word);
            while let Some(start) = base {
                let mut bitmap = 0u64;
                while i < addresses.len() {
                    let delta = (addresses[i] - start) / word;
                    if delta >= bits {
                        break;
                    }
                    bitmap |= 1 << delta;
                    i += 1;
                }
                if bitmap == 0 {
                    break;
                }
                encoding.write_addr(&mut out, (bitmap << 1) | 1)?;
                base = start.checked_add(bits * word);
            }
        }
        Ok(out)
    }

    /// Return the number of addresses.
    #[must_use]
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Return `true` if the table has no addresses.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Return an iterator over the addresses.
    pub fn iter(&self) -> core::slice::Iter<'_, u64> {
        self.addresses.iter()
    }
}

impl<'a> IntoIterator for &'a RelrTable {
    type Item = &'a u64;
    type IntoIter = core::slice::Iter<'a, u64>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.iter()
    }
}

/// The start address of the next RELR bitmap.
#[derive(Debug, Clone, Copy)]
enum BitmapBase {
    /// No address precedes the bitmap.
    Missing,
    /// The next bitmap starts at this address.
    At(u64),
    /// The preceding entry ends at the end of the address space of the class, so a bitmap
    /// cannot follow.
    End,
}

/// Return the word size of `encoding` as a `u64`.
const fn word_size(encoding: Encoding) -> u64 {
    if encoding.is_64bit() { 8 } else { 4 }
}

/// Return the spec name of the entry structure.
const fn structure_name(encoding: Encoding) -> &'static str {
    if encoding.is_64bit() {
        "Elf64_Relr"
    } else {
        "Elf32_Relr"
    }
}
