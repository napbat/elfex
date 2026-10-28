//! Symbol hash tables.
//!
//! A dynamic linker uses a hash table to find a dynamic symbol by name. ELF files use two
//! formats:
//!
//! - [`SysvHashTable`]: the classic System V table (`DT_HASH`, `SHT_HASH`), with the
//!   [`sysv_hash`] function.
//! - [`GnuHashTable`]: the GNU table (`DT_GNU_HASH`, `SHT_GNU_HASH`), with a Bloom filter and
//!   the [`gnu_hash`] function.
//!
//! The tables contain symbol indexes only. A lookup gets the symbol names from a callback,
//! because the names are in the dynamic symbol table and the dynamic string table.
//!
//! # Examples
//!
//! ```
//! use elfex::hash::{GnuHashTable, SysvHashTable, sysv_hash_entry_size};
//! use elfex::{Encoding, Machine};
//!
//! let encoding = Encoding::ELF64_LE;
//! // The names of the dynamic symbols. Symbol 0 is the null symbol.
//! let names: [&[u8]; 3] = [b"", b"malloc", b"free"];
//! let name_of = |index: u32| names.get(usize::try_from(index).ok()?).copied();
//!
//! let entry_size = sysv_hash_entry_size(Machine::X86_64, encoding.class);
//! let table = SysvHashTable::build(&names, 0)?;
//! let bytes = table.write(encoding, entry_size)?;
//! let parsed = SysvHashTable::parse(&bytes, encoding, entry_size)?;
//! assert_eq!(parsed, table);
//! assert_eq!(parsed.lookup(b"free", name_of), Some(2));
//! assert_eq!(parsed.lookup(b"calloc", name_of), None);
//!
//! // The GNU table hashes the symbols from index 1. It can reorder them: `order` gives the
//! // old position of each hashed symbol.
//! let (table, order) = GnuHashTable::build(&names[1..], 1, encoding, 0)?;
//! let mut sorted = vec![names[0]];
//! sorted.extend(order.iter().map(|&position| names[1 + position]));
//! let parsed = GnuHashTable::parse(&table.write(encoding)?, encoding)?;
//! let sorted_name_of = |index: u32| sorted.get(usize::try_from(index).ok()?).copied();
//! let index = parsed.lookup(b"malloc", sorted_name_of);
//! assert_eq!(index.and_then(sorted_name_of), Some(&b"malloc"[..]));
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::endian::{Class, Encoding};
use crate::header::Machine;
use crate::prelude::*;
use crate::{Error, Result};

mod gnu;
#[cfg(test)]
mod tests;

pub use gnu::GnuHashTable;

/// Calculate the System V ELF hash of a symbol name.
///
/// This is the `elf_hash` function of the System V ABI. `DT_HASH` tables use it.
#[must_use]
pub fn sysv_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in name {
        hash = (hash << 4).wrapping_add(u32::from(byte));
        let high = hash & 0xf000_0000;
        if high != 0 {
            hash ^= high >> 24;
        }
        hash &= !high;
    }
    hash
}

/// Calculate the GNU hash of a symbol name.
///
/// This is the djb2 function (`h * 33 + c`, start value 5381, wrapping). `DT_GNU_HASH` tables
/// use it.
#[must_use]
pub fn gnu_hash(name: &[u8]) -> u32 {
    name.iter().fold(5381_u32, |hash, &byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(byte))
    })
}

/// Return the size in bytes of one word in a System V hash table (`DT_HASH`).
///
/// The words are 4 bytes (`Elf32_Word`) on most targets, also in ELF64 files. 64-bit S/390
/// (`EM_S390`) and Alpha (`EM_ALPHA`) use 8-byte words.
#[must_use]
pub const fn sysv_hash_entry_size(machine: Machine, class: Class) -> usize {
    match (machine, class) {
        (Machine::S390 | Machine::ALPHA, Class::Elf64) => 8,
        _ => 4,
    }
}

/// The bucket counts that GNU ld selects from for a hash table.
const BUCKET_COUNTS: [u32; 19] = [
    1, 3, 17, 37, 67, 97, 131, 197, 263, 521, 1031, 2053, 4099, 8209, 16411, 32771, 65537, 131_101,
    262_147,
];

/// Return the bucket count that GNU ld uses for `symbols` hashed symbols.
///
/// The count is the largest value in [`BUCKET_COUNTS`] that is not more than `symbols`, and
/// a minimum of 1.
fn default_bucket_count(symbols: usize) -> u32 {
    let mut best = 1;
    for &count in &BUCKET_COUNTS {
        if usize::try_from(count).is_ok_and(|count| symbols < count) {
            break;
        }
        best = count;
    }
    best
}

/// Convert a count from the table to `usize`. A `usize` has at least 32 bits on the targets
/// of elfex, so the conversion does not fail.
fn to_usize(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// Convert a length to a 32-bit table field, or return a `ValueOutOfRange` error.
fn len_u32(len: usize, field: &str) -> Result<u32> {
    u32::try_from(len)
        .map_err(|_| Error::value_out_of_range(format!("{field} {len} does not fit in 32 bits")))
}

/// Make sure that a System V hash table word size is 4 or 8.
fn check_entry_size(entry_size: usize) -> Result<()> {
    if entry_size == 4 || entry_size == 8 {
        Ok(())
    } else {
        Err(Error::invalid_table(format!(
            "the hash table entry size {entry_size} is not 4 or 8"
        ))
        .in_structure("DT_HASH"))
    }
}

/// Read the word at `index` of a System V hash table.
fn read_word(bytes: &[u8], encoding: Encoding, entry_size: usize, index: usize) -> Result<u32> {
    // An offset after the end of `bytes` gives a `BufferTooSmall` error.
    let offset = index.saturating_mul(entry_size);
    if entry_size == 8 {
        let value = encoding.read_u64(bytes, offset)?;
        u32::try_from(value).map_err(|_| {
            Error::invalid_table(format!(
                "the hash table word {value:#x} does not fit in 32 bits"
            ))
            .at_offset(u64::try_from(offset).unwrap_or(u64::MAX))
        })
    } else {
        encoding.read_u32(bytes, offset)
    }
}

/// A System V symbol hash table (`DT_HASH`, `SHT_HASH`).
///
/// The table starts with `nbucket` and `nchain`, then the `bucket` array and the `chain`
/// array. Each value is a dynamic symbol index. The index 0 (`STN_UNDEF`) ends a chain.
/// `nchain` is equal to the number of symbols in the dynamic symbol table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SysvHashTable {
    /// The `bucket` array: the first symbol index of each hash chain.
    pub buckets: Vec<u32>,
    /// The `chain` array: the next symbol index for each symbol index.
    pub chains: Vec<u32>,
}

impl SysvHashTable {
    /// Parse a System V hash table from the start of `bytes`.
    ///
    /// `entry_size` is the size of each word: 4 or 8. Use [`sysv_hash_entry_size`] to get it.
    /// The parser ignores bytes after the end of the table.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `entry_size` is
    ///   not 4 or 8, if `bytes` is too small for the bucket and chain arrays, or if an 8-byte
    ///   word does not fit in 32 bits.
    /// - Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` is
    ///   too small for the header.
    pub fn parse(bytes: &[u8], encoding: Encoding, entry_size: usize) -> Result<Self> {
        check_entry_size(entry_size)?;
        Self::parse_words(bytes, encoding, entry_size).map_err(|e| e.in_structure("DT_HASH"))
    }

    /// Parse the words of a table with a valid `entry_size`.
    fn parse_words(bytes: &[u8], encoding: Encoding, entry_size: usize) -> Result<Self> {
        let nbucket = read_word(bytes, encoding, entry_size, 0)?;
        let nchain = read_word(bytes, encoding, entry_size, 1)?;
        let bucket_len = to_usize(nbucket);
        let chain_len = to_usize(nchain);
        let needed = bucket_len
            .checked_add(chain_len)
            .and_then(|words| words.checked_add(2))
            .and_then(|words| words.checked_mul(entry_size));
        if needed.is_none_or(|needed| needed > bytes.len()) {
            return Err(Error::invalid_table(format!(
                "{nbucket} buckets and {nchain} chains do not fit in {} bytes",
                bytes.len()
            )));
        }
        let read_range = |start: usize, len: usize| -> Result<Vec<u32>> {
            (start..start + len)
                .map(|index| read_word(bytes, encoding, entry_size, index))
                .collect()
        };
        Ok(Self {
            buckets: read_range(2, bucket_len)?,
            chains: read_range(2 + bucket_len, chain_len)?,
        })
    }

    /// Serialize the table.
    ///
    /// `entry_size` is the size of each word: 4 or 8.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `entry_size` is
    ///   not 4 or 8.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an array
    ///   has more than `u32::MAX` entries.
    pub fn write(&self, encoding: Encoding, entry_size: usize) -> Result<Vec<u8>> {
        check_entry_size(entry_size)?;
        let nbucket = len_u32(self.buckets.len(), "nbucket")?;
        let nchain = len_u32(self.chains.len(), "nchain")?;
        let words = self
            .buckets
            .len()
            .saturating_add(self.chains.len())
            .saturating_add(2);
        let mut out = Vec::with_capacity(words.saturating_mul(entry_size));
        let header = [nbucket, nchain];
        let all = header
            .iter()
            .chain(self.buckets.iter())
            .chain(self.chains.iter());
        for &word in all {
            if entry_size == 8 {
                encoding.write_u64(&mut out, u64::from(word));
            } else {
                encoding.write_u32(&mut out, word);
            }
        }
        Ok(out)
    }

    /// Return `nchain`: the number of symbols in the dynamic symbol table.
    #[must_use]
    pub fn symbol_count(&self) -> u32 {
        u32::try_from(self.chains.len()).unwrap_or(u32::MAX)
    }

    /// Find the index of the dynamic symbol with the name `name`.
    ///
    /// `symbol_name` returns the name of the symbol at a symbol index, or `None` if the name
    /// is not available. The lookup stops after `nchain` steps, so a chain with a cycle does
    /// not cause an endless loop.
    ///
    /// Return `None` if no symbol in the chain has the name.
    #[must_use]
    pub fn lookup<'a, F>(&self, name: &[u8], mut symbol_name: F) -> Option<u32>
    where
        F: FnMut(u32) -> Option<&'a [u8]>,
    {
        let nbucket = u32::try_from(self.buckets.len())
            .ok()
            .filter(|count| *count != 0)?;
        let bucket = usize::try_from(sysv_hash(name) % nbucket).ok()?;
        let mut index = *self.buckets.get(bucket)?;
        for _ in 0..self.chains.len() {
            if index == 0 {
                return None;
            }
            if symbol_name(index) == Some(name) {
                return Some(index);
            }
            index = *self.chains.get(usize::try_from(index).ok()?)?;
        }
        None
    }

    /// Build a System V hash table for the dynamic symbols with the names `names`.
    ///
    /// `names[i]` is the name of the symbol at index `i`. Symbol 0 is the null symbol: the
    /// builder does not put it in the table. Set `nbucket` to 0 to let the builder select the
    /// bucket count that GNU ld uses.
    ///
    /// In each chain, the symbols are in increasing index order. Thus a lookup finds the
    /// first symbol with a name.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if `names` has
    /// more than `u32::MAX` entries.
    pub fn build(names: &[&[u8]], nbucket: u32) -> Result<Self> {
        len_u32(names.len(), "nchain")?;
        let nbucket = if nbucket == 0 {
            default_bucket_count(names.len())
        } else {
            nbucket
        };
        let mut buckets = vec![0_u32; to_usize(nbucket)];
        let mut chains = vec![0_u32; names.len()];
        for (index, name) in names.iter().enumerate().skip(1).rev() {
            let symbol = len_u32(index, "symbol index")?;
            let bucket = to_usize(sysv_hash(name) % nbucket);
            if let (Some(chain), Some(head)) = (chains.get_mut(index), buckets.get_mut(bucket)) {
                *chain = *head;
                *head = symbol;
            }
        }
        Ok(Self { buckets, chains })
    }
}
