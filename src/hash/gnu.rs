//! The GNU symbol hash table (`DT_GNU_HASH`, `SHT_GNU_HASH`).

use super::{default_bucket_count, gnu_hash, len_u32, to_usize};
use crate::endian::{Class, Encoding};
use crate::prelude::*;
use crate::{Error, Result};

/// The size of the `DT_GNU_HASH` header: `nbuckets`, `symoffset`, `bloom_size` and
/// `bloom_shift`.
const HEADER_SIZE: usize = 16;

/// Return the number of bits in one Bloom filter word of the class: 32 or 64.
const fn word_bits(class: Class) -> u32 {
    match class {
        Class::Elf32 => 32,
        Class::Elf64 => 64,
    }
}

/// Return the smallest `n` such that `1 << n` is not less than `value`.
const fn ceil_log2(value: u32) -> u32 {
    if value <= 1 {
        0
    } else {
        32 - (value - 1).leading_zeros()
    }
}

/// A GNU symbol hash table (`DT_GNU_HASH`, `SHT_GNU_HASH`).
///
/// The table has a header, a Bloom filter, a bucket array and a chain array:
///
/// - The dynamic symbols before `symoffset` are not in the table.
/// - The hashed symbols are sorted by bucket. A bucket holds the index of the first symbol
///   in its chain, or 0 for an empty bucket.
/// - The chain array holds one hash value for each hashed symbol (symbol index minus
///   `symoffset`). Bit 0 of a value is 1 for the last symbol of a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GnuHashTable {
    /// The class of the table. It sets the size of the Bloom filter words (32 or 64 bits).
    pub class: Class,
    /// `symoffset`: the dynamic symbol index of the first hashed symbol.
    pub symoffset: u32,
    /// `bloom_shift`: the shift count for the second Bloom filter hash.
    pub bloom_shift: u32,
    /// The Bloom filter words. The file has class-sized words; this field widens them to
    /// `u64`.
    pub bloom: Vec<u64>,
    /// The bucket array: the first dynamic symbol index of each chain, or 0.
    pub buckets: Vec<u32>,
    /// The chain array: the hash values of the hashed symbols. Bit 0 marks the end of a chain.
    pub chains: Vec<u32>,
}

impl GnuHashTable {
    /// Parse a GNU hash table from the start of `bytes`.
    ///
    /// The chain array has no explicit length. The parser follows the chain of the highest
    /// bucket value to its end, and ignores the bytes after it.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` is
    ///   too small for the header.
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `bytes` is too
    ///   small for the Bloom filter, the bucket array or the chain array.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        Self::parse_parts(bytes, encoding).map_err(|e| e.in_structure("DT_GNU_HASH"))
    }

    /// Parse the table without the structure context.
    fn parse_parts(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        let nbuckets = encoding.read_u32(bytes, 0)?;
        let symoffset = encoding.read_u32(bytes, 4)?;
        let bloom_size = encoding.read_u32(bytes, 8)?;
        let bloom_shift = encoding.read_u32(bytes, 12)?;
        let word = encoding.addr_size();
        let bloom_len = to_usize(bloom_size);
        let bucket_len = to_usize(nbuckets);
        let buckets_start = bloom_len
            .checked_mul(word)
            .and_then(|size| size.checked_add(HEADER_SIZE));
        let chains_start = buckets_start.and_then(|start| {
            bucket_len
                .checked_mul(4)
                .and_then(|size| size.checked_add(start))
        });
        let Some(chains_start) = chains_start.filter(|end| *end <= bytes.len()) else {
            return Err(Error::invalid_table(format!(
                "{bloom_size} Bloom filter words and {nbuckets} buckets do not fit in {} bytes",
                bytes.len()
            )));
        };
        let buckets_start = HEADER_SIZE + bloom_len * word;
        let bloom = (0..bloom_len)
            .map(|index| encoding.read_addr(bytes, HEADER_SIZE + index * word))
            .collect::<Result<Vec<_>>>()?;
        let buckets = (0..bucket_len)
            .map(|index| encoding.read_u32(bytes, buckets_start + index * 4))
            .collect::<Result<Vec<_>>>()?;
        let chain_count = chain_len(bytes, encoding, chains_start, symoffset, &buckets)?;
        let chains = (0..chain_count)
            .map(|index| encoding.read_u32(bytes, chains_start + index * 4))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            class: encoding.class,
            symoffset,
            bloom_shift,
            bloom,
            buckets,
            chains,
        })
    }

    /// Serialize the table.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the class of
    ///   `encoding` is not the class of the table.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an array
    ///   has more than `u32::MAX` entries, or if a Bloom filter word of an ELF32 table does not
    ///   fit in 32 bits.
    pub fn write(&self, encoding: Encoding) -> Result<Vec<u8>> {
        if encoding.class != self.class {
            return Err(Error::invalid_table(
                "the encoding class is not the class of the Bloom filter words",
            )
            .in_structure("DT_GNU_HASH"));
        }
        let nbuckets = len_u32(self.buckets.len(), "nbuckets")?;
        let bloom_size = len_u32(self.bloom.len(), "bloom_size")?;
        let size = self
            .bloom
            .len()
            .saturating_mul(encoding.addr_size())
            .saturating_add(self.buckets.len().saturating_mul(4))
            .saturating_add(self.chains.len().saturating_mul(4))
            .saturating_add(HEADER_SIZE);
        let mut out = Vec::with_capacity(size);
        for value in [nbuckets, self.symoffset, bloom_size, self.bloom_shift] {
            encoding.write_u32(&mut out, value);
        }
        for &word in &self.bloom {
            encoding.write_addr(&mut out, word)?;
        }
        for &value in self.buckets.iter().chain(self.chains.iter()) {
            encoding.write_u32(&mut out, value);
        }
        Ok(out)
    }

    /// Return the number of dynamic symbols that the table covers: `symoffset` plus the
    /// number of hashed symbols.
    ///
    /// The dynamic symbol table can have more symbols than this count. The table does not
    /// record symbols after the last hashed symbol.
    #[must_use]
    pub fn symbol_count(&self) -> u32 {
        u32::try_from(self.chains.len())
            .ok()
            .and_then(|count| self.symoffset.checked_add(count))
            .unwrap_or(u32::MAX)
    }

    /// Return `false` if the Bloom filter shows that no symbol has the GNU hash `hash`.
    ///
    /// A `true` result does not prove that a symbol has the hash. An empty Bloom filter gives
    /// `true` for all hashes.
    #[must_use]
    pub fn maybe_contains(&self, hash: u32) -> bool {
        let Ok(words) = u32::try_from(self.bloom.len()) else {
            return true;
        };
        if words == 0 {
            return true;
        }
        let bits = word_bits(self.class);
        // The index is less than `words`, so the word is present.
        let index = to_usize((hash / bits) & (words - 1));
        let word = self.bloom.get(index).copied().unwrap_or(u64::MAX);
        let second = hash.checked_shr(self.bloom_shift).unwrap_or(0);
        let mask = (1_u64 << (hash % bits)) | (1_u64 << (second % bits));
        word & mask == mask
    }

    /// Find the index of the dynamic symbol with the name `name`.
    ///
    /// `symbol_name` returns the name of the symbol at a symbol index, or `None` if the name
    /// is not available. The lookup checks the Bloom filter first, then compares the hash
    /// values in the chain and calls `symbol_name` only for matching hashes.
    ///
    /// Return `None` if no symbol in the chain has the name.
    #[must_use]
    pub fn lookup<'a, F>(&self, name: &[u8], mut symbol_name: F) -> Option<u32>
    where
        F: FnMut(u32) -> Option<&'a [u8]>,
    {
        let hash = gnu_hash(name);
        if !self.maybe_contains(hash) {
            return None;
        }
        let nbuckets = u32::try_from(self.buckets.len())
            .ok()
            .filter(|count| *count != 0)?;
        let mut symbol = *self.buckets.get(usize::try_from(hash % nbuckets).ok()?)?;
        if symbol == 0 || symbol < self.symoffset {
            return None;
        }
        let mut index = usize::try_from(symbol - self.symoffset).ok()?;
        loop {
            let value = *self.chains.get(index)?;
            if (value ^ hash) >> 1 == 0 && symbol_name(symbol) == Some(name) {
                return Some(symbol);
            }
            if value & 1 != 0 {
                return None;
            }
            index = index.checked_add(1)?;
            symbol = symbol.checked_add(1)?;
        }
    }

    /// Build a GNU hash table for the hashed symbols with the names `names`.
    ///
    /// `names` are the names of the hashed symbols in their current order: the symbols at
    /// dynamic symbol index `symoffset` and after. Set `nbuckets` to 0 to let the builder
    /// select the bucket count that GNU ld uses. The builder selects the Bloom filter size and
    /// `bloom_shift` like GNU ld.
    ///
    /// The table requires the hashed symbols sorted by bucket. The returned `Vec<usize>` is
    /// the new order: a permutation of `0..names.len()`. Entry `i` is the current position of
    /// the symbol that must go to index `symoffset + i`. Reorder the hashed symbols in the
    /// dynamic symbol table (and the symbol version table) with it. The returned table is
    /// valid for the reordered symbols.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `symoffset` is 0
    ///   and `names` is not empty: the null symbol cannot be in the table.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if the last
    ///   hashed symbol index does not fit in 32 bits.
    pub fn build(
        names: &[&[u8]],
        symoffset: u32,
        encoding: Encoding,
        nbuckets: u32,
    ) -> Result<(Self, Vec<usize>)> {
        if symoffset == 0 && !names.is_empty() {
            return Err(
                Error::invalid_table("symoffset 0 puts the null symbol in the table")
                    .in_structure("DT_GNU_HASH"),
            );
        }
        let count = len_u32(names.len(), "hashed symbol count")?;
        symoffset.checked_add(count).ok_or_else(|| {
            Error::value_out_of_range(format!(
                "{count} hashed symbols after symoffset {symoffset} do not fit in 32 bits"
            ))
        })?;
        let nbuckets = if nbuckets == 0 {
            default_bucket_count(names.len())
        } else {
            nbuckets
        };
        let hashes: Vec<u32> = names.iter().copied().map(gnu_hash).collect();
        let bucket_of = |position: usize| hashes.get(position).map(|hash| hash % nbuckets);
        let mut order: Vec<usize> = (0..names.len()).collect();
        order.sort_by_key(|&position| bucket_of(position));
        let mut buckets = vec![0_u32; to_usize(nbuckets)];
        let mut chains = Vec::with_capacity(order.len());
        for (new_position, &old_position) in order.iter().enumerate() {
            let hash = hashes.get(old_position).copied().unwrap_or_default();
            let bucket = hash % nbuckets;
            let symbol = symoffset.saturating_add(len_u32(new_position, "symbol index")?);
            if let Some(head) = buckets.get_mut(to_usize(bucket))
                && *head == 0
            {
                *head = symbol;
            }
            let last = order
                .get(new_position + 1)
                .is_none_or(|&next| bucket_of(next) != Some(bucket));
            chains.push(if last { hash | 1 } else { hash & !1 });
        }
        let (bloom, bloom_shift) = build_bloom(&hashes, encoding.class)?;
        let table = Self {
            class: encoding.class,
            symoffset,
            bloom_shift,
            bloom,
            buckets,
            chains,
        };
        Ok((table, order))
    }
}

/// Return the number of chain array entries of a GNU hash table.
///
/// Follow the chain of the highest bucket value to the entry with bit 0 set.
fn chain_len(
    bytes: &[u8],
    encoding: Encoding,
    chains_start: usize,
    symoffset: u32,
    buckets: &[u32],
) -> Result<usize> {
    let Some(last_start) = buckets
        .iter()
        .copied()
        .filter(|&value| value != 0 && value >= symoffset)
        .max()
    else {
        return Ok(0);
    };
    let mut index = to_usize(last_start - symoffset);
    loop {
        let value = index
            .checked_mul(4)
            .and_then(|offset| offset.checked_add(chains_start))
            .and_then(|offset| encoding.read_u32(bytes, offset).ok())
            .ok_or_else(|| {
                Error::invalid_table(format!(
                    "the chain of symbol {last_start} continues after the end of the data"
                ))
            })?;
        // The read above fails before `index` can reach `usize::MAX`.
        index += 1;
        if value & 1 != 0 {
            return Ok(index);
        }
    }
}

/// Build the Bloom filter for the hashes like GNU ld. Return the words and `bloom_shift`.
fn build_bloom(hashes: &[u32], class: Class) -> Result<(Vec<u64>, u32)> {
    let count = len_u32(hashes.len(), "hashed symbol count")?;
    let mut log2 = ceil_log2(count) + 1;
    if log2 < 3 {
        log2 = 5;
    } else if (1_u64 << (log2 - 2)) & u64::from(count) != 0 {
        log2 += 3;
    } else {
        log2 += 2;
    }
    let word_log2 = if class.is_64bit() {
        log2 = log2.max(6);
        6
    } else {
        5
    };
    let bloom_shift = log2.min(31);
    let words = 1_u32 << (bloom_shift - word_log2);
    let bits = word_bits(class);
    let mut bloom = vec![0_u64; to_usize(words)];
    for &hash in hashes {
        let index = to_usize((hash / bits) & (words - 1));
        if let Some(word) = bloom.get_mut(index) {
            *word |= (1_u64 << (hash % bits)) | (1_u64 << ((hash >> bloom_shift) % bits));
        }
    }
    Ok((bloom, bloom_shift))
}
