//! String tables (`SHT_STRTAB` sections and the `DT_STRTAB` data).
//!
//! A string table is a sequence of NUL-terminated strings. Other structures refer to a string
//! by its byte offset in the table (for example `st_name`, `sh_name` and `DT_NEEDED`). Offset 0
//! is the empty string in a well-formed table.
//!
//! Use [`StringTable`] to read strings, and [`StringTableBuilder`] to make a new table. A
//! [`StringTable`] borrows its bytes, so it does not copy the table of a file.
//!
//! # Examples
//!
//! ```
//! use elfex::strtab::{StringTable, StringTableBuilder};
//!
//! let mut builder = StringTableBuilder::new();
//! let foobar = builder.add("foobar")?;
//! // "bar" uses the tail of "foobar".
//! let bar = builder.add("bar")?;
//! assert_eq!(bar, foobar + 3);
//!
//! let table = builder.table();
//! assert_eq!(table.get(foobar)?, "foobar");
//! assert_eq!(table.get(bar)?, "bar");
//! assert_eq!(table.get(0)?, "");
//! # Ok::<(), elfex::Error>(())
//! ```

use crate::prelude::*;
use crate::{Error, Result};
use core::ops::Bound;

/// A string table (`SHT_STRTAB` section data or the `DT_STRTAB` data).
///
/// The table borrows its bytes. Each lookup checks the offset and the NUL terminator, so the
/// bytes can come from an untrusted file. The strings that a lookup returns borrow the bytes,
/// not the table. Use [`StringTableBuilder::table`] to read the strings of a new table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct StringTable<'a> {
    data: &'a [u8],
}

impl<'a> StringTable<'a> {
    /// Make a string table of `bytes`. The method does not copy the bytes.
    #[must_use]
    pub const fn parse(bytes: &'a [u8]) -> Self {
        Self { data: bytes }
    }

    /// Return the raw bytes of the table.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Return the size of the table in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the table has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return the bytes of the string at `offset`, without the NUL terminator.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `offset` is not
    /// in the table, or if no NUL terminator follows `offset`.
    pub fn get_bytes(&self, offset: u32) -> Result<&'a [u8]> {
        let rest = usize::try_from(offset)
            .ok()
            .and_then(|start| self.data.get(start..))
            .ok_or_else(|| {
                Error::invalid_table(format!(
                    "string offset {offset:#x} is outside the string table ({} bytes)",
                    self.data.len()
                ))
                .at_offset(u64::from(offset))
            })?;
        nul_position(rest)
            .and_then(|len| rest.get(..len))
            .ok_or_else(|| {
                Error::invalid_table(format!(
                    "string at offset {offset:#x} has no NUL terminator"
                ))
                .at_offset(u64::from(offset))
            })
    }

    /// Return the string at `offset` as UTF-8 text.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `offset` is
    ///   not in the table, or if no NUL terminator follows `offset`.
    /// - Return [`ErrorKind::InvalidUtf8`](crate::ErrorKind::InvalidUtf8) if the string is not
    ///   valid UTF-8.
    pub fn get(&self, offset: u32) -> Result<&'a str> {
        let bytes = self.get_bytes(offset)?;
        core::str::from_utf8(bytes).map_err(|_| Error::invalid_utf8().at_offset(u64::from(offset)))
    }

    /// Return the string at `offset`. Replace each invalid UTF-8 sequence with `U+FFFD`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `offset` is not
    /// in the table, or if no NUL terminator follows `offset`.
    pub fn get_lossy(&self, offset: u32) -> Result<Cow<'a, str>> {
        self.get_bytes(offset).map(String::from_utf8_lossy)
    }

    /// Return an iterator over the NUL-terminated strings of the table.
    ///
    /// Each item is the offset of a string and its bytes without the NUL terminator. The
    /// iterator starts at offset 0. It stops at the first string that has no NUL terminator,
    /// or at an offset that does not fit in 32 bits.
    #[must_use]
    pub fn iter(&self) -> StringTableIter<'a> {
        StringTableIter {
            data: self.data,
            pos: 0,
        }
    }
}

impl<'a> IntoIterator for &StringTable<'a> {
    type Item = (u32, &'a [u8]);
    type IntoIter = StringTableIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for StringTable<'a> {
    type Item = (u32, &'a [u8]);
    type IntoIter = StringTableIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// An iterator over the strings of a [`StringTable`].
///
/// Each item is the offset of a string and its bytes without the NUL terminator.
#[derive(Debug, Clone)]
pub struct StringTableIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for StringTableIter<'a> {
    type Item = (u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.next_string();
        if item.is_none() {
            // Stop all later calls without a new scan.
            self.pos = self.data.len();
        }
        item
    }
}

impl<'a> StringTableIter<'a> {
    /// Read the string at the current position and move after its NUL terminator.
    fn next_string(&mut self) -> Option<(u32, &'a [u8])> {
        let rest = self.data.get(self.pos..)?;
        let len = nul_position(rest)?;
        let offset = u32::try_from(self.pos).ok()?;
        let bytes = rest.get(..len)?;
        self.pos = self.pos.checked_add(len)?.checked_add(1)?;
        Some((offset, bytes))
    }
}

/// A builder for a new string table.
///
/// The table starts with one NUL byte, so offset 0 is the empty string. The builder adds each
/// different string one time:
///
/// - If the table already has the same string, [`add`](Self::add) returns its offset.
/// - If the table already has a longer string that ends with the new string, `add` returns
///   the offset of that tail. For example, `"bar"` can use the tail of `"foobar"`.
///
/// The builder does not move an old string to the tail of a longer string that you add
/// later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringTableBuilder {
    data: Vec<u8>,
    /// Each added string in reverse byte order, with the offset of its NUL terminator.
    ///
    /// The strings that end with a string `s` are the keys that start with the reverse of `s`.
    /// In a sorted map, these keys follow the reverse of `s` directly.
    reversed: BTreeMap<Vec<u8>, usize>,
}

impl StringTableBuilder {
    /// Create a builder that holds only the empty string at offset 0.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: vec![0],
            reversed: BTreeMap::new(),
        }
    }

    /// Add a string and return its offset in the table.
    ///
    /// The empty string is always at offset 0. If the table already contains the string, the
    /// builder returns the old offset and does not add bytes.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `string`
    ///   contains a NUL byte.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if the
    ///   offset of the string does not fit in 32 bits.
    pub fn add(&mut self, string: impl AsRef<[u8]>) -> Result<u32> {
        let string = string.as_ref();
        if string.is_empty() {
            return Ok(0);
        }
        if string.contains(&0) {
            return Err(Error::invalid_table(
                "a string table entry cannot contain a NUL byte",
            ));
        }
        let key: Vec<u8> = string.iter().rev().copied().collect();
        if let Some(offset) = self.find_tail(&key) {
            return to_offset(offset);
        }
        let start = self.data.len();
        let offset = to_offset(start)?;
        self.data.extend_from_slice(string);
        let nul = self.data.len();
        self.data.push(0);
        self.reversed.insert(key, nul);
        Ok(offset)
    }

    /// Return the offset of an added string that ends with the bytes of `key` in reverse order.
    fn find_tail(&self, key: &[u8]) -> Option<usize> {
        let (found, &nul) = self
            .reversed
            .range::<[u8], _>((Bound::Included(key), Bound::Unbounded))
            .next()?;
        if found.starts_with(key) {
            nul.checked_sub(key.len())
        } else {
            None
        }
    }

    /// Return the bytes of the table.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return a [`StringTable`] that reads the strings of the builder.
    #[must_use]
    pub fn table(&self) -> StringTable<'_> {
        StringTable::parse(&self.data)
    }

    /// Return the bytes of the table and consume the builder.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Return the size of the table in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if the table has no bytes. The leading NUL byte makes this `false`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Default for StringTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Return the position of the first NUL byte in `bytes`.
///
/// The function tests 8 bytes at a time, because symbol names are long and each name lookup
/// searches for the NUL terminator.
fn nul_position(bytes: &[u8]) -> Option<usize> {
    const LOW: u64 = 0x0101_0101_0101_0101;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let (chunks, _) = bytes.as_chunks::<8>();
    let mut start = 0;
    for chunk in chunks {
        let word = u64::from_le_bytes(*chunk);
        // The expression is not zero if and only if a byte of `word` is zero.
        if word.wrapping_sub(LOW) & !word & HIGH != 0 {
            break;
        }
        start += 8;
    }
    let tail = bytes.get(start..)?;
    tail.iter()
        .position(|&byte| byte == 0)
        .map(|position| start + position)
}

/// Convert a byte position in the table to a 32-bit string offset.
fn to_offset(position: usize) -> Result<u32> {
    u32::try_from(position).map_err(|_| {
        Error::value_out_of_range(format!(
            "string offset {position:#x} does not fit in 32 bits"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn get_reads_strings_and_tails() {
        let table = StringTable::parse(b"\0foo\0bar\0");
        assert_eq!(table.len(), 9);
        assert_eq!(table.get(0).unwrap(), "");
        assert_eq!(table.get(1).unwrap(), "foo");
        assert_eq!(table.get(2).unwrap(), "oo");
        assert_eq!(table.get(5).unwrap(), "bar");
        assert_eq!(table.get_bytes(8).unwrap(), b"");
        assert_eq!(table.as_bytes(), b"\0foo\0bar\0");
    }

    #[test]
    fn get_rejects_malformed_offsets() {
        let table = StringTable::parse(b"\0foo\0bar");
        // The offset is equal to the length.
        let err = table.get_bytes(8).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        // The offset is after the end.
        let err = table.get(100).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        let err = table.get(u32::MAX).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        // The last string has no NUL terminator.
        let err = table.get(5).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        let err = table.get_lossy(6).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));

        let empty = StringTable::default();
        assert!(empty.is_empty());
        let err = empty.get(0).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn get_reports_invalid_utf8() {
        let table = StringTable::parse(&[0, b'a', 0xff, 0]);
        let err = table.get(1).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidUtf8));
        assert_eq!(table.get_lossy(1).unwrap(), "a\u{fffd}");
        assert_eq!(table.get_bytes(1).unwrap(), [b'a', 0xff]);
    }

    #[test]
    fn iter_stops_at_unterminated_string() {
        let table = StringTable::parse(b"\0foo\0\0bar\0trail");
        let items: Vec<(u32, &[u8])> = table.iter().collect();
        assert_eq!(
            items,
            [
                (0, &b""[..]),
                (1, &b"foo"[..]),
                (5, &b""[..]),
                (6, &b"bar"[..]),
            ]
        );
        let mut iter = table.iter();
        assert_eq!(iter.by_ref().count(), 4);
        assert_eq!(iter.next(), None);
        let mut offsets = Vec::new();
        for (offset, _) in &table {
            offsets.push(offset);
        }
        assert_eq!(offsets, [0, 1, 5, 6]);
        assert_eq!(StringTable::default().iter().count(), 0);
    }

    #[test]
    fn builder_deduplicates_strings() {
        let mut builder = StringTableBuilder::new();
        assert_eq!(builder.as_bytes(), b"\0");
        assert_eq!(builder.add("foo").unwrap(), 1);
        assert_eq!(builder.add(b"bar").unwrap(), 5);
        assert_eq!(builder.add("foo").unwrap(), 1);
        assert_eq!(builder.add("").unwrap(), 0);
        assert_eq!(builder.len(), 9);
        assert!(!builder.is_empty());
        assert_eq!(builder.as_bytes(), b"\0foo\0bar\0");
    }

    #[test]
    fn builder_reuses_tails() {
        let mut builder = StringTableBuilder::default();
        assert_eq!(builder.add("foobar").unwrap(), 1);
        assert_eq!(builder.add("bar").unwrap(), 4);
        assert_eq!(builder.add("r").unwrap(), 6);
        assert_eq!(builder.add("foobar").unwrap(), 1);
        // A longer string after a shorter string gets new bytes.
        assert_eq!(builder.add("xfoobar").unwrap(), 8);
        // "ba" is not a tail, so it gets new bytes.
        assert_eq!(builder.add("ba").unwrap(), 16);
        let bytes = builder.into_bytes();
        assert_eq!(bytes, b"\0foobar\0xfoobar\0ba\0");

        let table = StringTable::parse(&bytes);
        assert_eq!(table.get(4).unwrap(), "bar");
        assert_eq!(table.get(6).unwrap(), "r");
        assert_eq!(table.get(16).unwrap(), "ba");
    }

    #[test]
    fn builder_rejects_nul_bytes() {
        let mut builder = StringTableBuilder::new();
        let err = builder.add(b"a\0b").unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        assert_eq!(builder.as_bytes(), b"\0");
        assert_eq!(builder.table().get(0).unwrap(), "");
    }

    #[test]
    fn nul_position_finds_the_first_nul_at_each_position() {
        for len in 0..20 {
            // Bytes with the high bit set must not look like a NUL byte.
            let mut bytes = vec![0x80; len];
            assert_eq!(nul_position(&bytes), None);
            for position in 0..len {
                bytes[position] = 0;
                assert_eq!(nul_position(&bytes), Some(position), "{len} {position}");
                bytes.fill(0x01);
                bytes[position] = 0;
                if let Some(next) = bytes.get_mut(position + 1) {
                    *next = 0;
                }
                assert_eq!(nul_position(&bytes), Some(position), "{len} {position}");
                bytes.fill(0x80);
            }
        }
    }
}
