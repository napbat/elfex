//! The ELF class and data encoding, and helpers that read and write values in that encoding.
//!
//! ELF data can be ELF32 or ELF64 ([`Class`]), and little-endian or big-endian ([`Endian`]).
//! [`Encoding`] combines the two. Each parser and builder in this crate takes an [`Encoding`],
//! and reads and writes all multi-byte values through it.

use crate::prelude::*;
use crate::{Error, ErrorKind, Result};

/// The `EI_CLASS` value `ELFCLASS32`.
pub const ELFCLASS32: u8 = 1;
/// The `EI_CLASS` value `ELFCLASS64`.
pub const ELFCLASS64: u8 = 2;
/// The `EI_DATA` value `ELFDATA2LSB` (little-endian).
pub const ELFDATA2LSB: u8 = 1;
/// The `EI_DATA` value `ELFDATA2MSB` (big-endian).
pub const ELFDATA2MSB: u8 = 2;

/// The ELF file class: the size of addresses and offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// `ELFCLASS32`: 32-bit addresses and offsets.
    Elf32,
    /// `ELFCLASS64`: 64-bit addresses and offsets.
    Elf64,
}

impl Class {
    /// Parse an `EI_CLASS` byte.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidClass`] for a value other than `ELFCLASS32` or `ELFCLASS64`.
    pub fn from_ident_byte(value: u8) -> Result<Self> {
        match value {
            ELFCLASS32 => Ok(Self::Elf32),
            ELFCLASS64 => Ok(Self::Elf64),
            other => Err(Error::new(ErrorKind::InvalidClass(other))),
        }
    }

    /// Return the `EI_CLASS` byte of the class.
    #[must_use]
    pub const fn ident_byte(self) -> u8 {
        match self {
            Self::Elf32 => ELFCLASS32,
            Self::Elf64 => ELFCLASS64,
        }
    }

    /// Return the size in bytes of an address, an offset or a class-sized word: 4 or 8.
    #[must_use]
    pub const fn addr_size(self) -> usize {
        match self {
            Self::Elf32 => 4,
            Self::Elf64 => 8,
        }
    }

    /// Return `true` for `ELFCLASS64`.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        matches!(self, Self::Elf64)
    }
}

/// The ELF data encoding: the byte order of multi-byte values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// `ELFDATA2LSB`: little-endian.
    Little,
    /// `ELFDATA2MSB`: big-endian.
    Big,
}

impl Endian {
    /// Parse an `EI_DATA` byte.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidDataEncoding`] for a value other than `ELFDATA2LSB` or
    /// `ELFDATA2MSB`.
    pub fn from_ident_byte(value: u8) -> Result<Self> {
        match value {
            ELFDATA2LSB => Ok(Self::Little),
            ELFDATA2MSB => Ok(Self::Big),
            other => Err(Error::new(ErrorKind::InvalidDataEncoding(other))),
        }
    }

    /// Return the `EI_DATA` byte of the byte order.
    #[must_use]
    pub const fn ident_byte(self) -> u8 {
        match self {
            Self::Little => ELFDATA2LSB,
            Self::Big => ELFDATA2MSB,
        }
    }
}

/// The class and the byte order of ELF data.
///
/// Use the `read_*` methods to decode values at an offset in a byte slice, the `write_*`
/// methods to append values to a `Vec<u8>`, and the `put_*` methods to change values in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Encoding {
    /// The file class.
    pub class: Class,
    /// The byte order.
    pub endian: Endian,
}

/// Get `N` bytes at `offset`, or return a `BufferTooSmall` error.
fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    offset
        .checked_add(N)
        .and_then(|end| bytes.get(offset..end))
        .and_then(|slice| <[u8; N]>::try_from(slice).ok())
        .ok_or_else(|| Error::buffer_too_small(offset.saturating_add(N), bytes.len()))
}

/// Get a mutable range of `N` bytes at `offset`, or return a `BufferTooSmall` error.
fn slice_at_mut<const N: usize>(bytes: &mut [u8], offset: usize) -> Result<&mut [u8]> {
    let len = bytes.len();
    offset
        .checked_add(N)
        .and_then(|end| bytes.get_mut(offset..end))
        .ok_or_else(|| Error::buffer_too_small(offset.saturating_add(N), len))
}

macro_rules! endian_value {
    ($read:ident, $write:ident, $put:ident, $ty:ty, $size:literal, $doc:literal) => {
        #[doc = concat!("Read ", $doc, " at `offset` in `bytes`.")]
        ///
        /// # Errors
        ///
        /// Return [`ErrorKind::BufferTooSmall`] if the value does not fit in `bytes`.
        pub fn $read(self, bytes: &[u8], offset: usize) -> Result<$ty> {
            let raw = array_at::<$size>(bytes, offset)?;
            Ok(match self.endian {
                Endian::Little => <$ty>::from_le_bytes(raw),
                Endian::Big => <$ty>::from_be_bytes(raw),
            })
        }

        #[doc = concat!("Append ", $doc, " to `out`.")]
        pub fn $write(self, out: &mut Vec<u8>, value: $ty) {
            match self.endian {
                Endian::Little => out.extend_from_slice(&value.to_le_bytes()),
                Endian::Big => out.extend_from_slice(&value.to_be_bytes()),
            }
        }

        #[doc = concat!("Write ", $doc, " at `offset` in `bytes`.")]
        ///
        /// # Errors
        ///
        /// Return [`ErrorKind::BufferTooSmall`] if the value does not fit in `bytes`.
        pub fn $put(self, bytes: &mut [u8], offset: usize, value: $ty) -> Result<()> {
            let target = slice_at_mut::<$size>(bytes, offset)?;
            match self.endian {
                Endian::Little => target.copy_from_slice(&value.to_le_bytes()),
                Endian::Big => target.copy_from_slice(&value.to_be_bytes()),
            }
            Ok(())
        }
    };
}

impl Encoding {
    /// ELF32, little-endian.
    pub const ELF32_LE: Self = Self::new(Class::Elf32, Endian::Little);
    /// ELF32, big-endian.
    pub const ELF32_BE: Self = Self::new(Class::Elf32, Endian::Big);
    /// ELF64, little-endian.
    pub const ELF64_LE: Self = Self::new(Class::Elf64, Endian::Little);
    /// ELF64, big-endian.
    pub const ELF64_BE: Self = Self::new(Class::Elf64, Endian::Big);

    /// Create an encoding.
    #[must_use]
    pub const fn new(class: Class, endian: Endian) -> Self {
        Self { class, endian }
    }

    /// Return `true` for `ELFCLASS64`.
    #[must_use]
    pub const fn is_64bit(self) -> bool {
        self.class.is_64bit()
    }

    /// Return the size in bytes of an address, an offset or a class-sized word: 4 or 8.
    #[must_use]
    pub const fn addr_size(self) -> usize {
        self.class.addr_size()
    }

    endian_value!(read_u16, write_u16, put_u16, u16, 2, "a `u16`");
    endian_value!(read_u32, write_u32, put_u32, u32, 4, "a `u32`");
    endian_value!(read_u64, write_u64, put_u64, u64, 8, "a `u64`");
    endian_value!(read_i32, write_i32, put_i32, i32, 4, "an `i32`");
    endian_value!(read_i64, write_i64, put_i64, i64, 8, "an `i64`");

    /// Read a class-sized unsigned value at `offset` in `bytes`.
    ///
    /// A class-sized value is 4 bytes in ELF32 and 8 bytes in ELF64. Examples are `Elf32_Addr`,
    /// `Elf32_Off` and `Elf32_Word`, and `Elf64_Addr`, `Elf64_Off` and `Elf64_Xword`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::BufferTooSmall`] if the value does not fit in `bytes`.
    pub fn read_addr(self, bytes: &[u8], offset: usize) -> Result<u64> {
        match self.class {
            Class::Elf32 => self.read_u32(bytes, offset).map(u64::from),
            Class::Elf64 => self.read_u64(bytes, offset),
        }
    }

    /// Read a class-sized signed value (`Elf32_Sword` or `Elf64_Sxword`) at `offset`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::BufferTooSmall`] if the value does not fit in `bytes`.
    pub fn read_signed_addr(self, bytes: &[u8], offset: usize) -> Result<i64> {
        match self.class {
            Class::Elf32 => self.read_i32(bytes, offset).map(i64::from),
            Class::Elf64 => self.read_i64(bytes, offset),
        }
    }

    /// Append a class-sized unsigned value to `out`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`] if the class is ELF32 and `value` does not fit in
    /// 32 bits.
    pub fn write_addr(self, out: &mut Vec<u8>, value: u64) -> Result<()> {
        match self.class {
            Class::Elf32 => self.write_u32(out, narrow_u32(value)?),
            Class::Elf64 => self.write_u64(out, value),
        }
        Ok(())
    }

    /// Append a class-sized signed value to `out`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`] if the class is ELF32 and `value` does not fit in
    /// 32 bits.
    pub fn write_signed_addr(self, out: &mut Vec<u8>, value: i64) -> Result<()> {
        match self.class {
            Class::Elf32 => self.write_i32(out, narrow_i32(value)?),
            Class::Elf64 => self.write_i64(out, value),
        }
        Ok(())
    }

    /// Write a class-sized unsigned value at `offset` in `bytes`.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::ValueOutOfRange`] if the class is ELF32 and `value` does not fit
    ///   in 32 bits.
    /// - Return [`ErrorKind::BufferTooSmall`] if the value does not fit in `bytes`.
    pub fn put_addr(self, bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
        match self.class {
            Class::Elf32 => self.put_u32(bytes, offset, narrow_u32(value)?),
            Class::Elf64 => self.put_u64(bytes, offset, value),
        }
    }
}

/// Convert a value to `u32`, or return a `ValueOutOfRange` error.
fn narrow_u32(value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| {
        Error::value_out_of_range(format!("{value:#x} does not fit in an ELF32 field"))
    })
}

/// Convert a value to `i32`, or return a `ValueOutOfRange` error.
fn narrow_i32(value: i64) -> Result<i32> {
    i32::try_from(value)
        .map_err(|_| Error::value_out_of_range(format!("{value} does not fit in an ELF32 field")))
}

/// A bounded cursor that reads values in one [`Encoding`].
#[derive(Debug, Clone)]
pub(crate) struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
    encoding: Encoding,
}

impl<'a> ByteReader<'a> {
    /// Create a cursor at the start of `data`.
    pub(crate) const fn new(data: &'a [u8], encoding: Encoding) -> Self {
        Self {
            data,
            pos: 0,
            encoding,
        }
    }

    /// Return the current position.
    pub(crate) const fn position(&self) -> usize {
        self.pos
    }

    /// Return the number of bytes after the current position.
    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Move the position forward by `len` bytes.
    fn advance(&mut self, len: usize) -> Result<usize> {
        let start = self.pos;
        let end = start
            .checked_add(len)
            .filter(|end| *end <= self.data.len())
            .ok_or_else(|| Error::buffer_too_small(start.saturating_add(len), self.data.len()))?;
        self.pos = end;
        Ok(start)
    }

    /// Read one byte.
    pub(crate) fn u8(&mut self) -> Result<u8> {
        let start = self.advance(1)?;
        Ok(self.data[start])
    }

    /// Read a `u16`.
    pub(crate) fn u16(&mut self) -> Result<u16> {
        let start = self.advance(2)?;
        self.encoding.read_u16(self.data, start)
    }

    /// Read a `u32`.
    pub(crate) fn u32(&mut self) -> Result<u32> {
        let start = self.advance(4)?;
        self.encoding.read_u32(self.data, start)
    }

    /// Read a `u64`.
    pub(crate) fn u64(&mut self) -> Result<u64> {
        let start = self.advance(8)?;
        self.encoding.read_u64(self.data, start)
    }

    /// Read a class-sized unsigned value.
    pub(crate) fn addr(&mut self) -> Result<u64> {
        let start = self.advance(self.encoding.addr_size())?;
        self.encoding.read_addr(self.data, start)
    }

    /// Read a class-sized signed value.
    pub(crate) fn signed_addr(&mut self) -> Result<i64> {
        let start = self.advance(self.encoding.addr_size())?;
        self.encoding.read_signed_addr(self.data, start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_both_byte_orders() {
        let mut out = Vec::new();
        Encoding::ELF32_BE.write_u32(&mut out, 0x0102_0304);
        Encoding::ELF32_LE.write_u16(&mut out, 0x0506);
        assert_eq!(out, [1, 2, 3, 4, 6, 5]);
        assert_eq!(Encoding::ELF64_BE.read_u32(&out, 0).unwrap(), 0x0102_0304);
        assert_eq!(Encoding::ELF64_LE.read_u16(&out, 4).unwrap(), 0x0506);
        assert!(Encoding::ELF64_LE.read_u16(&out, 5).is_err());
        assert!(Encoding::ELF64_LE.read_u16(&out, usize::MAX).is_err());
    }

    #[test]
    fn class_sized_values_follow_the_class() {
        let mut out = Vec::new();
        Encoding::ELF32_LE
            .write_addr(&mut out, 0xffff_ffff)
            .unwrap();
        assert_eq!(out.len(), 4);
        assert!(matches!(
            Encoding::ELF32_LE.write_addr(&mut out, 0x1_0000_0000),
            Err(Error {
                kind: ErrorKind::ValueOutOfRange(_),
                ..
            })
        ));
        Encoding::ELF64_LE.write_signed_addr(&mut out, -2).unwrap();
        assert_eq!(out.len(), 12);
        assert_eq!(Encoding::ELF64_LE.read_signed_addr(&out, 4).unwrap(), -2);
        assert_eq!(Encoding::ELF32_LE.read_signed_addr(&out, 4).unwrap(), -2);

        let mut patch = vec![0u8; 8];
        Encoding::ELF64_BE.put_addr(&mut patch, 0, 0x1122).unwrap();
        assert_eq!(patch, [0, 0, 0, 0, 0, 0, 0x11, 0x22]);
        assert!(Encoding::ELF32_BE.put_addr(&mut patch, 6, 1).is_err());
    }

    #[test]
    fn byte_reader_stops_at_the_end() {
        let data = [1, 0, 0, 0, 2];
        let mut reader = ByteReader::new(&data, Encoding::ELF32_LE);
        assert_eq!(reader.addr().unwrap(), 1);
        assert_eq!(reader.remaining(), 1);
        assert!(reader.u16().is_err());
        assert_eq!(reader.position(), 4);
        assert_eq!(reader.u8().unwrap(), 2);
    }
}
