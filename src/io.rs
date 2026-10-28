//! Sequential streams and positional image readers.
//!
//! [`nostdio`] supplies the sequential [`Read`], [`Write`] and [`Seek`] traits, which also
//! work in `no_std` builds. The Elfex [`ReadAt`] trait stays positional. Thus you can query
//! mapped or remote images without a shared stream cursor.
//!
//! The positional readers are [`SliceReader`], [`VecReader`], [`SeekReader`] (for a
//! `Read + Seek` stream) and [`BaseAddressReader`] (for a module in the current process).
//! With the `std` feature, `FileReader` reads a file on disk.

pub use nostdio::*;

#[cfg(feature = "std")]
pub use crate::reader::FileReader;
pub use crate::reader::{BaseAddressReader, ReadAt, SeekReader, SliceReader, VecReader};
