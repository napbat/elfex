//! Parse an [`ElfImage`] from a raw file or a loader-mapped image.

use super::{ElfImage, Segment, zeroed};
use crate::elf::validate::RangeIndex;
use crate::elf::{ElfHeaders, MissingSegmentData, ParseOptions, SourceLayout};
use crate::prelude::*;
use crate::program::ProgramHeader;
use crate::reader::{ReadAt, SliceReader};
use crate::{Error, Result};

#[cfg(feature = "std")]
use crate::reader::FileReader;
#[cfg(feature = "std")]
use std::path::Path;

/// The page size for reads of a source that cannot read some ranges.
///
/// If a segment read fails, the parser reads the segment again page by page. Then one page
/// that it cannot read does not make the full segment unreadable.
const PAGE_SIZE: u64 = 4096;

/// The maximum quantity of segment data that the parser reads from a source with a known
/// size, as a multiple of the source size.
///
/// Segments can share source bytes, but each segment owns a copy. This limit keeps the memory
/// use in proportion to the source.
const SEGMENT_DATA_LIMIT: u64 = 16;

/// The maximum quantity of segment data that the parser reads from a source with an unknown
/// size: 4 GiB, or the address space limit on a platform with a smaller `usize`.
///
/// The parser reads such a source in chunks of [`UNSIZED_CHUNK`] bytes, and stops at the end
/// of the source. This limit stops a source that supplies data at all offsets.
pub(crate) const MAX_UNSIZED_SEGMENT_BYTES: u64 = if usize::BITS < u64::BITS {
    usize::MAX as u64
} else {
    1 << 32
};

/// The size of one segment read from a source with an unknown size.
///
/// The parser does not allocate the full segment before it reads the data, because a bad
/// `p_filesz` or `p_memsz` can be very large.
const UNSIZED_CHUNK: u64 = 64 * 1024;

/// A range of segment bytes to read from the source.
#[derive(Debug, Clone, Copy)]
struct SegmentRead {
    /// The offset of the range from the base offset of the source.
    offset: u64,
    /// The number of bytes to read.
    len: u64,
    /// The number of bytes at the start of the range that the source must supply. The source
    /// can end before the other bytes.
    required: u64,
}

/// The source of the segment data and the parse options.
struct SegmentSource<'r, R> {
    /// The source.
    reader: &'r R,
    /// The offset of the ELF header in the source.
    base_offset: u64,
    /// The parse options.
    options: ParseOptions,
    /// The number of source bytes after the base offset, if the source size is known.
    source_size: Option<u64>,
    /// The number of segment bytes that the parser can still read.
    budget: u64,
}

impl ElfImage {
    /// Parse a raw ELF file in a byte slice.
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from_with_options`].
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_with_options(data, ParseOptions::file())
    }

    /// Parse a loader-mapped ELF image in a byte slice. Byte 0 of `data` is the image origin.
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from_with_options`].
    pub fn parse_mapped(data: &[u8]) -> Result<Self> {
        Self::parse_with_options(data, ParseOptions::mapped())
    }

    /// Parse a loader-mapped ELF image in a byte slice, and keep the runtime address of the
    /// image origin.
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from_with_options`].
    pub fn parse_mapped_at(data: &[u8], runtime_base: u64) -> Result<Self> {
        Self::parse_with_options(data, ParseOptions::mapped().runtime_base(runtime_base))
    }

    /// Parse an ELF image in a byte slice with explicit [`ParseOptions`].
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from_with_options`].
    pub fn parse_with_options(data: &[u8], options: ParseOptions) -> Result<Self> {
        Self::read_from_with_options(&SliceReader::new(data), 0, options)
    }

    /// Read an ELF image from a [`ReadAt`] source with an explicit layout.
    ///
    /// `base_offset` is the offset of the ELF header in the source. The parser rejects
    /// segment bytes that it cannot read.
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from_with_options`].
    pub fn read_from<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        layout: SourceLayout,
    ) -> Result<Self> {
        let options = ParseOptions {
            layout,
            missing_segment_data: MissingSegmentData::Error,
            runtime_base: None,
        };
        Self::read_from_with_options(reader, base_offset, options)
    }

    /// Read a loader-mapped ELF image from a [`ReadAt`] source, and keep the runtime address
    /// of the image origin.
    ///
    /// `source_offset` is the offset of the image origin in the source. For a
    /// [`BaseAddressReader`](crate::BaseAddressReader) at the image origin, use 0. A reader
    /// for a full remote process can use the runtime address as `source_offset`.
    ///
    /// # Errors
    ///
    /// Return an error for any condition listed on [`Self::read_from_with_options`].
    pub fn read_mapped_from<R: ReadAt>(
        reader: &R,
        source_offset: u64,
        runtime_base: u64,
    ) -> Result<Self> {
        Self::read_from_with_options(
            reader,
            source_offset,
            ParseOptions::mapped().runtime_base(runtime_base),
        )
    }

    /// Read an ELF image from a [`ReadAt`] source with explicit [`ParseOptions`].
    ///
    /// `base_offset` is the offset of the ELF header in the source. The parser reads the
    /// segment data as [`Segment`] describes:
    ///
    /// - In the file layout, segment data is at `base_offset` plus `p_offset`. As the Linux
    ///   loader does, the parser rejects a file that ends inside the file range of a segment.
    /// - In the mapped layout, segment data is at `base_offset` plus `p_vaddr` minus the image
    ///   origin. The source must supply the first `p_filesz` bytes. The source can end
    ///   before `p_memsz` bytes.
    ///
    /// With [`MissingSegmentData::Zero`], the parser fills the bytes that it cannot read with
    /// zeros. It reads a segment page by page (4096 bytes) after a failed read, so that one
    /// missing page does not fill the full segment with zeros.
    ///
    /// If the source size is unknown, the parser reads each segment in chunks of 64 KiB, and
    /// allocates memory only for the chunks that it reads or fills with zeros. All segment
    /// data together must not be larger than 4 GiB (on a 32-bit platform, the address space
    /// limit).
    ///
    /// # Errors
    ///
    /// - Return an error from [`ElfHeaders::read_from`] for bad headers.
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if a source with
    ///   a known size ends inside the required bytes of a segment, and the options use
    ///   [`MissingSegmentData::Error`].
    /// - Return [`ErrorKind::InvalidSegment`](crate::ErrorKind::InvalidSegment) if a segment in
    ///   the file layout is larger than a source with a known size, if all segment data
    ///   together is larger than 16 times the source size, if all segment data from a source
    ///   with an unknown size is larger than 4 GiB, if an offset overflows, or if the image
    ///   origin of a mapped image is undefined.
    /// - Return the error of the reader if a read of required bytes fails, and the options
    ///   use [`MissingSegmentData::Error`].
    /// - Return a generic error if an allocation fails.
    pub fn read_from_with_options<R: ReadAt>(
        reader: &R,
        base_offset: u64,
        options: ParseOptions,
    ) -> Result<Self> {
        let headers = ElfHeaders::read_from(reader, base_offset, options.layout)?;
        let source_size = reader.size().map(|size| size.saturating_sub(base_offset));
        let mut source = SegmentSource {
            reader,
            base_offset,
            options,
            source_size,
            budget: source_size.map_or(MAX_UNSIZED_SEGMENT_BYTES, |size| {
                size.saturating_mul(SEGMENT_DATA_LIMIT)
            }),
        };
        let planner = ReadPlanner::new(&headers, options.layout);
        let mut segments = Vec::with_capacity(headers.program_headers.len());
        for header in &headers.program_headers {
            let data = match planner.plan(header)? {
                Some(request) => source.read(request)?,
                None => Vec::new(),
            };
            segments.push(Segment {
                header: *header,
                data,
            });
        }
        Ok(Self {
            header: headers.header,
            segments,
            source_layout: options.layout,
            runtime_base: options.runtime_base,
        })
    }

    /// Parse a raw ELF file on disk.
    ///
    /// # Errors
    ///
    /// Return an I/O error if the file does not open. Return an error for any condition listed
    /// on [`Self::read_from_with_options`].
    #[cfg(feature = "std")]
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let reader = FileReader::open(path)?;
        Self::read_from(&reader, 0, SourceLayout::File)
    }

    /// Read all bytes of a stream, and parse them as a raw ELF file.
    ///
    /// # Errors
    ///
    /// Return an I/O error if the stream read fails. Return an error for any condition listed
    /// on [`Self::read_from_with_options`].
    pub fn from_stream<R: nostdio::Read>(stream: &mut R) -> Result<Self> {
        let mut data = Vec::new();
        stream.read_to_end(&mut data)?;
        Self::parse(&data)
    }
}

/// Find the source range of the data of each segment.
struct ReadPlanner {
    /// The layout of the source.
    layout: SourceLayout,
    /// The image origin, for the mapped layout.
    origin: Option<u64>,
    /// The file ranges of the `PT_LOAD` segments, for the file layout.
    loaded: RangeIndex,
}

impl ReadPlanner {
    /// Make a planner for the segments of `headers`.
    fn new(headers: &ElfHeaders, layout: SourceLayout) -> Self {
        let loaded = match layout {
            SourceLayout::File => RangeIndex::load_file_ranges(&headers.program_headers),
            SourceLayout::Mapped => RangeIndex::default(),
        };
        Self {
            layout,
            origin: headers.image_origin(),
            loaded,
        }
    }

    /// Return the source range of the data of `segment`, or `None` if the segment has no own
    /// data.
    fn plan(&self, segment: &ProgramHeader) -> Result<Option<SegmentRead>> {
        match self.layout {
            SourceLayout::File => Ok(self.plan_file(segment)),
            SourceLayout::Mapped => self.plan_mapped(segment),
        }
    }

    /// Return the file range of `segment` in a raw file.
    fn plan_file(&self, segment: &ProgramHeader) -> Option<SegmentRead> {
        if segment.filesz == 0 {
            return None;
        }
        if !segment.is_load()
            && segment
                .file_range()
                .is_some_and(|range| self.loaded.contains(0, range.start, range.end))
        {
            return None;
        }
        Some(SegmentRead {
            offset: segment.offset,
            len: segment.filesz,
            required: segment.filesz,
        })
    }

    /// Return the memory range of a `PT_LOAD` segment in a loader-mapped image.
    fn plan_mapped(&self, segment: &ProgramHeader) -> Result<Option<SegmentRead>> {
        if !segment.is_load() || segment.memsz == 0 {
            return Ok(None);
        }
        let offset = self
            .origin
            .and_then(|origin| segment.vaddr.checked_sub(origin))
            .ok_or_else(|| {
                Error::invalid_segment("the image origin of the mapped image is undefined")
                    .at_address(segment.vaddr)
                    .in_structure("PT_LOAD")
            })?;
        Ok(Some(SegmentRead {
            offset,
            len: segment.memsz,
            required: segment.filesz.min(segment.memsz),
        }))
    }
}

impl<R: ReadAt> SegmentSource<'_, R> {
    /// Read the bytes of `request`.
    fn read(&mut self, request: SegmentRead) -> Result<Vec<u8>> {
        let absolute = self
            .base_offset
            .checked_add(request.offset)
            .ok_or_else(|| {
                Error::invalid_segment("the segment offset overflows").at_offset(request.offset)
            })?;
        let Some(source_size) = self.source_size else {
            return self.read_unsized(request, absolute);
        };
        let zero = self.options.missing_segment_data == MissingSegmentData::Zero;
        let readable = source_size.saturating_sub(request.offset).min(request.len);
        if readable < request.required {
            if !zero {
                return Err(Error::invalid_segment("the source ends inside the segment")
                    .at_offset(request.offset)
                    .in_structure("segment data"));
            }
            if self.options.layout == SourceLayout::File && request.len > source_size {
                return Err(
                    Error::invalid_segment("the segment is larger than the source")
                        .at_offset(request.offset)
                        .in_structure("segment data"),
                );
            }
        }
        let total = readable.max(request.required);
        self.charge(total, request.offset)?;
        let total = to_usize(total, request.offset)?;
        let readable = to_usize(readable, request.offset)?;
        let required = to_usize(request.required, request.offset)?;
        let mut data = zeroed(total)?;
        let Some(buffer) = data.get_mut(..readable) else {
            return Err(too_large(request.offset));
        };
        match self.reader.read_exact_at(absolute, buffer) {
            Ok(()) => {}
            Err(error) if !zero && readable <= required => {
                return Err(error.at_offset(absolute).in_structure("segment data"));
            }
            Err(_) => {
                let kept = self.read_pages(absolute, buffer, required)?;
                if kept < readable {
                    data.truncate(kept);
                }
            }
        }
        Ok(data)
    }

    /// Read the bytes of `request` from a source with an unknown size, in chunks of
    /// [`UNSIZED_CHUNK`] bytes.
    ///
    /// The data grows only by the chunks that the parser reads, or fills with zeros. The
    /// function stops at the first page that it cannot read after the required bytes.
    fn read_unsized(&mut self, request: SegmentRead, absolute: u64) -> Result<Vec<u8>> {
        let zero = self.options.missing_segment_data == MissingSegmentData::Zero;
        let mut data = Vec::new();
        let mut position = 0u64;
        while position < request.len {
            let len = (request.len - position).min(UNSIZED_CHUNK);
            let offset = absolute.checked_add(position).ok_or_else(|| {
                Error::invalid_segment("the segment offset overflows").at_offset(request.offset)
            })?;
            self.charge(len, request.offset)?;
            let required = request.required.saturating_sub(position).min(len);
            let start = data.len();
            let chunk = to_usize(len, request.offset)?;
            data.try_reserve_exact(chunk)
                .map_err(|_| Error::generic("the segment data is too large to allocate"))?;
            data.resize(start.saturating_add(chunk), 0);
            let Some(buffer) = data.get_mut(start..) else {
                return Err(too_large(request.offset));
            };
            let kept = match self.reader.read_exact_at(offset, buffer) {
                Ok(()) => chunk,
                Err(error) if !zero && required == len => {
                    return Err(error.at_offset(offset).in_structure("segment data"));
                }
                Err(_) => self.read_pages(offset, buffer, to_usize(required, request.offset)?)?,
            };
            if kept < chunk {
                data.truncate(start.saturating_add(kept));
                let unused = u64::try_from(chunk.saturating_sub(kept)).unwrap_or(len);
                self.budget = self.budget.saturating_add(unused);
                break;
            }
            position = position.saturating_add(len);
        }
        Ok(data)
    }

    /// Read `buffer` page by page after a failed read, and return the number of bytes at the
    /// start of `buffer` that the segment keeps.
    ///
    /// In a page that the parser cannot read, it keeps the bytes before the end of the source
    /// or the failed read. If these bytes do not contain all the `required` bytes, the page is
    /// an error, or the parser fills the other bytes of the page with zeros with
    /// [`MissingSegmentData::Zero`]. Otherwise, the segment ends after these bytes.
    fn read_pages(&self, absolute: u64, buffer: &mut [u8], required: usize) -> Result<usize> {
        let zero = self.options.missing_segment_data == MissingSegmentData::Zero;
        let readable = buffer.len();
        let mut position = 0usize;
        while position < readable {
            let offset = u64::try_from(position)
                .ok()
                .and_then(|position| absolute.checked_add(position))
                .ok_or_else(|| {
                    Error::invalid_segment("the segment offset overflows").at_offset(absolute)
                })?;
            let to_boundary = PAGE_SIZE - offset % PAGE_SIZE;
            let chunk = usize::try_from(to_boundary)
                .map_or(readable - position, |size| size.min(readable - position));
            let end = position + chunk;
            let Some(page) = buffer.get_mut(position..end) else {
                break;
            };
            if let Err(error) = self.reader.read_exact_at(offset, page) {
                let kept = position.saturating_add(self.read_prefix(offset, page));
                if kept >= required {
                    return Ok(kept);
                }
                if !zero {
                    return Err(error.at_offset(offset).in_structure("segment data"));
                }
                if let Some(rest) = buffer.get_mut(kept..end) {
                    rest.fill(0);
                }
            }
            position = end;
        }
        Ok(readable)
    }

    /// Read the start of `buffer` until the source ends or a read fails, and return the
    /// number of bytes that the parser read.
    fn read_prefix(&self, offset: u64, buffer: &mut [u8]) -> usize {
        let mut total = 0usize;
        while let Some(rest) = buffer.get_mut(total..).filter(|rest| !rest.is_empty()) {
            let Some(at) = u64::try_from(total)
                .ok()
                .and_then(|total| offset.checked_add(total))
            else {
                break;
            };
            match self.reader.read_at(at, rest) {
                Ok(count) if count > 0 && count <= rest.len() => total += count,
                _ => break,
            }
        }
        total
    }

    /// Subtract `len` bytes from the read budget.
    fn charge(&mut self, len: u64, offset: u64) -> Result<()> {
        self.budget = self.budget.checked_sub(len).ok_or_else(|| {
            let message = if self.source_size.is_some() {
                "the segment data is too large for the source size"
            } else {
                "the segment data from a source with an unknown size is too large"
            };
            Error::invalid_segment(message)
                .at_offset(offset)
                .in_structure("segment data")
        })?;
        Ok(())
    }
}

/// Return the error for a segment that is too large for this platform.
fn too_large(offset: u64) -> Error {
    Error::invalid_segment("the segment is too large for this platform").at_offset(offset)
}

/// Convert a segment size to `usize`.
fn to_usize(value: u64, offset: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| too_large(offset))
}
