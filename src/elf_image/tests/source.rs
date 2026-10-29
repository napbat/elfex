//! Tests for the segment reads from sources with unreadable ranges, read budgets and offsets
//! near the end of the address space.

use super::*;

/// The offset of `p_filesz` in an ELF64 program header.
const FILESZ: usize = 32;
/// The offset of `p_memsz` in an ELF64 program header.
const MEMSZ: usize = 40;

/// Return the file offset of program header `index` in the ELF64 sample.
fn program_header(index: usize) -> usize {
    64 + index * 56
}

/// Return the mapped ELF64 sample.
fn mapped_sample() -> Vec<u8> {
    ElfImage::parse(&sample(Encoding::ELF64_LE))
        .unwrap()
        .to_mapped_image()
        .unwrap()
}

/// Set `p_filesz` and `p_memsz` of program header `index` in the ELF64 `bytes` to `size`.
fn set_sizes(bytes: &mut [u8], index: usize, size: u64) {
    for field in [FILESZ, MEMSZ] {
        Encoding::ELF64_LE
            .put_u64(bytes, program_header(index) + field, size)
            .unwrap();
    }
}

/// Assert that `error` is an `InvalidSegment` error at `offset`.
fn assert_segment_error(error: &Error, offset: u64) {
    assert!(
        matches!(error.kind(), ErrorKind::InvalidSegment(_)),
        "{error:?}"
    );
    let context = error.context().unwrap();
    assert_eq!(context.file_offset, Some(offset), "{error:?}");
}

#[test]
fn sized_file_source_with_failed_read() {
    let bytes = sample(Encoding::ELF64_LE);
    let reader = TestReader::sized(&bytes).with_hole(0x210..0x220);
    let error = ElfImage::read_from(&reader, 0, SourceLayout::File).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Generic(_)), "{error:?}");
    let context = error.context().unwrap();
    assert_eq!(context.file_offset, Some(0x200));
    assert_eq!(context.structure.as_deref(), Some("segment data"));

    // The parser keeps the bytes before the hole and fills the rest of the page with zeros.
    let options = ParseOptions::file().allow_missing_segment_data();
    let image = ElfImage::read_from_with_options(&reader, 0, options).unwrap();
    let data = &image.segments[3].data;
    assert_eq!(data.len(), 0x40);
    assert_eq!(data[..0x10], bytes[0x200..0x210]);
    assert!(all_zero(&data[0x10..]));
    assert_eq!(*image.segments[2].data, bytes[..0x200]);
}

#[test]
fn sized_mapped_source_with_failed_read() {
    let mapped = mapped_sample();
    let options = ParseOptions::mapped().allow_missing_segment_data();
    // The hole is after `p_filesz`: the segment ends at the hole.
    let reader = TestReader::sized(&mapped).with_hole(0x1300..0x1310);
    for options in [ParseOptions::mapped(), options] {
        let image = ElfImage::read_from_with_options(&reader, 0, options).unwrap();
        assert_eq!(*image.segments[3].data, mapped[0x1200..0x1300]);
    }

    // The hole is before `p_filesz`.
    let reader = TestReader::sized(&mapped).with_hole(0x1210..0x1220);
    let error = ElfImage::read_from_with_options(&reader, 0, ParseOptions::mapped()).unwrap_err();
    assert!(matches!(error.kind(), ErrorKind::Generic(_)), "{error:?}");
    assert_eq!(error.context().unwrap().file_offset, Some(0x1200));
    let image = ElfImage::read_from_with_options(&reader, 0, options).unwrap();
    let data = &image.segments[3].data;
    assert_eq!(data.len(), 0x200);
    assert_eq!(data[..0x10], mapped[0x1200..0x1210]);
    assert!(all_zero(&data[0x10..]));
}

#[test]
fn sized_source_limits_segment_data() {
    let mut mapped = mapped_sample();
    // The second `PT_LOAD` segment needs 1 MiB: more than 16 times the source size.
    set_sizes(&mut mapped, 3, 0x10_0000);
    let error = read_sized(&mapped, ParseOptions::mapped()).unwrap_err();
    assert_segment_error(&error, 0x1200);

    let options = ParseOptions::mapped().allow_missing_segment_data();
    let error = read_sized(&mapped, options).unwrap_err();
    assert_segment_error(&error, 0x1200);
    let context = error.context().unwrap();
    assert_eq!(context.structure.as_deref(), Some("segment data"));

    // 1 MiB fits in the budget of a source of 128 KiB.
    mapped.resize(0x2_0000, 0);
    let image = read_sized(&mapped, options).unwrap();
    assert_eq!(image.segments[3].data.len(), 0x10_0000);
    assert_eq!(image.segments[3].data[..0x40], mapped[0x1200..0x1240]);
}

#[test]
fn segment_offset_overflow_is_invalid_segment() {
    let bytes = sample_with(Encoding::ELF64_LE, |_, segments| {
        segments[3].offset = 0x2000;
        segments[3].vaddr = BASE + 0x2000;
    });
    let base = u64::MAX - 0xfff;
    let reader = TestReader::unknown_size(&bytes).at(base);
    let error = ElfImage::read_from(&reader, base, SourceLayout::File).unwrap_err();
    assert_segment_error(&error, 0x2000);
}

#[test]
fn unsized_read_past_the_end_of_the_address_space() {
    let options = ParseOptions::mapped().allow_missing_segment_data();
    let mut long = mapped_sample();
    set_sizes(&mut long, 2, 0x2_0000);
    let mut short = mapped_sample();
    set_sizes(&mut short, 2, 0x1_0000);

    // The second chunk of 64 KiB starts at 2^64.
    let base = u64::MAX - 0xffff;
    let reader = TestReader::unknown_size(&long).at(base);
    let error = ElfImage::read_from_with_options(&reader, base, options).unwrap_err();
    assert_segment_error(&error, 0);

    // A page in the first chunk starts at 2^64.
    let base = u64::MAX - 0x7fff;
    let reader = TestReader::unknown_size(&short).at(base);
    let error = ElfImage::read_from_with_options(&reader, base, options).unwrap_err();
    assert_segment_error(&error, base);

    // The full segment ends at 2^64.
    let base = u64::MAX - 0xffff;
    let reader = TestReader::unknown_size(&short).at(base);
    let image = ElfImage::read_from_with_options(&reader, base, options).unwrap();
    let segment = &image.segments[2].data;
    assert_eq!(segment.len(), 0x1_0000);
    assert_eq!(segment[..short.len()], short[..]);
    assert!(all_zero(&segment[short.len()..]));
}
