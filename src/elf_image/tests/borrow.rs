//! Tests for the segment data that borrows a byte slice.

use super::*;

/// Return `true` if all segments with data borrow it.
fn all_borrowed(image: &ElfImage<'_>) -> bool {
    image
        .segments
        .iter()
        .all(|segment| segment.data.is_empty() || matches!(segment.data, Cow::Borrowed(_)))
}

#[test]
fn slice_parse_borrows_and_a_write_copies() {
    let bytes = sample(Encoding::ELF64_LE);
    let mut image = ElfImage::parse(&bytes).unwrap();
    assert!(all_borrowed(&image));
    let load = image.segments.iter().position(Segment::is_load).unwrap();
    let vaddr = image.segments[load].header.vaddr;
    let before = image.read_vaddr(vaddr, 4).unwrap();
    image.write_vaddr(vaddr, &[0xaa]).unwrap();
    assert!(matches!(image.segments[load].data, Cow::Owned(_)));
    assert_eq!(image.read_vaddr(vaddr, 4).unwrap()[..1], [0xaa]);
    assert_eq!(image.read_vaddr(vaddr, 4).unwrap()[1..], before[1..]);

    // A `ReadAt` source gives owned data with the same content.
    let parsed = ElfImage::parse(&bytes).unwrap();
    let read = ElfImage::read_from(&SliceReader::new(&bytes), 0, SourceLayout::File).unwrap();
    assert!(
        read.segments
            .iter()
            .all(|segment| matches!(segment.data, Cow::Owned(_)))
    );
    assert_eq!(read, parsed);
    assert_eq!(parsed.clone().into_owned(), read);
}

#[test]
fn slice_parse_accepts_the_inputs_of_a_slice_reader() {
    let file = sample(Encoding::ELF32_BE);
    let mapped = ElfImage::parse(&sample(Encoding::ELF64_LE))
        .unwrap()
        .to_mapped_image()
        .unwrap();
    let options = [
        ParseOptions::file(),
        ParseOptions::file().allow_missing_segment_data(),
        ParseOptions::mapped(),
        ParseOptions::mapped().allow_missing_segment_data(),
    ];
    for (index, options) in options.into_iter().enumerate() {
        let bytes = if index < 2 { &file } else { &mapped };
        for len in (0..=bytes.len()).step_by(0x40) {
            let data = &bytes[..len];
            let parsed = ElfImage::parse_with_options(data, options);
            let read = ElfImage::read_from_with_options(&SliceReader::new(data), 0, options);
            match (parsed, read) {
                (Ok(parsed), Ok(read)) => assert_eq!(parsed, read, "{index} {len:#x}"),
                (Err(parsed), Err(read)) => {
                    assert_eq!(parsed.to_string(), read.to_string(), "{index} {len:#x}");
                }
                (parsed, read) => panic!("{index} {len:#x}: {parsed:?} and {read:?}"),
            }
        }
    }
}

#[test]
fn zero_bytes_after_the_slice_make_a_copy() {
    let bytes = sample(Encoding::ELF64_LE);
    let load = ElfImage::parse(&bytes)
        .unwrap()
        .segments
        .iter()
        .rposition(Segment::is_load)
        .unwrap();
    // Cut the file inside the last `PT_LOAD` segment.
    let header = ElfImage::parse(&bytes).unwrap().segments[load].header;
    let end = usize::try_from(header.offset + header.filesz).unwrap();
    let data = &bytes[..end - 1];
    assert!(ElfImage::parse(data).is_err());
    let options = ParseOptions::file().allow_missing_segment_data();
    let image = ElfImage::parse_with_options(data, options).unwrap();
    let segment = &image.segments[load];
    assert!(matches!(segment.data, Cow::Owned(_)));
    assert_eq!(segment.data.len(), usize::try_from(header.filesz).unwrap());
    assert_eq!(segment.data.last(), Some(&0));
}
