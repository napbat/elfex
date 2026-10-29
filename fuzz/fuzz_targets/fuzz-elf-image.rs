//! Fuzz target that parses arbitrary bytes as an ELF image in the file layout and in the mapped
//! layout, and then runs the build paths, the validation and the dynamic symbol accessor on
//! each result.

#![no_main]

use elfex::ElfImage;
use libfuzzer_sys::fuzz_target;

/// The largest mapped image or raw file that the target makes, in bytes.
///
/// A mapped image needs the full memory range of the `PT_LOAD` segments, and libFuzzer stops
/// at 2 GiB of memory.
const MAX_OUTPUT_SIZE: u64 = 64 << 20;

fuzz_target!(|data: &[u8]| {
    if let Ok(image) = ElfImage::parse(data) {
        exercise(&image);
    }
    if let Ok(image) = ElfImage::parse_mapped(data) {
        exercise(&image);
    }
});

/// Run the build paths, the validation and the symbol and note accessors on `image`.
fn exercise(image: &ElfImage<'_>) {
    let _ = image.validate();
    let _ = image.dynamic_symbol_list();
    let _ = image.core_file_mappings();
    let _ = image.auxv();
    let small = image
        .headers()
        .mapped_size()
        .is_some_and(|size| size <= MAX_OUTPUT_SIZE);
    if small
        && let Ok(mapped) = image.to_mapped_image()
        && let Ok(mapped_image) = ElfImage::parse_mapped(&mapped)
    {
        let _ = mapped_image.validate();
        let _ = mapped_image.dynamic_symbol_list();
    }
    if dump_size(image).is_some_and(|size| size <= MAX_OUTPUT_SIZE)
        && let Ok(rebuilt) = image.try_build()
    {
        let _ = ElfImage::parse(&rebuilt);
    }
}

/// Return an upper limit of the size of the raw file that `ElfImage::try_build` makes, or
/// `None` if an end overflows.
///
/// The file ends at the end of the last segment file range or of the program header table.
fn dump_size(image: &ElfImage<'_>) -> Option<u64> {
    let count = u64::try_from(image.segments.len()).ok()?;
    let table_size = count.checked_mul(u64::from(image.header.phentsize.max(56)))?;
    let table_end = image.header.phoff.checked_add(table_size)?;
    image
        .program_headers()
        .map(|header| header.offset.checked_add(header.filesz))
        .try_fold(table_end, |size, end| Some(size.max(end?)))
}
