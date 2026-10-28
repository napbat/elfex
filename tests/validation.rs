//! Integration tests for the validation of damaged files and for robustness against
//! malformed input.

use elfex::program::PF_X;
use elfex::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use elfex::{
    BuilderSection, ElfBuilder, ElfFile, ElfHeaders, ElfImage, Encoding, ParseOptions,
    ProgramHeader, SectionHeader, SegmentType, ValidationCode, ValidationResult,
};

/// The four combinations of class and byte order.
const ENCODINGS: [Encoding; 4] = [
    Encoding::ELF32_LE,
    Encoding::ELF32_BE,
    Encoding::ELF64_LE,
    Encoding::ELF64_BE,
];

/// The largest mapped image that the robustness tests make, in bytes.
const MAX_MAPPED_SIZE: u64 = 1 << 20;

/// Build an executable with an interpreter, code, data and a comment, and return the file.
fn sample(encoding: Encoding) -> ElfFile {
    ElfBuilder::new(encoding)
        .interpreter("/lib/ld-elfex.so.1")
        .add_section(BuilderSection::progbits(
            ".rodata",
            SHF_ALLOC,
            b"constant\0".to_vec(),
        ))
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0xc3; 0x20],
        ))
        .add_section(BuilderSection::progbits(
            ".data",
            SHF_ALLOC | SHF_WRITE,
            vec![7; 0x10],
        ))
        .add_section(BuilderSection::nobits(".bss", SHF_ALLOC | SHF_WRITE, 0x100))
        .add_section(BuilderSection::progbits(
            ".comment",
            0,
            b"validation\0".to_vec(),
        ))
        .entry_in_section(".text", 0)
        .try_build()
        .expect("the sample file should build")
}

/// Apply `damage` to the sample file, build it, parse the output and validate it.
fn damaged(encoding: Encoding, damage: impl FnOnce(&mut ElfFile)) -> ValidationResult {
    let mut file = sample(encoding);
    damage(&mut file);
    let bytes = file.try_build().expect("the damaged file should build");
    let parsed = ElfFile::parse(&bytes).expect("the damaged file should parse");
    assert_eq!(parsed.validate().issues.len(), file.validate().issues.len());
    parsed.validate()
}

/// Return the program header indices of the `PT_LOAD` segments of `file`.
fn load_indices(file: &ElfFile) -> Vec<usize> {
    file.program_headers()
        .iter()
        .enumerate()
        .filter(|(_, header)| header.segment_type == SegmentType::LOAD)
        .map(|(index, _)| index)
        .collect()
}

/// Return the program header of the executable `PT_LOAD` segment.
fn code_segment(file: &mut ElfFile) -> &mut ProgramHeader {
    file.program_headers_mut()
        .iter_mut()
        .find(|header| header.segment_type == SegmentType::LOAD && header.flags & PF_X != 0)
        .expect("the file has a code segment")
}

/// Return the section header `name`.
fn section<'a>(file: &'a mut ElfFile, name: &str) -> &'a mut SectionHeader {
    let index = file
        .section_by_name(name)
        .unwrap_or_else(|| panic!("the file has {name}"))
        .index;
    &mut file.section_headers_mut()[index]
}

/// Check that `result` has the error `code`.
fn assert_error(result: &ValidationResult, code: ValidationCode) {
    assert!(
        result.errors().any(|issue| issue.code == code),
        "expected {code}, got {:?}",
        result.issues
    );
}

#[test]
fn builder_output_has_no_errors() {
    for encoding in ENCODINGS {
        let file = sample(encoding);
        let result = file.validate();
        assert!(!result.has_errors(), "{:?}", result.issues);
        let image = ElfImage::parse(file.as_bytes()).expect("the image should parse");
        assert!(!image.validate().has_errors());
    }
}

#[test]
fn reports_overlapping_load_segments() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let loads = load_indices(file);
            let first = &mut file.program_headers_mut()[loads[0]];
            first.memsz += 0x2000;
        });
        assert_error(&result, ValidationCode::OverlappingSegments);
    }
}

#[test]
fn reports_an_entry_point_outside_the_code() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let rodata = file
                .section_by_name(".rodata")
                .expect("the file has .rodata")
                .header
                .addr;
            file.set_entry_point(rodata);
        });
        assert_error(&result, ValidationCode::EntryPointOutOfBounds);
        let result = damaged(encoding, |file| file.set_entry_point(0x10));
        assert_error(&result, ValidationCode::EntryPointOutOfBounds);
    }
}

#[test]
fn reports_misaligned_segments() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let code = code_segment(file);
            code.vaddr += 1;
            code.paddr += 1;
        });
        assert_error(&result, ValidationCode::MisalignedSegment);
        let result = damaged(encoding, |file| code_segment(file).align = 0x1800);
        assert_error(&result, ValidationCode::MisalignedSegment);
    }
}

#[test]
fn reports_a_load_segment_with_more_file_bytes_than_memory() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let code = code_segment(file);
            code.memsz = code.filesz - 1;
        });
        assert_error(&result, ValidationCode::SegmentFileSizeTooLarge);
    }
}

#[test]
fn reports_unsorted_load_segments_as_a_warning() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let loads = load_indices(file);
            file.program_headers_mut().swap(loads[0], loads[1]);
        });
        assert!(
            result
                .warnings()
                .any(|issue| issue.code == ValidationCode::UnsortedSegments)
        );
    }
}

#[test]
fn reports_a_section_past_the_end_of_the_file() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let end = u64::try_from(file.len()).expect("the length fits");
            section(file, ".comment").offset = end + 0x100;
        });
        assert_error(&result, ValidationCode::SectionOutOfFile);
    }
}

#[test]
fn reports_a_segment_past_the_end_of_the_file() {
    for encoding in ENCODINGS {
        let mut file = sample(encoding);
        let end = u64::try_from(file.len()).expect("the length fits");
        let note = ProgramHeader {
            segment_type: SegmentType::NOTE,
            flags: 0,
            offset: end - 4,
            vaddr: 0,
            paddr: 0,
            filesz: 0x40,
            memsz: 0,
            align: 4,
        };
        let stack = file
            .program_headers_mut()
            .iter_mut()
            .find(|header| header.segment_type == SegmentType::GNU_STACK)
            .expect("the file has PT_GNU_STACK");
        *stack = note;
        let bytes = file.try_build().expect("the damaged file should build");
        let parsed = ElfFile::parse(&bytes).expect("the damaged file should parse");
        assert_error(&parsed.validate(), ValidationCode::SegmentOutOfFile);
        assert!(ElfImage::parse(&bytes).is_err());
    }
}

#[test]
fn reports_a_bad_section_name_table_index() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let text = file
                .section_by_name(".text")
                .expect("the file has .text")
                .index;
            file.header_mut().shstrndx = u16::try_from(text).expect("the index fits");
        });
        assert_error(&result, ValidationCode::InvalidStringTableIndex);
        let result = damaged(encoding, |file| file.header_mut().shstrndx = 0xfe00);
        assert_error(&result, ValidationCode::InvalidStringTableIndex);
    }
}

#[test]
fn reports_a_duplicate_interpreter_segment() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let interp = *file
                .headers()
                .segment(SegmentType::INTERP)
                .expect("the file has PT_INTERP");
            let stack = file
                .program_headers_mut()
                .iter_mut()
                .find(|header| header.segment_type == SegmentType::GNU_STACK)
                .expect("the file has PT_GNU_STACK");
            *stack = interp;
        });
        assert_error(&result, ValidationCode::DuplicateSegment);
    }
}

#[test]
fn reports_an_interpreter_outside_the_load_segments() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| {
            let interp = file
                .program_headers_mut()
                .iter_mut()
                .find(|header| header.segment_type == SegmentType::INTERP)
                .expect("the file has PT_INTERP");
            interp.vaddr = 0x10;
            interp.paddr = 0x10;
        });
        assert_error(&result, ValidationCode::SegmentNotLoaded);
    }
}

#[test]
fn reports_a_bad_section_link() {
    for encoding in ENCODINGS {
        let result = damaged(encoding, |file| section(file, ".comment").link = 0x7fff);
        assert_error(&result, ValidationCode::InvalidSectionLink);
    }
}

/// Return an upper limit of the size of the raw file that `ElfImage::try_build` makes, or
/// `None` if an end overflows.
fn dump_size(image: &ElfImage) -> Option<u64> {
    let count = u64::try_from(image.segments.len()).ok()?;
    let table_size = count.checked_mul(u64::from(image.header.phentsize.max(56)))?;
    let table_end = image.header.phoff.checked_add(table_size)?;
    image
        .program_headers()
        .map(|header| header.offset.checked_add(header.filesz))
        .try_fold(table_end, |size, end| Some(size.max(end?)))
}

/// Parse `bytes` with each parser, and run the accessors on each result.
///
/// The results can be errors. The function checks that no parser panics, and that the round
/// trip of each `ElfFile` that parses is lossless.
fn parse_everything(bytes: &[u8]) {
    let _ = ElfHeaders::from_slice(bytes);
    let _ = ElfHeaders::from_mapped_slice(bytes);
    if let Ok(file) = ElfFile::parse(bytes) {
        let _ = file.validate();
        for section in file.sections() {
            let _ = file.section_data(section.index);
        }
        for index in 0..file.program_headers().len() {
            let _ = file.segment_data(index);
        }
        assert_eq!(
            file.try_build().ok().as_deref(),
            Some(bytes),
            "the round trip of a parsed file must be lossless"
        );
    }
    for options in [
        ParseOptions::file(),
        ParseOptions::mapped(),
        ParseOptions::mapped().allow_missing_segment_data(),
    ] {
        if let Ok(image) = ElfImage::parse_with_options(bytes, options) {
            let _ = image.validate();
            let _ = image.interpreter();
            if dump_size(&image).is_some_and(|size| size <= MAX_MAPPED_SIZE) {
                let _ = image.try_build();
            }
            let small = image
                .headers()
                .mapped_size()
                .is_some_and(|size| size <= MAX_MAPPED_SIZE);
            if small && let Ok(mapped) = image.to_mapped_image() {
                let _ = ElfImage::parse_mapped(&mapped);
            }
        }
    }
}

#[test]
fn truncated_files_do_not_panic() {
    for encoding in ENCODINGS {
        let bytes = sample(encoding)
            .try_build()
            .expect("the sample should build");
        for len in 0..bytes.len() {
            parse_everything(&bytes[..len]);
        }
    }
}

#[test]
fn damaged_header_bytes_do_not_panic() {
    for encoding in ENCODINGS {
        let file = sample(encoding);
        let bytes = file.try_build().expect("the sample should build");
        let header = file.header();
        let to_usize = |value: u64| usize::try_from(value).expect("the value fits");
        let program_table = to_usize(header.phoff)
            ..to_usize(header.phoff) + usize::from(header.phentsize) * file.program_headers().len();
        let section_table = to_usize(header.shoff)
            ..to_usize(header.shoff) + usize::from(header.shentsize) * file.section_headers().len();
        let offsets = (0..usize::from(header.ehsize))
            .chain(program_table)
            .chain(section_table);
        for offset in offsets {
            for value in [0xff, 0x80] {
                let mut damaged = bytes.clone();
                damaged[offset] = value;
                parse_everything(&damaged);
            }
        }
    }
}
