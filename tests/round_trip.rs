//! Integration tests for lossless round trips and edits of raw ELF files.

use elfex::io::Cursor;
use elfex::program::{PF_R, PF_W};
use elfex::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use elfex::{
    BuilderSection, ElfBuilder, ElfFile, ElfHeaders, ElfImage, Encoding, Endian, Machine,
    NewSection, SectionType, SegmentType,
};

/// The four combinations of class and byte order.
const ENCODINGS: [Encoding; 4] = [
    Encoding::ELF32_LE,
    Encoding::ELF32_BE,
    Encoding::ELF64_LE,
    Encoding::ELF64_BE,
];

/// The interpreter path of the sample files.
const INTERPRETER: &str = "/lib/ld-elfex.so.1";

/// Return a machine that matches the class and the byte order of `encoding`.
fn machine(encoding: Encoding) -> Machine {
    match (encoding.is_64bit(), encoding.endian) {
        (false, Endian::Little) => Machine::I386,
        (false, Endian::Big) => Machine::PPC,
        (true, Endian::Little) => Machine::X86_64,
        (true, Endian::Big) => Machine::PPC64,
    }
}

/// Return a `NT_GNU_BUILD_ID` note (`Elf32_Nhdr` or `Elf64_Nhdr`) with a 20-byte descriptor.
fn build_id_note(encoding: Encoding) -> Vec<u8> {
    let mut note = Vec::new();
    encoding.write_u32(&mut note, 4);
    encoding.write_u32(&mut note, 20);
    encoding.write_u32(&mut note, 3);
    note.extend_from_slice(b"GNU\0");
    note.extend((1..=20).map(|value: u8| value * 3));
    note
}

/// Return a builder for an executable with an interpreter, a note, code, data and `.bss`.
fn sample_builder(encoding: Encoding) -> ElfBuilder {
    ElfBuilder::new(encoding)
        .machine(machine(encoding))
        .interpreter(INTERPRETER)
        .add_section(BuilderSection::note(
            ".note.gnu.build-id",
            build_id_note(encoding),
        ))
        .add_section(BuilderSection::progbits(
            ".rodata",
            SHF_ALLOC,
            b"read-only data\0".to_vec(),
        ))
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            vec![0x90; 0x40],
        ))
        .add_section(BuilderSection::progbits(
            ".data",
            SHF_ALLOC | SHF_WRITE,
            vec![0x5a; 0x30],
        ))
        .add_section(BuilderSection::nobits(
            ".bss",
            SHF_ALLOC | SHF_WRITE,
            0x2000,
        ))
        .add_section(BuilderSection::progbits(
            ".comment",
            0,
            b"elfex round trip\0".to_vec(),
        ))
        .add_segment_for_section(SegmentType::NOTE, ".note.gnu.build-id")
        .entry_in_section(".text", 0x10)
}

/// Build the sample file and return its bytes.
fn sample_bytes(encoding: Encoding) -> Vec<u8> {
    sample_builder(encoding)
        .try_build()
        .expect("the sample file should build")
        .try_build()
        .expect("the sample file should serialize")
}

/// Parse `bytes`, check that the file has no validation errors, and check that the round trip
/// of the parsed file is lossless.
fn reparse(bytes: &[u8]) -> ElfFile<&[u8]> {
    let file = ElfFile::parse(bytes).expect("the edited file should parse");
    let issues = file.validate();
    assert!(
        !issues.has_errors(),
        "validation errors: {:?}",
        issues.issues
    );
    assert_eq!(
        file.try_build().expect("the edited file should build"),
        bytes
    );
    file
}

/// Return the index of the section `name`.
fn section_index<D: AsRef<[u8]>>(file: &ElfFile<D>, name: &str) -> usize {
    file.section_by_name(name)
        .unwrap_or_else(|| panic!("the file should have a {name} section"))
        .index
}

#[test]
fn builder_output_round_trips_for_each_encoding() {
    for encoding in ENCODINGS {
        let built = sample_builder(encoding)
            .try_build()
            .expect("the sample file should build");
        let bytes = built.try_build().expect("the sample file should serialize");
        assert_eq!(bytes, built.as_bytes());

        let file = reparse(&bytes);
        assert_eq!(file, built);
        assert_eq!(file.encoding(), encoding);
        assert_eq!(file.is_64bit(), encoding.is_64bit());
        assert_eq!(file.machine(), machine(encoding));
        let text = file.section_by_name(".text").expect("the file has .text");
        assert_eq!(file.entry_point(), text.header.addr + 0x10);
        assert_eq!(text.data, [0x90; 0x40]);
        assert_eq!(
            file.section_by_name(".comment").map(|section| section.data),
            Some(&b"elfex round trip\0"[..])
        );

        let headers = ElfHeaders::from_slice(&bytes).expect("the headers should parse");
        assert_eq!(&headers, file.headers());

        let image = ElfImage::parse(&bytes).expect("the image should parse");
        assert_eq!(
            image.interpreter().ok().flatten().as_deref(),
            Some(INTERPRETER)
        );
        assert!(!image.validate().has_errors());
    }
}

#[test]
fn round_trip_keeps_bytes_after_the_last_item() {
    for encoding in ENCODINGS {
        let mut bytes = sample_bytes(encoding);
        bytes.extend_from_slice(b"trailing overlay bytes");
        let file = ElfFile::parse(&bytes).expect("the file should parse");
        assert_eq!(file.try_build().expect("the file should build"), bytes);
    }
}

#[test]
fn set_section_data_shrinks_in_place_and_grows_at_the_end() {
    for encoding in ENCODINGS {
        let bytes = sample_bytes(encoding);
        let mut file = ElfFile::from_vec(bytes.clone()).expect("the file should parse");

        let rodata = section_index(&file, ".rodata");
        let rodata_offset = file.section_headers()[rodata].offset;
        file.set_section_data(rodata, b"short\0".to_vec())
            .expect("a smaller SHF_ALLOC section should change in place");
        let larger = vec![0xaa; 0x100];
        assert!(file.set_section_data(rodata, larger).is_err());

        let comment = section_index(&file, ".comment");
        let new_comment = b"a much longer comment than the original comment\0".to_vec();
        file.set_section_data(comment, new_comment.clone())
            .expect("a larger section without SHF_ALLOC should move");

        let built = file.try_build().expect("the edited file should build");
        let edited = reparse(&built);
        let rodata = edited
            .section_by_name(".rodata")
            .expect("the file has .rodata");
        assert_eq!(rodata.header.offset, rodata_offset);
        assert_eq!(rodata.data, b"short\0");
        let comment = edited
            .section_by_name(".comment")
            .expect("the file has .comment");
        assert_eq!(comment.data, new_comment);
        assert!(comment.header.offset >= u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }
}

#[test]
fn add_section_appends_data_and_a_name() {
    for encoding in ENCODINGS {
        let mut file = ElfFile::from_vec(sample_bytes(encoding)).expect("the file should parse");
        let count = file.section_headers().len();
        let index = file
            .add_section(NewSection::new(
                ".elfex.extra",
                SectionType::PROGBITS,
                vec![1, 2, 3, 4, 5],
            ))
            .expect("the section should add");
        assert_eq!(index, count);

        let mut alloc = NewSection::new(".elfex.alloc", SectionType::PROGBITS, vec![0]);
        alloc.flags = SHF_ALLOC;
        assert!(file.add_section(alloc).is_err());

        let built = file.try_build().expect("the edited file should build");
        let edited = reparse(&built);
        assert_eq!(edited.section_headers().len(), count + 1);
        let added = edited
            .section_by_name(".elfex.extra")
            .expect("the file has the new section");
        assert_eq!(added.index, index);
        assert_eq!(added.data, [1, 2, 3, 4, 5]);
        assert_eq!(
            edited
                .section_by_name(".comment")
                .map(|section| section.data),
            Some(&b"elfex round trip\0"[..])
        );
    }
}

#[test]
fn remove_section_renumbers_the_other_sections() {
    for encoding in ENCODINGS {
        let mut file = ElfFile::from_vec(sample_bytes(encoding)).expect("the file should parse");
        let count = file.section_headers().len();
        let names: Vec<String> = file
            .section_names()
            .iter()
            .filter(|name| *name != ".comment")
            .cloned()
            .collect();
        let comment = section_index(&file, ".comment");
        assert!(file.remove_section(0).is_err());
        file.remove_section(comment)
            .expect("the comment section should remove");

        let built = file.try_build().expect("the edited file should build");
        let edited = reparse(&built);
        assert_eq!(edited.section_headers().len(), count - 1);
        assert_eq!(edited.section_names(), names);
        assert!(edited.section_by_name(".comment").is_none());
        assert_eq!(
            edited.section_by_name(".data").map(|section| section.data),
            Some(&[0x5a; 0x30][..])
        );
    }
}

#[test]
fn add_load_segment_maps_new_data() {
    for encoding in ENCODINGS {
        let mut file = ElfFile::from_vec(sample_bytes(encoding)).expect("the file should parse");
        let loads = file.headers().load_segments().count();
        let data = b"data of a new segment".to_vec();
        let vaddr = file
            .add_load_segment(PF_R | PF_W, data.clone(), 0x1000)
            .expect("the segment should add");
        assert!(file.add_load_segment(PF_R, vec![0], 3).is_err());

        let bytes = file.try_build().expect("the edited file should build");
        let edited = reparse(&bytes);
        assert!(edited.headers().load_segments().count() > loads);
        assert_eq!(
            edited
                .read_vaddr(vaddr, data.len())
                .expect("the data is mapped"),
            data
        );

        let image = ElfImage::parse(&bytes).expect("the edited image should parse");
        assert_eq!(
            image
                .read_vaddr(vaddr, data.len())
                .expect("the data is mapped"),
            data
        );
        assert_eq!(
            image.interpreter().ok().flatten().as_deref(),
            Some(INTERPRETER)
        );
    }
}

#[test]
fn set_interpreter_writes_in_place_or_in_a_new_segment() {
    let long_path = "/opt/elfex/a/very/long/path/to/the/program/interpreter/ld-linux.so.2";
    for encoding in ENCODINGS {
        for path in ["/lib/ld.so", long_path] {
            let mut file =
                ElfFile::from_vec(sample_bytes(encoding)).expect("the file should parse");
            file.set_interpreter(path)
                .expect("the interpreter should change");
            assert!(file.set_interpreter("bad\0path").is_err());

            let bytes = file.try_build().expect("the edited file should build");
            let edited = reparse(&bytes);
            let interp = edited
                .section_by_name(".interp")
                .expect("the file has .interp");
            assert!(interp.data.starts_with(path.as_bytes()));

            let image = ElfImage::parse(&bytes).expect("the edited image should parse");
            assert_eq!(image.interpreter().ok().flatten().as_deref(), Some(path));
        }
    }
}

#[test]
fn edits_without_interpreter_fail() {
    let mut file = ElfBuilder::new(Encoding::ELF64_LE)
        .try_build()
        .expect("an empty file should build");
    assert!(file.set_interpreter("/lib/ld.so").is_err());
}

#[test]
fn stream_io_round_trips() {
    for encoding in ENCODINGS {
        let bytes = sample_bytes(encoding);

        let mut input = Cursor::new(bytes.clone());
        let file = ElfFile::from_stream(&mut input).expect("the stream should parse");
        let mut output = Cursor::new(Vec::new());
        file.write_to(&mut output)
            .expect("the stream write should work");
        assert_eq!(output.into_inner(), bytes);

        let mut input = Cursor::new(bytes.clone());
        let image = ElfImage::from_stream(&mut input).expect("the image stream should parse");
        let mut output = Cursor::new(Vec::new());
        image
            .write_to(&mut output)
            .expect("the image write should work");
        let dump = output.into_inner();
        assert_eq!(dump, image.try_build().expect("the image should build"));
        let reparsed = ElfImage::parse(&dump).expect("the dump should parse");
        assert!(reparsed.program_headers().eq(image.program_headers()));
        assert_eq!(reparsed.entry_point(), image.entry_point());
    }
}

#[cfg(feature = "std")]
#[test]
fn file_helpers_round_trip() {
    let directory = std::env::temp_dir().join(format!(
        "elfex-round-trip-{}-file-helpers",
        std::process::id()
    ));
    std::fs::create_dir_all(&directory).expect("the temporary directory should exist");
    let path = directory.join("sample.elf");
    let dump_path = directory.join("dump.elf");

    let result = std::panic::catch_unwind(|| {
        let bytes = sample_bytes(Encoding::ELF64_LE);
        let file = ElfFile::parse(&bytes).expect("the file should parse");
        file.write_to_file(&path).expect("the file should write");
        assert_eq!(std::fs::read(&path).expect("the file should read"), bytes);

        let loaded = ElfFile::from_file(&path).expect("the file should load");
        assert_eq!(loaded, file);
        let headers = ElfHeaders::from_file(&path).expect("the headers should load");
        assert_eq!(&headers, file.headers());
        let image = ElfImage::from_file(&path).expect("the image should load");
        image
            .write_to_file(&dump_path)
            .expect("the dump should write");
        let dump = ElfImage::from_file(&dump_path).expect("the dump should load");
        assert!(dump.program_headers().eq(image.program_headers()));
        assert_eq!(
            std::fs::read(&dump_path).expect("the dump should read"),
            image.try_build().expect("the image should build")
        );
    });

    std::fs::remove_dir_all(&directory).expect("the temporary directory should remove");
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
