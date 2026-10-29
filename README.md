# Elfex

Elfex is a parser, editor and builder for ELF files and images. It works with `no_std`.
Elfex keeps raw files and loader-mapped images apart, because each layout translates a virtual
address to a different source offset.

[![CI](https://github.com/napbat/elfex/actions/workflows/ci.yml/badge.svg)](https://github.com/napbat/elfex/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](#license)

## What it supports

- Raw ELF files, loader-mapped images, and the memory of a remote process.
- ELF32 and ELF64, little-endian and big-endian data. `Encoding` reads all multi-byte values.
- Executables, shared objects, relocatable objects and core files.
- Checked translation between virtual addresses, file offsets and runtime addresses, with
  the load bias of a position-independent image.
- Sections, segments, the zero-filled memory after `p_filesz`, and the extended numbering
  of large header tables (`PN_XNUM`, `SHN_XINDEX`).
- The dynamic table, the dynamic and static symbol tables, string tables, notes, SysV and
  GNU hash tables, and GNU symbol versions.
- Section groups (`SHT_GROUP`, COMDAT), and the `NT_FILE` and `NT_AUXV` notes of core files.
- `REL`, `RELA` and `RELR` relocations, with relocation types for many architectures.
- `.eh_frame` and `.eh_frame_hdr` records: CIEs, FDEs and the binary search table.
- Lossless round trips of raw files through `ElfFile`. When nothing changes,
  `ElfFile::try_build` returns the input bytes.
- patchelf-style edits: section data, new sections, new `PT_LOAD` segments and the program
  interpreter.
- Parsing of malformed input: `validate()` reports the problems. Fallible builders, with no
  panics on file data.
- Sequential I/O and positional I/O.
- `no_std + alloc` support. Sequential I/O uses
  [`nostdio`](https://github.com/coconutbird/nostdio). Positional `ReadAt` access is also
  available for mapped images and remote images.

Elfex does not do these tasks:

- It does not parse DWARF debug information. To parse it, give the bytes of the `.debug_*`
  sections (`ElfFile::section_data`) to a DWARF crate, for example `gimli`.
- It does not decompress `SHF_COMPRESSED` section data. It parses the compression header
  (`CompressionHeader`) only.
- It does not interpret the call frame instructions of a CIE or an FDE. It gives the
  instruction bytes.
- It does not decode Android packed relocations (`DT_ANDROID_REL`, `DT_ANDROID_RELA`).
- It does not demangle symbol names.

## Installation

```toml
[dependencies]
elfex = "0.1"
```

For `no_std + alloc`:

```toml
[dependencies]
elfex = { version = "0.1", default-features = false }
```

Elfex 0.1 requires Rust 1.88 or newer.

The default `std` feature adds filesystem helpers and `FileReader`. It also enables the `std`
feature of `nostdio`. Then the `nostdio` traits and `nostdio::IoError` are the `std::io` items,
so `std` files and streams work with the stream APIs directly.

Without `std`, parsing, building, mapped images, validation, in-memory readers and stream APIs
are still available. `nostdio` then supplies its own traits and error type. An I/O error is an
`ErrorKind::Io` in both builds.

## Core types

| Type | Use it for |
| --- | --- |
| `ElfFile` | A full raw file. It keeps all bytes, or borrows them, and gives the sections and the edits |
| `ElfImage` | The loader view: the file header and the segments, from raw bytes or loader-mapped bytes |
| `ElfHeaders` | The headers only. It does not load section or segment data |
| `ElfBuilder` | Building a new executable or shared object |

## Quick start

```rust,no_run
use elfex::ElfFile;

let file = ElfFile::from_file("/usr/bin/true")?;

println!("64-bit: {}", file.is_64bit());
println!("machine: {}", file.machine());
println!("entry point: {:#x}", file.entry_point());

for section in file.sections() {
    println!("{:<24} {:#x} {} bytes", section.name, section.header.addr, section.data.len());
}

if let Some(interpreter) = file.interpreter()? {
    println!("interpreter: {interpreter}");
}
for library in file.needed_libraries()? {
    println!("needs {library}");
}
# Ok::<(), elfex::Error>(())
```

Use `ElfFile::parse(raw_bytes)` for a raw file with sections. It borrows the bytes and does not
copy them. Use `ElfImage::parse(raw_bytes)` if you need only the segments, as the loader sees
them. It also borrows the bytes.

## Raw files versus mapped images

```rust,no_run
use elfex::{ElfImage, ParseOptions, SourceLayout};

# let raw_file_bytes: &[u8] = &[];
# let mapped_image: &[u8] = &[];
// Raw file: segment data is at the file offset p_offset.
let raw = ElfImage::parse(raw_file_bytes)?;

// Loader-mapped image: segment data is at p_vaddr minus the image origin.
let mapped = ElfImage::parse_mapped(mapped_image)?;

// Keep the runtime address of the image origin, to know the load bias.
let loaded = ElfImage::parse_mapped_at(mapped_image, 0x7f12_3456_0000)?;

// Explicit options also accept pages that the source cannot supply.
let partial = ElfImage::parse_with_options(
    mapped_image,
    ParseOptions::mapped().allow_missing_segment_data(),
)?;

assert_eq!(raw.source_layout(), SourceLayout::File);
assert_eq!(mapped.source_layout(), SourceLayout::Mapped);
assert_eq!(loaded.runtime_base(), Some(0x7f12_3456_0000));
println!("load bias: {:#x?}", loaded.load_bias());
println!("{} segments", partial.segments.len());
# Ok::<(), elfex::Error>(())
```

These terms apply to a mapped image:

- The image origin is the virtual address of file offset 0 in the `PT_LOAD` segment with the
  lowest address. Byte 0 of a mapped image is at the image origin. `image_origin()` gives
  it.
- The runtime base is the address of the image origin in the process. For a shared object
  that `dl_iterate_phdr` reports, the runtime base is `dlpi_addr` plus the image origin.
- The load bias is the runtime base minus the image origin. Add the load bias to a virtual
  address of the file to get the runtime address (`vaddr_to_runtime`).

`ElfImage::to_mapped_image()` makes loader-style bytes from the segments. It does not apply
relocations. `ElfImage::to_mapped_image_at(runtime_base)` makes the bytes for a different
runtime base. It applies the relative relocations: `R_*_RELATIVE` in the `RELA`, `REL` and PLT
tables, and all `RELR` entries. It does not apply symbol relocations.

`ElfImage::try_build()` writes a raw file without sections from the segments. Use it to dump a
mapped image to a file. For a dump of a live process, first call
`ElfImage::restore_dynamic_pointers()`. It writes the virtual addresses of the file back into
the `d_ptr` entries that glibc changed (see the caution below). Then other tools can read the
dynamic table of the dump. The `dump-process` example does this.

> **Caution:** In a loaded process, glibc writes runtime addresses into many `d_ptr` entries
> of `.dynamic` (but not on MIPS and RISC-V). Parse such an image with a runtime base
> (`parse_mapped_at` or `read_mapped_from`). Then the dynamic table accessors translate the
> runtime addresses back to virtual addresses of the file.

For a remote process or a different random-access source, implement `ReadAt`. Then use one of
these functions:

```text
ElfImage::read_from(&reader, source_offset, SourceLayout::Mapped)
ElfImage::read_mapped_from(&reader, source_offset, runtime_base)
ElfImage::read_from_with_options(&reader, source_offset, options)
ElfHeaders::read_from(&reader, source_offset, SourceLayout::Mapped)
```

A process can have pages that are not readable. With `MissingSegmentData::Zero`
(`ParseOptions::allow_missing_segment_data`), the parser fills these pages with zeros. It does
not discard the full segment.

```rust,no_run
use elfex::{ElfImage, ParseOptions, ReadAt, Result};

/// The memory of a different process, for example through `/proc/<pid>/mem`.
struct ProcessMemory;

impl ReadAt for ProcessMemory {
    fn read_at(&self, address: u64, buf: &mut [u8]) -> Result<usize> {
        // Read the bytes at `address`. Return an error for a page that is not readable.
        # let _ = (address, buf);
        # Ok(0)
    }

    fn size(&self) -> Option<u64> {
        // A process has no size.
        None
    }
}

# let runtime_base = 0x7f12_3456_0000;
let image = ElfImage::read_from_with_options(
    &ProcessMemory,
    runtime_base,
    ParseOptions::mapped()
        .runtime_base(runtime_base)
        .allow_missing_segment_data(),
)?;
println!("{:?}", image.needed_libraries()?);
# Ok::<(), elfex::Error>(())
```

`BaseAddressReader` reads a module in the current process. `ElfHeaders::vaddr_to_source_offset`
does the same layout-aware translation as the image parser. It does not read the segments.

## Editing

`ElfFile` keeps all bytes of the file. `ElfFile::parse` borrows the bytes. The edits that change
the size of the file need a file that owns its bytes: use `ElfFile::from_vec` or
`ElfFile::into_owned`. Each edit changes the data buffer and the headers. `ElfFile::try_build`
writes the headers into a copy of the buffer:

- `set_section_data` replaces the data of a section. Smaller data stays in place. Larger data
  of a section without `SHF_ALLOC` moves to the end of the file.
- `add_section` adds a section without `SHF_ALLOC`, and adds its name to `.shstrtab`.
- `remove_section` removes a section and renumbers the sections after it: the section links,
  `e_shstrndx`, the `st_shndx` values of all symbol tables (also `SHT_SYMTAB_SHNDX`) and the
  section group members. An `STT_SECTION` symbol of the removed section becomes undefined.
  The method refuses to remove a section that a link, another symbol, a relocation or a group
  signature uses.
- `add_load_segment` adds a `PT_LOAD` segment. If the program header table cannot grow in
  place, the method moves it to a new segment, as patchelf does.
- `set_interpreter` changes the `PT_INTERP` path, in place or in a new segment.

```rust
use elfex::program::{PF_R, PF_W};
use elfex::section::{SHF_ALLOC, SHF_EXECINSTR};
use elfex::{BuilderSection, ElfBuilder, ElfFile, Encoding, Machine, NewSection, SectionType};

# let bytes = ElfBuilder::new(Encoding::ELF64_LE)
#     .machine(Machine::X86_64)
#     .interpreter("/lib64/ld-linux-x86-64.so.2")
#     .add_section(BuilderSection::progbits(".text", SHF_ALLOC | SHF_EXECINSTR, vec![0xc3]))
#     .add_section(BuilderSection::progbits(".comment", 0, b"GCC\0".to_vec()))
#     .entry_in_section(".text", 0)
#     .try_build()?
#     .try_build()?;
// The round trip is lossless.
let mut file = ElfFile::from_vec(bytes.clone())?;
assert_eq!(file.try_build()?, bytes);

// Change the program interpreter, as `patchelf --set-interpreter` does.
file.set_interpreter("/opt/glibc/lib/ld-linux-x86-64.so.2")?;

// Replace the data of a section. The larger data moves to the end of the file.
let comment = file.section_by_name(".comment").expect("the file has .comment").index;
file.set_section_data(comment, b"elfex 0.1\0".to_vec())?;

// Add a section without SHF_ALLOC, and a new writable PT_LOAD segment.
file.add_section(NewSection::new(".elfex", SectionType::PROGBITS, vec![1, 2, 3]))?;
let address = file.add_load_segment(PF_R | PF_W, vec![0x5a; 64], 0x1000)?;

let edited_bytes = file.try_build()?;
let edited = ElfFile::parse(&edited_bytes)?;
assert!(!edited.validate().has_errors());
assert_eq!(edited.read_vaddr(address, 64)?, [0x5a; 64]);
assert_eq!(edited.interpreter()?.as_deref(), Some("/opt/glibc/lib/ld-linux-x86-64.so.2"));
# Ok::<(), elfex::Error>(())
```

Use `header_mut`, `program_headers_mut` and `section_headers_mut` for other header edits.
`try_build` serializes them.

## Tables

`ElfFile` and `ElfImage` have the same accessors for the dynamic linking data. Each accessor
reads the tables that the dynamic table names. `ElfFile` uses the sections (for example
`.dynsym`) if they exist.

| Accessor | Result |
| --- | --- |
| `dynamic()`, `dynamic_strings()` | The dynamic table and its string table |
| `needed_libraries()`, `soname()`, `rpath()`, `runpath()` | The `DT_NEEDED`, `DT_SONAME`, `DT_RPATH` and `DT_RUNPATH` strings |
| `interpreter()` | The `PT_INTERP` path |
| `dynamic_symbols()`, `dynamic_symbol_list()` | The dynamic symbol table, and the symbols with names, sections and versions (`NamedSymbol`) |
| `exports()`, `imports()`, `lookup_dynamic_symbol(name)` | The defined and the undefined dynamic symbols, and a hash table lookup |
| `version_tables()` | The `versym`, `verdef` and `verneed` tables |
| `sysv_hash_table()`, `gnu_hash_table()` | The `DT_HASH` and `DT_GNU_HASH` tables |
| `dynamic_relocations()` | The `RELA`, `REL`, PLT, `RELR`, Android packed (`DT_ANDROID_REL`, `DT_ANDROID_RELA`) and CREL (`DT_CREL`) relocation tables |
| `linking()` | A `LinkingView` that parses each of these tables only once |
| `notes()`, `build_id()` | The notes, and the `NT_GNU_BUILD_ID` descriptor |
| `core_file_mappings()`, `auxv()` | The `NT_FILE` mapped files and the `NT_AUXV` auxiliary vector of a core file |
| `init_array()`, `fini_array()`, `preinit_array()` | The initialization and termination functions |
| `eh_frame_hdr()` | The `PT_GNU_EH_FRAME` table |

`ElfFile` also has accessors for the sections:

| Accessor | Result |
| --- | --- |
| `symbols()`, `symbol_strings()` | The static symbol table (`SHT_SYMTAB`) and its string table |
| `symbol_list()` | The static symbols with names and sections (`NamedSymbol`). `SHT_SYMTAB_SHNDX` gives the extended section indices |
| `lookup_symbol(name)` | A static symbol, or else a dynamic symbol, with the name |
| `section_relocations(index)`, `relocation_sections()` | One relocation section (`SHT_REL`, `SHT_RELA`, `SHT_CREL`, `SHT_ANDROID_REL` or `SHT_ANDROID_RELA`), or all of them with their target sections (`RelocationSection`) |
| `section_groups()` | The `SHT_GROUP` sections with their flags, signatures and members (`SectionGroup`). `GroupTable` parses and writes the data of one group |
| `section_data_by_name(name)` | The bytes of the first section with the name |
| `to_image()` | The `ElfImage` of the file as it is now, with all edits |

`Relocation::type_name(machine)` gives the spec name of a relocation type, for example
`R_X86_64_RELATIVE`. `Note::type_name()` gives the spec name of a note type for its owner,
for example `NT_GNU_BUILD_ID`.

Each accessor parses the tables that it needs again. To call many accessors, or to look up
many symbols, use `linking()`. The `LinkingView` parses each table at the first call that needs
it and keeps it, so each `lookup(name)` is a hash table lookup only. It gives the same results
as the accessors.

```rust,no_run
use elfex::ElfFile;

# let bytes: &[u8] = &[];
let file = ElfFile::parse(bytes)?;

println!("soname: {:?}", file.soname()?);
for symbol in file.exports()? {
    let version = symbol.version.as_deref().unwrap_or("");
    println!("export {}@{version} at {:#x}", symbol.name, symbol.symbol.value);
}
for symbol in file.imports()? {
    println!("import {} from {:?}", symbol.name, symbol.version_file);
}
if let Some(build_id) = file.build_id()? {
    let hex: String = build_id.iter().map(|byte| format!("{byte:02x}")).collect();
    println!("build ID: {hex}");
}
let relocations = file.dynamic_relocations()?;
if let Some(rela) = &relocations.rela {
    println!("{} RELA relocations", rela.relocations.len());
}
for section in file.relocation_sections()? {
    for relocation in &section.table {
        let kind = relocation.type_name(file.machine()).unwrap_or("unknown");
        println!("{}: {kind} at {:#x}", section.name, relocation.offset);
    }
}
for group in file.section_groups()? {
    println!("group {:?} with {} members", group.signature, group.members.len());
}
let view = file.linking()?;
for name in ["malloc", "free"] {
    if let Some(symbol) = view.lookup(name)? {
        println!("{name} is symbol {} at {:#x}", symbol.index, symbol.symbol.value);
    }
}
# Ok::<(), elfex::Error>(())
```

Each table type also parses from bytes and serializes to bytes. For example,
`SymbolTable::parse(bytes, encoding)` parses the contiguous bytes of a symbol table, and
`RelocationTable::parse(bytes, encoding, machine, with_addend)` parses a `REL` or `RELA`
table. `RelocationTable` also decodes and encodes the compressed formats:
`parse_android_packed` and `write_android_packed` for the Android `APS2` format, and
`parse_crel` and `write_crel` for CREL. The table modules (`dynamic`, `symbol`, `strtab`,
`reloc`, `note`, `hash`, `version`, `group` and `eh_frame`) also hold the constants of each
area, and the builders (`SymbolTableBuilder`, `StringTableBuilder`, `SysvHashTable::try_build`
and `GnuHashTable::try_build`). Each `build` function panics on invalid input. Use the
matching `try_build` function to get a `Result`.

`ElfHeaders::validate(file_size)` checks only the headers, without the file data. Use it after
`ElfHeaders::from_slice` or `ElfHeaders::read_from`.

## Sequential and positional I/O

`nostdio` supplies the `Read`, `Write` and `Seek` traits and the `Cursor` type. `elfex::io`
re-exports them:

```rust,no_run
use elfex::ElfFile;
use elfex::io::Cursor;

# let raw_file_bytes: &[u8] = &[];
let mut input = Cursor::new(raw_file_bytes);
let file = ElfFile::from_stream(&mut input)?;

let mut output = Cursor::new(Vec::new());
file.write_to(&mut output)?;
# Ok::<(), elfex::Error>(())
```

Elfex also has the positional `ReadAt` abstraction. `ReadAt` is better for these sources:

- process memory
- sparse address spaces
- sources with concurrent callers
- sources that must not share cursor state

`SeekReader` adapts a `nostdio::Read + Seek` source to `ReadAt`.

## Building a file

```rust
use elfex::program::SegmentType;
use elfex::section::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE};
use elfex::{BuilderSection, ElfBuilder, ElfImage, Encoding, Machine};

let file = ElfBuilder::new(Encoding::ELF64_LE)
    .machine(Machine::X86_64)
    .interpreter("/lib64/ld-linux-x86-64.so.2")
    .add_section(BuilderSection::progbits(
        ".text",
        SHF_ALLOC | SHF_EXECINSTR,
        vec![0x31, 0xff, 0xb8, 0x3c, 0, 0, 0, 0x0f, 0x05],
    ))
    .add_section(BuilderSection::progbits(".data", SHF_ALLOC | SHF_WRITE, vec![0; 16]))
    .add_section(BuilderSection::nobits(".bss", SHF_ALLOC | SHF_WRITE, 0x1000))
    .entry_in_section(".text", 0)
    .try_build()?;
assert!(!file.validate().has_errors());

let raw_file = file.try_build()?;
let image = ElfImage::parse(&raw_file)?;
assert_eq!(image.load_segments().count(), 3);
assert!(image.segment(SegmentType::GNU_STACK).is_some());
# Ok::<(), elfex::Error>(())
```

The builder puts the sections in `PT_LOAD` segments by their flags: read-only, executable
and writable. It adds `PT_PHDR`, `PT_INTERP` and `PT_GNU_STACK`. Use
`add_segment_for_section` for other segments, for example `PT_DYNAMIC` or `PT_NOTE`. The
builder returns an `ElfFile`, so you can edit the result further.

Section data that holds addresses (for example `.dynamic` or relocated code) needs the layout
before the build. `ElfBuilder::try_layout()` plans the layout without the file bytes, and
returns the address, file offset and size of each section (`BuilderLayout::section(name)`) and
the entry point. The layout depends only on the builder settings and on the type, flags, size,
alignment and order of the sections. Thus, plan with placeholder data of the final size, make
the final data from the addresses, and then build:

```rust
use elfex::section::{SHF_ALLOC, SHF_WRITE};
use elfex::{BuilderSection, ElfBuilder, Encoding};

let pointer = |data| BuilderSection::progbits(".pointer", SHF_ALLOC | SHF_WRITE, data);
let builder = ElfBuilder::new(Encoding::ELF64_LE)
    .add_section(BuilderSection::progbits(".rodata", SHF_ALLOC, b"hello\0".to_vec()));
let layout = builder.clone().add_section(pointer(vec![0; 8])).try_layout()?;
let rodata = layout.section(".rodata").expect("the layout has .rodata").addr;
let file = builder.add_section(pointer(rodata.to_le_bytes().to_vec())).try_build()?;
assert_eq!(file.section_by_name(".rodata").map(|section| section.header.addr), Some(rodata));
# Ok::<(), elfex::Error>(())
```

## Examples

The `examples/` directory has four command line tools. Each tool needs the `std` feature.

| Example | What it does |
| --- | --- |
| `elfdump` | Prints a summary of a file, as `readelf` does: headers, dynamic table, symbols with versions, relocations, notes and validation issues |
| `elfpatch` | Changes a file, as `patchelf` does: the interpreter, added and removed sections and the entry point. It validates the result |
| `dump-process` | Reads a module of a running Linux process through `/proc/<pid>/mem`, prints a summary and can write the module to a file |
| `build-tiny` | Builds a minimal static x86-64 Linux executable that prints a message |

```bash
cargo run --example elfdump -- -h -l -S -d /usr/bin/ls
cargo run --example elfdump -- -s -V /usr/lib/x86_64-linux-gnu/libc.so.6
cargo run --example elfpatch -- --print-interpreter --print-needed /usr/bin/ls
cargo run --example elfpatch -- --set-interpreter /opt/ld.so --add-section .note.extra=extra.bin -o ls.patched /usr/bin/ls
cargo run --example dump-process -- "$(pidof -s sleep)" libc.so.6 --output libc.dump
cargo run --example build-tiny -- --message "Hello" tiny && ./tiny
```

Without part options, `elfdump` prints all parts. Use `--help` with each tool to see all
options. `dump-process` needs read access to the memory of the process. The kernel setting
`kernel.yama.ptrace_scope` can block this access. In that case, run the tool as root.

## Module layout

The facade modules contain the usual entry points:

| Module | Contents |
| --- | --- |
| `image` | `ElfFile`, `ElfImage`, `ElfHeaders`, parsing options, validation, and `ElfBuilder` |
| `headers` | The file header, the program and section headers, and their enums |
| `tables` | Dynamic, symbol, string, relocation, note, hash, version, group and unwind tables |
| `io` | `nostdio` traits/types plus positional `ReadAt` readers |

Specialized modules, for example `dynamic`, `symbol`, `reloc`, `note`, `linking` and
`validation`, are also public. Use them to import a specific area.

Nested modules use the `module.rs` and `module/child.rs` layout. Elfex does not use the older
`module/mod.rs` form.

## Development

[`mise`](https://mise.jdx.dev/) manages the toolchain and the pre-commit hooks:

```bash
mise install
mise run precommit-install
mise run precommit
```

The hooks run rustfmt and Clippy on all targets of the crate. They do this with all features
and with `no_std + alloc`. They also lint the separate fuzz and benchmark packages.

CI runs the same checks. CI also runs the tests and rustdoc with both feature sets, and Clippy
and the tests for the 32-bit `i686-pc-windows-msvc` target. On Linux, CI also does these
tasks:

- It runs the tests on big-endian hosts (`s390x` and 32-bit `powerpc`) through qemu.
- It runs the corpus compatibility test and the edit-and-run test (see below).
- It runs each fuzz target for one minute.
- It measures the line coverage, and fails below 97%.

Each package manifest denies warnings, the Clippy pedantic group, missing docs and unsafe code.
In the crate, the only unsafe code is `BaseAddressReader`. In the separate `bench/` package, the
only unsafe code is the counting allocator. Direct Cargo commands thus apply the same policy.
The Rust examples in this README compile as doctests.

The fuzz targets are in `fuzz/`. Run them with `cargo-fuzz` on Linux, macOS or WSL:

```bash
cargo +nightly fuzz run fuzz-elf-headers
cargo +nightly fuzz run fuzz-elf-image
cargo +nightly fuzz run fuzz-elf-file
cargo +nightly fuzz run fuzz-elf-edit
```

`fuzz-elf-edit` applies a sequence of `ElfFile` edits to the input. It checks that each edited
file parses again and that its round trip is lossless.

The separate `bench/` package measures the speed and the heap use of Elfex. It has Criterion
benchmarks (`cargo bench --manifest-path bench/Cargo.toml`) and a `memory` binary with a
counting allocator. The input is a large synthetic shared object, and optionally the files in
`ELFEX_BENCH_FILES`. `bench/README.md` gives the commands, and `bench/BASELINE.md` gives the
baseline results.

### Compatibility tests with real files

The ignored test `tests/corpus` compares Elfex with `llvm-readelf` on real ELF files. For each
file, it checks these items:

- The parse, the lossless round trip and the validation.
- The headers, sections, segments, dynamic table, symbols, relocations, notes, versions and
  section groups, against the JSON and text output of `llvm-readelf`. This includes the
  Android packed (`SHT_ANDROID_REL`, `SHT_ANDROID_RELA`) and CREL (`SHT_CREL`) relocation
  sections.
- All accessors of `ElfFile` and `ElfImage`, the `.eh_frame` parser, the symbol lookup of
  `LinkingView` and the accessors, and the mapped image.

Make a corpus with `scripts/build-corpus.sh` (it needs clang and ld.lld), then run the test on
Linux or WSL. The script also makes Android shared objects with packed relocations
(`ld.lld --pack-dyn-relocs=android`) and objects with CREL relocations
(`clang -Wa,--crel`). Add the system directories that you want to check:

```bash
scripts/build-corpus.sh ~/elfex-corpus
ELFEX_CORPUS=~/elfex-corpus:/usr/bin:/usr/lib/x86_64-linux-gnu:/lib/modules \
    cargo test --release --test corpus -- --ignored --nocapture corpus
```

These environment variables control the test:

| Variable | Use |
| --- | --- |
| `ELFEX_CORPUS` | The files and directories to check, separated as in `PATH`. The test walks the directories recursively and selects the ELF files |
| `ELFEX_CORPUS_MAX_BYTES` | The size of the largest file to check. The default is 512 MiB |
| `ELFEX_READELF` | The reference tool. The default is `llvm-readelf`. Without the tool, the test does only the self-consistency checks |

The test prints each failure and a summary table, and fails if a category has failures.
`tests/corpus/defects.rs` lists the known defects of toolchain outputs that the test accepts.

The ignored test `edit_and_run` edits the programs in `gnu/x86_64`, `gnu/aarch64` and
`gnu/powerpc64le` of the corpus with each `ElfFile` edit. Then it runs each edited program and
compares the output with the output of the original program. It runs the AArch64 and POWER
programs with `qemu-user`:

```bash
ELFEX_CORPUS=~/elfex-corpus cargo test --test corpus -- --ignored --nocapture edit_and_run
```

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Elfex by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
