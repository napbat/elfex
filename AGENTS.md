# Agent rules

These rules apply to all agents that change this repository. Obey all rules in all changes.

## Language: ASD-STE100 style

Write all new and changed text in a style like ASD-STE100 Simplified Technical English. This
includes doc comments, code comments, Markdown files and commit messages. Follow the writing
rules below. The STE dictionary does not apply: use any clear English word.

- Keep sentences short: about 20 words for an instruction, about 25 words for a description.
- Write one instruction in each sentence.
- Use the imperative form for instructions.
- Use the active voice.
- Prefer simple tenses.
- Give each word one meaning, and use the same term for the same item each time.
- Use the names from the code for code items (for example `ElfImage`, `ReadAt`).
- Use articles ("the", "a") where they make the text clearer.
- Avoid long noun clusters. Break up clusters of more than three words.
- Write short paragraphs with one topic each.
- Use a vertical list for a sequence of steps or for many items.
- Put a warning or a caution before the instruction it applies to.

Start the summary line of each doc comment with a verb in the imperative form (for example
"Return the file offset of the segment."). Do not use the third person ("Returns").

Write a commit message as `area: summary`, with a lowercase summary. Use the module name as the
area (for example `dynamic`, `symbol`, `elf`). For a change outside `src/`, use the top-level
item (for example `ci`, `fuzz`, `readme`).

## Lints: Clippy pedantic

The crate denies all warnings, all Clippy `pedantic` lints, `missing_docs` and `unsafe_code`.
The `[lints]` tables in `Cargo.toml`, `fuzz/Cargo.toml` and `bench/Cargo.toml` set this.

- Keep the `[lints]` tables of the three manifests the same.
- Do not lower a lint level in a manifest or in the code.
- Do not use `#[allow(...)]`. The manifests deny `clippy::allow_attributes`.
- Use `#[expect(lint, reason = "...")]` only if no change to the code can remove the lint.
- Make sure that each expectation is fulfilled on 32-bit and 64-bit targets, with and without
  the `std` feature. An unfulfilled expectation is an error.
- Do not add an item to `clippy.toml` to hide a lint. Add a word to `doc-valid-idents` only for
  a product or architecture name in prose (for example AArch64).
- `clippy.toml` sets `avoid-breaking-exported-api = false`. Fix a lint on the public API too.
- Do not add `unsafe` code. The exceptions are `BaseAddressReader` in `src/reader.rs` and the
  counting allocator in `bench/src/bin/memory.rs`. Each of their unsafe items has
  `#[expect(unsafe_code)]` and a `// SAFETY:` comment.
- Make sure that these commands complete without warnings:

```sh
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path bench/Cargo.toml --all-targets -- -D warnings
```

## File size: 1000 lines

- Keep each source file at a maximum of 1000 lines. This includes integration tests.
- If a change makes a file longer than 1000 lines, split the file into submodules.
- If you change a file that is already longer than 1000 lines, do not make it longer. Split it
  as part of the change.
- Put each submodule in a new file below the directory of its parent module.
- Split by topic. Do not split at a random line.

Clippy also limits each function to 100 lines (the `too_many_lines` default).

## Layout: Cargo package layout

Follow the Cargo package layout:
<https://doc.rust-lang.org/cargo/guide/project-layout.html>.

- Put the library root in `src/lib.rs`.
- Put integration tests in `tests/`.
- Put fuzz targets in `fuzz/fuzz_targets/`.
- Put examples in `examples/` and benchmarks in `benches/`.
- For a test, example or benchmark with many files, make a directory with a `main.rs` file and
  the modules.
- Use snake_case names for modules.
- Put a module in `foo.rs` and its child modules in `foo/`. Do not use `mod.rs` files. The
  manifests deny `clippy::mod_module_files`.
- Re-export a new public type from the crate root (`src/lib.rs`). If a facade module matches
  its area (`image`, `headers`, `tables` or `io`), also re-export it from that module.

## Library rules

- Keep the library usable as `no_std + alloc`. Import `alloc` items through
  `use crate::prelude::*;`. Put each item that needs `std` behind `#[cfg(feature = "std")]`.
- Treat all ELF bytes as untrusted input. Do not panic on file data.
- Use checked arithmetic and `TryFrom` for values from file data. On failure, return an
  `Error` with the `ErrorKind` that matches the problem. Do not use an `as` cast that can
  truncate or wrap.
- Give each panicking function a `try_*` function that returns `Result`. Document the panic in
  a `# Panics` section, and refer to the `try_*` function.
- Support ELF32 and ELF64, little-endian and big-endian data, and raw files and loader-mapped
  images.
- Remember that `usize` has 32 bits on `i686-pc-windows-msvc`. CI checks this target.
- Read all multi-byte values through `Encoding`. Do not assume the byte order of the host.
- Keep `ElfFile` round trips lossless. When nothing changes, `ElfFile::try_build` returns the
  input bytes.
- In docs for a spec structure, name the ELF structure (for example `Elf64_Dyn`). For an address
  field, say if it is a virtual address or a file offset.
- Do not use language features or library APIs newer than Rust 1.88 (`rust-version`).
- A breaking change to the public API needs a new minor version while the version is `0.x`.
  List each breaking change in the pull request.
- The Rust examples in `README.md` compile as doctests. Keep them correct when the API changes.

## Tests

- Add a regression test for each defect. Make sure that the test fails before the fix.
- Build test images in the test, with `ElfBuilder` or explicit bytes. Do not read ELF files from
  the host system.
- Make sure that the tests pass with and without the `std` feature.
- Do not use wall-clock time or random data without a fixed seed.

## Working copies

- Use one git worktree for each branch when agents work in parallel.
- Use absolute paths for all edits in a worktree. Do not edit the primary checkout from a
  worktree task.

## Checks

Make sure that all these checks pass before you report a change as complete:

```sh
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo fmt --manifest-path bench/Cargo.toml -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy --no-default-features --all-targets -- -D warnings
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path bench/Cargo.toml --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features
cargo doc --no-deps --all-features
cargo +1.88.0 check --all-features --all-targets
```

CI also runs Clippy and the tests for `i686-pc-windows-msvc`. To check 32-bit `usize`, add
`--target i686-pc-windows-msvc` to the Clippy and test commands.

`mise run precommit` runs the format and Clippy checks.

The corpus test is optional. Run it on Linux or WSL after a change to the parsers, the
accessors or the edits. It needs a corpus from `scripts/build-corpus.sh` and `llvm-readelf`:

```sh
scripts/build-corpus.sh ~/elfex-corpus
ELFEX_CORPUS=~/elfex-corpus:/usr/bin:/usr/lib/x86_64-linux-gnu \
    cargo test --release --test corpus -- --ignored --nocapture
```

- Make sure that the summary shows no failures. The README lists the environment variables.
- If the test finds a defect in Elfex, fix it and add a unit regression test.
- If the reference tool is wrong, change the comparison in `tests/corpus/compare` and give
  the reason in a comment.
- If a toolchain output is wrong, add the defect to `tests/corpus/defects.rs` with the
  reason.
- The ignored `edit_and_run` test also runs edited programs. It needs `qemu-user` for the
  AArch64 and POWER programs.
