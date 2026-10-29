# Elfex benchmarks

This package measures the speed and the heap use of Elfex. It is a separate package, like
`fuzz/`. It is not part of the published crate.

## Inputs

- **`synthetic`**: an x86-64 shared object that the package builds with `ElfBuilder` and the
  table builders. It has 51,000 versioned dynamic symbols, a GNU hash table, 50,000 `RELA`
  relocations, 50,000 `.symtab` symbols and a build ID note. Thus the benchmarks run on all
  hosts.
- **Real files**: set `ELFEX_BENCH_FILES` to a list of paths. Separate the paths like `PATH`
  (`:` on Linux, `;` on Windows).

## Operations

`src/lib.rs` defines the operations (`Operation`). Each benchmark name is `<input>/<operation>`:

| Operation | Elfex call |
| --- | --- |
| `headers_from_slice` | `ElfHeaders::from_slice` |
| `file_parse` | `ElfFile::parse` |
| `image_parse` | `ElfImage::parse` |
| `dynamic_symbol_list` | `ElfFile::dynamic_symbol_list` |
| `image_dynamic_symbol_list` | `ElfImage::dynamic_symbol_list` |
| `linking_symbol_names` | `ElfFile::linking`, then the name bytes of each symbol from `LinkingView::symbol_table` and `LinkingView::string_table` |
| `symbol_list` | `ElfFile::symbol_list` (`.symtab`) |
| `lookup_1000_cold` | `ElfFile::linking`, then `LinkingView::lookup` for 1,000 names |
| `lookup_1000_warm` | `LinkingView::lookup` for 1,000 names on a view with parsed tables |
| `lookup_dynamic_symbol_16` | `ElfFile::lookup_dynamic_symbol` for 16 names |
| `dynamic_relocations` | `ElfFile::dynamic_relocations`, then iterate all relocations |
| `notes_build_id` | `ElfFile::notes` and `ElfFile::build_id` |
| `file_try_build` | `ElfFile::try_build` (lossless round trip) |
| `to_mapped_image` | `ElfImage::to_mapped_image` |

Nine names in ten are exported dynamic symbols at equal steps. The other names are not in the
file.

## Commands

Run the commands on Linux or WSL from the repository root. Use release builds for all
measurements.

```bash
# Time: Criterion benchmarks. Save the results as the baseline "main".
ELFEX_BENCH_FILES=/usr/lib/llvm-19/lib/libLLVM.so.19.1:/usr/lib/x86_64-linux-gnu/libc.so.6 \
    cargo bench --manifest-path bench/Cargo.toml -- --save-baseline main

# Time: compare a changed tree with the saved baseline "main".
ELFEX_BENCH_FILES=/usr/lib/llvm-19/lib/libLLVM.so.19.1:/usr/lib/x86_64-linux-gnu/libc.so.6 \
    cargo bench --manifest-path bench/Cargo.toml -- --baseline main

# Time: only the synthetic input, only the symbol operations.
cargo bench --manifest-path bench/Cargo.toml -- 'synthetic/.*symbol'

# Heap: print a Markdown table for each input.
ELFEX_BENCH_FILES=/usr/lib/llvm-19/lib/libLLVM.so.19.1:/usr/lib/x86_64-linux-gnu/libc.so.6 \
    cargo run --release --manifest-path bench/Cargo.toml --bin memory
```

Criterion keeps the saved baselines in the target directory. If you set `CARGO_TARGET_DIR`,
use the same value for the two runs.

## Heap measurement

The `memory` binary has a global allocator that counts each allocation and forwards it to
`System`. It runs each operation once without measurement, then once with measurement:

- **Peak**: the highest heap size during the operation, minus the heap size at the start. The
  input bytes and the parsed `ElfFile` and `ElfImage` are allocated before the start.
- **Allocated**: the sum of the sizes of all allocations. A `realloc` counts as one allocation
  of the new size.
- **Allocations**: the number of allocations, `realloc` calls included.

## Baseline

`BASELINE.md` has the results for `origin/main` before the memory and speed work.
