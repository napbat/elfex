# Results after the memory and speed work

These results compare Elfex after the zero-copy work with the baseline in `BASELINE.md`
(commit `3f82985`). The machine, the inputs and the commands are the same as in
`BASELINE.md`.

## Changes

- `ElfFile<D>` is generic over the storage of the bytes. `ElfFile::parse` borrows the slice.
- `ElfImage<'a>` borrows the segment data of a byte slice.
- `StringTable<'a>` borrows its bytes, and the names of `NamedSymbol<'a>` borrow the string
  table. A symbol list has no allocation for each symbol.
- `exports` and `imports` describe only the symbols that they return.
- The symbol lists reuse the version strings of the last symbol.
- The large tables (symbols, relocations, GNU hash) get the exact capacity, so they do not grow
  and copy their entries.
- The symbol count from `DT_GNU_HASH` scans the relocations without a table.
- `LinkingView` parses the symbol, version and hash tables when it is made. It is `Send` and
  `Sync`. The cost of `linking()` on `libLLVM.so.19.1` is 0.34 ms and a peak of 1.69 MiB.

## Time (Criterion)

The values are the mean time of one run. The "after" column is from commit `73bcf53`
(before the exact capacity and the version string reuse, which make the symbol lists and the
relocations faster again, see the next section). The noisy `libLLVM.so.19.1` rows were measured
again on an idle machine.

| Operation | `libLLVM` before | `libLLVM` after | `libc` before | `libc` after | `synthetic` before | `synthetic` after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `headers_from_slice` | 2.6 µs | 1.33 µs | 2.72 µs | 2.57 µs | 856 ns | 593 ns |
| `file_parse` | 34.4 ms | 1.45 µs | 36.1 µs | 2.65 µs | 171 µs | 605 ns |
| `image_parse` | 32.4 ms | 1.50 µs | 51.6 µs | 2.75 µs | 337 µs | 694 ns |
| `dynamic_symbol_list` | 10.5 ms | 3.51 ms | 343 µs | 139 µs | 17.3 ms | 1.93 ms |
| `image_dynamic_symbol_list` | 17.2 ms | 4.09 ms | 363 µs | 146 µs | 16.2 ms | 2.21 ms |
| `linking_symbol_names` | 2.35 ms | 1.64 ms | 45.9 µs | 50.5 µs | 2.47 ms | 748 µs |
| `lookup_1000_cold` | 714 µs | 544 µs | 136 µs | 97.4 µs | 761 µs | 561 µs |
| `lookup_1000_warm` | 165 µs | 107 µs | 84.5 µs | 62.6 µs | 194 µs | 86.7 µs |
| `lookup_dynamic_symbol_16` | 9.31 ms | 6.90 ms | 522 µs | 423 µs | 10.3 ms | 6.99 ms |
| `dynamic_relocations` | 4.64 ms | 4.14 ms | 4.01 µs | 3.43 µs | 637 µs | 625 µs |
| `notes_build_id` | 188 ns | 176 ns | 258 ns | 244 ns | 117 ns | noisy |
| `file_try_build` | 29.3 ms | 24.8 ms | 33.6 µs | 28.8 µs | 177 µs | noisy |
| `to_mapped_image` | 30.5 ms | 24.3 ms | 45.2 µs | 44.5 µs | 199 µs | 124 µs |

`linking_symbol_names` on `libc.so.6` is 10% slower: the view now parses the version and hash
tables when it is made. The other operations of the view get faster for this reason.

## Time and heap at the final commit

A small timing binary with a counting allocator (best of 7 runs, peak heap above the input
buffer) gives these values for `libLLVM.so.19.1` (123.67 MiB):

| Operation | Before: time | Before: peak | After: time | After: peak |
| --- | ---: | ---: | ---: | ---: |
| `ElfFile::parse` | 23.3 ms | 123.67 MiB | 0.002 ms | 0.00 MiB |
| `ElfFile::parse` + `exports()` | 32.8 ms | 139.91 MiB | 3.74 ms | 6.86 MiB |
| `ElfImage::parse` + `exports()` | 35.2 ms | 156.50 MiB | 4.21 ms | 6.86 MiB |
| `exports()` | 8.55 ms | 16.25 MiB | 3.09 ms | 6.86 MiB |
| `imports()` | 8.54 ms | 16.25 MiB | 0.28 ms | 1.37 MiB |
| `needed_libraries()` | 0.045 ms | 3.62 MiB | 0.001 ms | 0.00 MiB |
| `dynamic_relocations()` | 4.00 ms | 16.03 MiB | 1.55 ms | 10.20 MiB |
| view: `lookup` x1000 | 0.62 ms | 5.79 MiB | 0.45 ms | 1.69 MiB |
| view: `exports` + `imports` | 13.9 ms | 16.25 MiB | 3.40 ms | 7.25 MiB |

With the input buffer, the peak of `ElfFile::parse` + `exports()` drops from 263.6 MiB
(2.1 times the file) to 130.5 MiB (1.06 times the file). With a memory map, the heap peak is
6.86 MiB.

## Heap (`memory` binary, commit `73bcf53`)

| Operation | `libLLVM` before: peak / allocations | `libLLVM` after: peak / allocations | `libc` before | `libc` after |
| --- | ---: | ---: | ---: | ---: |
| `file_parse` | 123.67 MiB / 43 | 4.87 KiB / 42 | 1.91 MiB / 74 | 8.75 KiB / 73 |
| `image_parse` | 123.66 MiB / 47 | 4.87 KiB / 45 | 1.89 MiB / 80 | 8.75 KiB / 76 |
| `dynamic_symbol_list` | 16.24 MiB / 105417 | 7.21 MiB / 50 | 663.55 KiB / 6429 | 453.57 KiB / 77 |
| `image_dynamic_symbol_list` | 32.83 MiB / 105488 | 7.21 MiB / 95 | 683.55 KiB / 6450 | 453.55 KiB / 98 |
| `linking_symbol_names` | 5.11 MiB / 21 | 2.16 MiB / 91 | 130.69 KiB / 16 | 151.83 KiB / 124 |
| `lookup_1000_cold` | 5.78 MiB / 1891 | 2.16 MiB / 91 | 166.06 KiB / 1904 | 151.83 KiB / 124 |
| `lookup_1000_warm` | 386 B / 1800 | 0 B / 0 | 61 B / 1800 | 0 B / 0 |
| `lookup_dynamic_symbol_16` | 5.78 MiB / 1488 | 2.16 MiB / 1456 | 166.04 KiB / 1696 | 131.83 KiB / 1664 |
| `dynamic_relocations` | 16.03 MiB / 33 | 16.03 MiB / 35 | 22.50 KiB / 27 | 22.53 KiB / 29 |
| `file_try_build` | 123.66 MiB / 6 | 123.66 MiB / 6 | 1.90 MiB / 6 | 1.90 MiB / 6 |
| `to_mapped_image` | 124.28 MiB / 1 | 124.28 MiB / 1 | 1.95 MiB / 1 | 1.95 MiB / 1 |

`file_try_build` and `to_mapped_image` make a new file, so their peak is the size of the
output.
