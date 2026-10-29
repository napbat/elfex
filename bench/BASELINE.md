# Baseline results

These results are for Elfex at commit `3f82985` (`origin/main` before the memory and speed
work). `bench/README.md` describes the inputs, the operations and the commands.

## Machine

| Item | Value |
| --- | --- |
| CPU | AMD Ryzen 9 9950X3D, 16 cores, 32 threads |
| Memory | 30 GiB available to WSL |
| OS | Debian 13.5 on WSL 2, kernel 6.6.114.1-microsoft-standard-WSL2, Windows host |
| Rust | rustc 1.99.1 (58cf8f9c3 2026-10-13), release profile |
| Criterion | 0.8.2, flat sampling, 10 samples, 1 s warm-up, 3 s measurement |
| `libLLVM.so.19.1` | Debian `libllvm19` 1:19.1.7-3+b1, 123.66 MiB, `/usr/lib/llvm-19/lib/libLLVM.so.19.1` |
| `libc.so.6` | Debian `libc6` 2.41-12+deb13u3, 1.90 MiB, `/usr/lib/x86_64-linux-gnu/libc.so.6` |

The two real files have no `.symtab`, thus `symbol_list` does no work for them.

## Time

The value is the mean time of one run of the operation. The percentage is half the width of
the 95% confidence interval, relative to the mean.

```bash
ELFEX_BENCH_FILES=/usr/lib/llvm-19/lib/libLLVM.so.19.1:/usr/lib/x86_64-linux-gnu/libc.so.6 \
    cargo bench --manifest-path bench/Cargo.toml -- --save-baseline main
```

| Operation | `synthetic` | `libLLVM.so.19.1` | `libc.so.6` |
| --- | ---: | ---: | ---: |
| `headers_from_slice` | 856 ns ±8% | 2.6 µs ±6% | 2.72 µs ±2% |
| `file_parse` | 171 µs ±8% | 34.4 ms ±5% | 36.1 µs ±2% |
| `image_parse` | 337 µs ±51% | 32.4 ms ±1% | 51.6 µs ±3% |
| `dynamic_symbol_list` | 17.3 ms ±10% | 10.5 ms ±5% | 343 µs ±3% |
| `image_dynamic_symbol_list` | 16.2 ms ±10% | 17.2 ms ±4% | 363 µs ±3% |
| `linking_symbol_names` | 2.47 ms ±12% | 2.35 ms ±5% | 45.9 µs ±3% |
| `symbol_list` | 15.5 ms ±11% | 12.8 ns ±4% | 19 ns ±5% |
| `lookup_1000_cold` | 761 µs ±13% | 714 µs ±2% | 136 µs ±5% |
| `lookup_1000_warm` | 194 µs ±9% | 165 µs ±4% | 84.5 µs ±3% |
| `lookup_dynamic_symbol_16` | 10.3 ms ±3% | 9.31 ms ±3% | 522 µs ±2% |
| `dynamic_relocations` | 637 µs ±1% | 4.64 ms ±2% | 4.01 µs ±3% |
| `notes_build_id` | 117 ns ±1% | 188 ns ±2% | 258 ns ±1% |
| `file_try_build` | 177 µs ±13% | 29.3 ms ±3% | 33.6 µs ±2% |
| `to_mapped_image` | 199 µs ±9% | 30.5 ms ±4% | 45.2 µs ±0% |

## Heap

```bash
ELFEX_BENCH_FILES=/usr/lib/llvm-19/lib/libLLVM.so.19.1:/usr/lib/x86_64-linux-gnu/libc.so.6 \
    cargo run --release --manifest-path bench/Cargo.toml --bin memory
```

### synthetic (7.81 MiB)

| Operation | Peak | Allocated | Allocations |
| --- | ---: | ---: | ---: |
| `headers_from_slice` | 2.43 KiB | 4.41 KiB | 24 |
| `file_parse` | 7.81 MiB | 7.81 MiB | 25 |
| `image_parse` | 5.04 MiB | 5.04 MiB | 30 |
| `dynamic_symbol_list` | 12.49 MiB | 20.99 MiB | 103043 |
| `image_dynamic_symbol_list` | 15.12 MiB | 26.24 MiB | 103103 |
| `linking_symbol_names` | 3.25 MiB | 4.75 MiB | 19 |
| `symbol_list` | 11.69 MiB | 20.19 MiB | 50031 |
| `lookup_1000_cold` | 3.97 MiB | 6.13 MiB | 1871 |
| `lookup_1000_warm` | 44 B | 38.67 KiB | 1800 |
| `lookup_dynamic_symbol_16` | 3.97 MiB | 97.57 MiB | 1168 |
| `dynamic_relocations` | 2.00 MiB | 4.00 MiB | 19 |
| `notes_build_id` | 599 B | 1.16 KiB | 10 |
| `file_try_build` | 7.81 MiB | 7.81 MiB | 6 |
| `to_mapped_image` | 5.05 MiB | 5.05 MiB | 1 |

### libLLVM.so.19.1 (123.66 MiB)

| Operation | Peak | Allocated | Allocations |
| --- | ---: | ---: | ---: |
| `headers_from_slice` | 4.87 KiB | 9.07 KiB | 42 |
| `file_parse` | 123.67 MiB | 123.67 MiB | 43 |
| `image_parse` | 123.66 MiB | 123.67 MiB | 47 |
| `dynamic_symbol_list` | 16.24 MiB | 24.74 MiB | 105417 |
| `image_dynamic_symbol_list` | 32.83 MiB | 57.93 MiB | 105488 |
| `linking_symbol_names` | 5.11 MiB | 6.62 MiB | 21 |
| `symbol_list` | 0 B | 0 B | 0 |
| `lookup_1000_cold` | 5.78 MiB | 7.91 MiB | 1891 |
| `lookup_1000_warm` | 386 B | 72.19 KiB | 1800 |
| `lookup_dynamic_symbol_16` | 5.78 MiB | 125.58 MiB | 1488 |
| `dynamic_relocations` | 16.03 MiB | 32.06 MiB | 33 |
| `notes_build_id` | 611 B | 1.63 KiB | 16 |
| `file_try_build` | 123.66 MiB | 123.66 MiB | 6 |
| `to_mapped_image` | 124.28 MiB | 124.28 MiB | 1 |

### libc.so.6 (1.90 MiB)

| Operation | Peak | Allocated | Allocations |
| --- | ---: | ---: | ---: |
| `headers_from_slice` | 8.75 KiB | 17.36 KiB | 73 |
| `file_parse` | 1.91 MiB | 1.91 MiB | 74 |
| `image_parse` | 1.89 MiB | 1.90 MiB | 80 |
| `dynamic_symbol_list` | 663.55 KiB | 1.18 MiB | 6429 |
| `image_dynamic_symbol_list` | 683.55 KiB | 1.22 MiB | 6450 |
| `linking_symbol_names` | 130.69 KiB | 227.03 KiB | 16 |
| `symbol_list` | 0 B | 0 B | 0 |
| `lookup_1000_cold` | 166.06 KiB | 309.47 KiB | 1904 |
| `lookup_1000_warm` | 61 B | 20.84 KiB | 1800 |
| `lookup_dynamic_symbol_16` | 166.04 KiB | 4.51 MiB | 1696 |
| `dynamic_relocations` | 22.50 KiB | 44.67 KiB | 27 |
| `notes_build_id` | 637 B | 2.11 KiB | 22 |
| `file_try_build` | 1.90 MiB | 1.90 MiB | 6 |
| `to_mapped_image` | 1.95 MiB | 1.95 MiB | 1 |
