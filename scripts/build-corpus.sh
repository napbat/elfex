#!/usr/bin/env bash
# Build a corpus of ELF samples for the compatibility test (`tests/corpus`).
#
# Usage: scripts/build-corpus.sh <output-directory>
#
# The script needs clang and ld.lld. It uses the GNU cross compilers and qemu when they are
# installed, and skips them when they are not. It never fails because one target is not
# available: it prints a note and continues.
set -u

out="${1:?usage: build-corpus.sh <output-directory>}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

note() { printf '%s\n' "$*" >&2; }

cat >"$work/lib.c" <<'EOF'
extern int imported_function(int);
extern int imported_data;
int exported_data = 42;
int *data_pointer = &exported_data;
int (*function_pointer)(int) = imported_function;
__thread int thread_local_value = 7;
static int counter;
__attribute__((constructor)) static void initialize(void) { counter = 1; }
__attribute__((destructor)) static void finalize(void) { counter = 0; }
__attribute__((weak)) int weak_function(void) { return 3; }
__attribute__((visibility("hidden"))) int hidden_function(void) { return counter; }
int exported_function(int value) {
    return imported_function(value) + imported_data + thread_local_value + hidden_function();
}
int versioned_function_v1(void) { return 1; }
int versioned_function_v2(void) { return 2; }
__asm__(".symver versioned_function_v1, versioned_function@VERS_1");
__asm__(".symver versioned_function_v2, versioned_function@@VERS_2");
EOF

cat >"$work/lib.map" <<'EOF'
VERS_1 { global: exported_function; exported_data; data_pointer; function_pointer;
         weak_function; thread_local_value; local: *; };
VERS_2 { global: versioned_function; } VERS_1;
EOF

cat >"$work/start.c" <<'EOF'
static const char message[] = "elfex";
const char *volatile message_pointer = message;
void _start(void) { for (;;) { } }
EOF

# The pointers keep the template instances and the inline function, so that each one gets a
# COMDAT section group. The static local gives a group with more than one member.
cat >"$work/comdat.cpp" <<'EOF'
template <typename T> T twice(T value) { return value + value; }
inline int &shared_counter() { static int value; return value; }
int (*twice_int)(int) = &twice<int>;
long (*twice_long)(long) = &twice<long>;
int &(*counter_function)() = &shared_counter;
EOF

# Clang target triples. Each one gives an object file, shared objects in several linker
# configurations and a static executable.
triples=(
    x86_64-linux-gnu i686-linux-gnu aarch64-linux-gnu aarch64_be-linux-gnu
    armv7-linux-gnueabihf armeb-linux-gnueabi riscv64-linux-gnu riscv32-linux-gnu
    powerpc-linux-gnu powerpc64-linux-gnu powerpc64le-linux-gnu mips-linux-gnu
    mipsel-linux-gnu mips64-linux-gnuabi64 mips64el-linux-gnuabi64 s390x-linux-gnu
    loongarch64-linux-gnu hexagon-linux-musl sparcv9-linux-gnu
)

for triple in "${triples[@]}"; do
    dir="$out/clang/$triple"
    mkdir -p "$dir"
    cflags=(--target="$triple" -O1 -fPIC -ffunction-sections -fdata-sections -nostdlib)
    if ! clang "${cflags[@]}" -c "$work/lib.c" -o "$dir/lib.o" 2>"$work/err"; then
        note "skip $triple: $(head -1 "$work/err")"
        rm -rf "$dir"
        continue
    fi
    clang "${cflags[@]}" -g -c "$work/lib.c" -o "$dir/lib-debug.o" 2>/dev/null || true
    clang++ "${cflags[@]}" -c "$work/comdat.cpp" -o "$dir/comdat.o" 2>/dev/null || true
    link() {
        local name="$1"
        shift
        ld.lld -shared --build-id -z relro -z now --version-script "$work/lib.map" \
            -soname "lib$name.so" "$@" "$dir/lib.o" -o "$dir/lib$name.so" 2>"$work/err" ||
            note "skip $triple lib$name.so: $(head -1 "$work/err")"
    }
    # MIPS does not support `.gnu.hash`.
    gnu=gnu
    case "$triple" in mips*) gnu=sysv ;; esac
    link both --hash-style=both
    link gnu --hash-style="$gnu"
    link sysv --hash-style=sysv
    link separate --hash-style="$gnu" -z separate-code
    link relr --hash-style="$gnu" --pack-dyn-relocs=relr
    link pagesize64k --hash-style="$gnu" -z max-page-size=65536
    link stripped --hash-style="$gnu" --strip-all
    clang "${cflags[@]}" -fno-PIC -c "$work/start.c" -o "$work/start.o" 2>/dev/null &&
        ld.lld -static -e _start "$work/start.o" -o "$dir/static" 2>/dev/null || true
    clang "${cflags[@]}" -c "$work/start.c" -o "$work/start-pic.o" 2>/dev/null &&
        ld.lld -pie -e _start --hash-style="$gnu" "$work/start-pic.o" -o "$dir/static-pie" \
            2>/dev/null || true
done

# Compressed debug sections (SHF_COMPRESSED).
dir="$out/clang/compressed"
mkdir -p "$dir"
clang --target=x86_64-linux-gnu -g -gz=zlib -fPIC -c "$work/lib.c" -o "$dir/zlib.o" 2>/dev/null || true
clang --target=x86_64-linux-gnu -g -gz=zstd -fPIC -c "$work/lib.c" -o "$dir/zstd.o" 2>/dev/null || true

# Pointer tables for the Android packed relocations. lld puts runs of relative relocations
# and runs of relocations with the same symbol in groups that share values.
{
    printf 'static int values[48];\nextern int imported_value;\n'
    printf 'int *value_pointers[48] = {'
    for i in $(seq 0 47); do printf '&values[%d], ' "$i"; done
    printf '};\nint *imported_pointers[12] = {'
    for i in $(seq 0 11); do printf '&imported_value + %d, ' "$i"; done
    printf '};\n'
} >"$work/packed.c"

# Android shared objects with packed relocations: SHT_ANDROID_REL (Arm) or SHT_ANDROID_RELA
# (AArch64), with SHT_RELR or SHT_ANDROID_RELR for the relative relocations.
for triple in aarch64-linux-android29 armv7-linux-androideabi29; do
    dir="$out/android/$triple"
    mkdir -p "$dir"
    cflags=(--target="$triple" -O1 -fPIC -ffunction-sections -fdata-sections -nostdlib)
    if ! clang "${cflags[@]}" -c "$work/lib.c" -o "$dir/lib.o" 2>"$work/err" ||
        ! clang "${cflags[@]}" -c "$work/packed.c" -o "$dir/packed.o" 2>"$work/err"; then
        note "skip $triple: $(head -1 "$work/err")"
        rm -rf "$dir"
        continue
    fi
    android_link() {
        local name="$1"
        shift
        ld.lld -shared --build-id -z relro -z now --version-script "$work/lib.map" \
            --hash-style=both -soname "lib$name.so" "$@" "$dir/lib.o" "$dir/packed.o" \
            -o "$dir/lib$name.so" 2>"$work/err" ||
            note "skip $triple lib$name.so: $(head -1 "$work/err")"
    }
    android_link android --pack-dyn-relocs=android
    android_link android-relr --pack-dyn-relocs=android+relr
    android_link android-relr-tags --pack-dyn-relocs=android+relr --use-android-relr-tags
done

# Objects with CREL relocation sections (SHT_CREL). LLVM 19 needs the experimental flag.
for triple in x86_64-linux-gnu aarch64-linux-gnu; do
    dir="$out/crel/$triple"
    mkdir -p "$dir"
    crel=(--target="$triple" -O1 -fPIC -ffunction-sections -fdata-sections -nostdlib)
    crel+=(-Wa,--crel,--allow-experimental-crel)
    if ! clang "${crel[@]}" -c "$work/lib.c" -o "$dir/lib.o" 2>"$work/err"; then
        note "skip CREL for $triple: $(head -1 "$work/err")"
        rm -rf "$dir"
        continue
    fi
    clang "${crel[@]}" -g -c "$work/lib.c" -o "$dir/lib-debug.o" 2>/dev/null || true
    clang "${crel[@]}" -c "$work/packed.c" -o "$dir/packed.o" 2>/dev/null || true
    clang++ "${crel[@]}" -c "$work/comdat.cpp" -o "$dir/comdat.o" 2>/dev/null || true
done

# Native and GNU cross toolchains with a C library: these programs run.
cat >"$work/hello.c" <<'EOF'
#include <stdio.h>
int main(void) { puts("hello from elfex"); return 0; }
EOF
gnu_build() {
    local compiler="$1" name="$2"
    command -v "$compiler" >/dev/null || { note "skip $compiler: not installed"; return; }
    local dir="$out/gnu/$name"
    mkdir -p "$dir"
    "$compiler" -O1 "$work/hello.c" -o "$dir/hello-pie" 2>/dev/null || true
    "$compiler" -O1 -no-pie "$work/hello.c" -o "$dir/hello-nopie" 2>/dev/null || true
    "$compiler" -O1 -static "$work/hello.c" -o "$dir/hello-static" 2>/dev/null || true
    "$compiler" -O1 -static-pie "$work/hello.c" -o "$dir/hello-static-pie" 2>/dev/null || true
    "$compiler" -O1 -g "$work/hello.c" -o "$dir/hello-debug" 2>/dev/null || true
    "$compiler" -O1 -fPIC -shared "$work/lib.c" -Wl,--version-script="$work/lib.map" \
        -Wl,--allow-shlib-undefined -o "$dir/liblib.so" 2>/dev/null || true
}
gnu_build gcc x86_64
gnu_build aarch64-linux-gnu-gcc aarch64
gnu_build powerpc64le-linux-gnu-gcc powerpc64le

# A core file of a native process.
if [ -x "$out/gnu/x86_64/hello-pie" ]; then
    mkdir -p "$out/core"
    (
        cd "$out/core" || exit
        ulimit -c unlimited
        sh -c 'kill -SEGV $$' 2>/dev/null
        python3 -c 'import os; os.abort()' 2>/dev/null
    ) || true
    find "$out/core" -type f -name 'core*' | head -2 | while read -r file; do
        chmod a+r "$file"
    done
fi
printf 'corpus: %s files in %s\n' "$(find "$out" -type f | wc -l)" "$out"
