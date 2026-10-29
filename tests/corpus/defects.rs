//! The known defects of toolchain outputs in the corpus.
//!
//! For such a file, elfex reports an error correctly. The corpus check accepts the error, and
//! the summary shows the number of files with each accepted defect.

use elfex::{DynamicTag, ElfFile, Machine};

/// A defect of some toolchain outputs.
pub struct KnownDefect {
    /// The short name of the defect in the summary.
    pub name: &'static str,
    /// The text in each failure message that the defect causes.
    pub pattern: &'static str,
    /// Return `true` if the file has the defect.
    applies: fn(&ElfFile<&[u8]>) -> bool,
    /// The reason that the file, not elfex, is wrong.
    #[expect(dead_code, reason = "the reason documents the defect")]
    reason: &'static str,
}

/// All known defects.
const DEFECTS: [KnownDefect; 2] = [
    KnownDefect {
        name: "lld-s390x-dt-hash",
        pattern: "in DT_HASH",
        applies: lld_s390x_hash,
        reason: "the s390x ABI uses 8-byte DT_HASH entries (glibc Elf_Symndx, binutils and GNU \
                 readelf agree), but lld 19 writes 4-byte entries for EM_S390",
    },
    KnownDefect {
        name: "lld-ppc64-elfv1-entry",
        pattern: "code: EntryPointOutOfBounds",
        applies: lld_ppc64_elfv1,
        reason: "lld 19 links ELFv1 objects (with .opd function descriptors) but sets the ELFv2 \
                 flag in e_flags; then e_entry is a descriptor in a data segment, and the \
                 kernel jumps to it as code",
    },
];

/// Return the known defects of `file`.
pub fn known_defects(file: &ElfFile<&[u8]>) -> Vec<&'static KnownDefect> {
    DEFECTS
        .iter()
        .filter(|defect| (defect.applies)(file))
        .collect()
}

/// Return `true` if lld linked the ELF64 S/390 file with a `DT_HASH` table.
fn lld_s390x_hash(file: &ElfFile<&[u8]>) -> bool {
    file.machine() == Machine::S390
        && file.is_64bit()
        && linked_by_lld(file)
        && file
            .dynamic()
            .ok()
            .flatten()
            .is_some_and(|table| table.contains(DynamicTag::HASH))
}

/// Return `true` if lld linked an ELF64 PowerPC file with `.opd` and set the `ELFv2` flag.
fn lld_ppc64_elfv1(file: &ElfFile<&[u8]>) -> bool {
    file.machine() == Machine::PPC64
        && file.header().flags & 3 == 2
        && file.section_by_name(".opd").is_some()
        && linked_by_lld(file)
}

/// Return `true` if the `.comment` section names lld.
fn linked_by_lld(file: &ElfFile<&[u8]>) -> bool {
    file.section_data_by_name(".comment")
        .ok()
        .flatten()
        .is_some_and(|comment| comment.windows(4).any(|window| window == b"LLD "))
}
