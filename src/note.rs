//! ELF notes: `SHT_NOTE` sections and `PT_NOTE` segments.
//!
//! A note table is a sequence of note entries. Each entry has an `Elf32_Nhdr` or `Elf64_Nhdr`
//! header. The two headers are identical: three 32-bit words `n_namesz`, `n_descsz` and `n_type`.
//! The owner name and the descriptor follow the header.
//!
//! The meaning of a note type depends on the owner name. For example, type 1 is
//! [`NT_GNU_ABI_TAG`] for the owner `"GNU"` and [`NT_PRSTATUS`] for the owner `"CORE"`.
//!
//! - [`Note`] is one entry. [`NoteTable`] parses and writes a sequence of entries.
//! - The module also decodes GNU notes ([`GnuAbiTag`] and [`GnuProperty`]) and core file
//!   notes ([`FileMapping`] for `NT_FILE` and [`AuxvEntry`] for `NT_AUXV`).
//!
//! # Examples
//!
//! ```
//! use elfex::note::{ELF_NOTE_GNU, NT_GNU_BUILD_ID, Note, NoteTable};
//! use elfex::Encoding;
//!
//! let table = NoteTable {
//!     notes: vec![Note::gnu_build_id(vec![0xde, 0xad, 0xbe, 0xef])],
//! };
//! let bytes = table.write(Encoding::ELF64_LE, 4)?;
//! // The header (12 bytes), "GNU\0" (4 bytes) and the descriptor (4 bytes).
//! assert_eq!(bytes.len(), 20);
//!
//! let parsed = NoteTable::parse(&bytes, Encoding::ELF64_LE, 4)?;
//! assert_eq!(parsed, table);
//! assert!(parsed.notes[0].is(ELF_NOTE_GNU, NT_GNU_BUILD_ID));
//! assert_eq!(parsed.build_id(), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
//! # Ok::<(), elfex::Error>(())
//! ```

mod coredump;
mod gnu;

pub use coredump::*;
pub use gnu::*;

use crate::prelude::*;
use crate::{Encoding, Error, Result};

/// The owner name of GNU notes.
pub const ELF_NOTE_GNU: &[u8] = b"GNU";
/// The owner name of core file notes.
pub const ELF_NOTE_CORE: &[u8] = b"CORE";
/// The owner name of Linux-specific core file notes.
pub const ELF_NOTE_LINUX: &[u8] = b"LINUX";
/// The owner name of `FreeBSD` notes.
pub const ELF_NOTE_FREEBSD: &[u8] = b"FreeBSD";
/// The owner name of `NetBSD` notes.
pub const ELF_NOTE_NETBSD: &[u8] = b"NetBSD";
/// The owner name of Android notes.
pub const ELF_NOTE_ANDROID: &[u8] = b"Android";
/// The owner name of Go notes.
pub const ELF_NOTE_GO: &[u8] = b"Go";

/// `NT_GNU_ABI_TAG` (owner `"GNU"`): the minimum kernel ABI.
pub const NT_GNU_ABI_TAG: u32 = 1;
/// `NT_GNU_HWCAP` (owner `"GNU"`): hardware capabilities.
pub const NT_GNU_HWCAP: u32 = 2;
/// `NT_GNU_BUILD_ID` (owner `"GNU"`): the unique build ID.
pub const NT_GNU_BUILD_ID: u32 = 3;
/// `NT_GNU_GOLD_VERSION` (owner `"GNU"`): the gold linker version.
pub const NT_GNU_GOLD_VERSION: u32 = 4;
/// `NT_GNU_PROPERTY_TYPE_0` (owner `"GNU"`): program properties.
pub const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
/// `NT_GNU_BUILD_ATTRIBUTE_OPEN` (owner `"GA"` prefix): build attributes of a range.
pub const NT_GNU_BUILD_ATTRIBUTE_OPEN: u32 = 0x100;
/// `NT_GNU_BUILD_ATTRIBUTE_FUNC` (owner `"GA"` prefix): build attributes of a function.
pub const NT_GNU_BUILD_ATTRIBUTE_FUNC: u32 = 0x101;

/// `NT_PRSTATUS` (owner `"CORE"`): the `prstatus` structure of a thread.
pub const NT_PRSTATUS: u32 = 1;
/// `NT_PRFPREG` (owner `"CORE"`): the floating-point registers.
pub const NT_PRFPREG: u32 = 2;
/// `NT_PRPSINFO` (owner `"CORE"`): the `prpsinfo` structure of the process.
pub const NT_PRPSINFO: u32 = 3;
/// `NT_TASKSTRUCT` (owner `"CORE"`): the task structure.
pub const NT_TASKSTRUCT: u32 = 4;
/// `NT_AUXV` (owner `"CORE"`): the auxiliary vector.
pub const NT_AUXV: u32 = 6;
/// `NT_SIGINFO` (owner `"CORE"`): the `siginfo` of the signal.
pub const NT_SIGINFO: u32 = 0x5349_4749;
/// `NT_FILE` (owner `"CORE"`): the mapped files.
pub const NT_FILE: u32 = 0x4649_4c45;
/// `NT_PRXFPREG` (owner `"LINUX"`): the x86 extended floating-point registers.
pub const NT_PRXFPREG: u32 = 0x46e6_2b7f;
/// `NT_X86_XSTATE` (owner `"LINUX"`): the x86 `XSAVE` state.
pub const NT_X86_XSTATE: u32 = 0x202;
/// `NT_ARM_VFP` (owner `"LINUX"`): the ARM VFP registers.
pub const NT_ARM_VFP: u32 = 0x400;
/// `NT_ARM_TLS` (owner `"LINUX"`): the ARM TLS register.
pub const NT_ARM_TLS: u32 = 0x401;
/// `NT_ARM_HW_BREAK` (owner `"LINUX"`): the ARM hardware breakpoint registers.
pub const NT_ARM_HW_BREAK: u32 = 0x402;
/// `NT_ARM_HW_WATCH` (owner `"LINUX"`): the ARM hardware watchpoint registers.
pub const NT_ARM_HW_WATCH: u32 = 0x403;
/// `NT_ARM_SVE` (owner `"LINUX"`): the `AArch64` SVE registers.
pub const NT_ARM_SVE: u32 = 0x405;
/// `NT_ARM_PAC_MASK` (owner `"LINUX"`): the `AArch64` pointer authentication masks.
pub const NT_ARM_PAC_MASK: u32 = 0x406;
/// `NT_ARM_TAGGED_ADDR_CTRL` (owner `"LINUX"`): the `AArch64` tagged address control.
pub const NT_ARM_TAGGED_ADDR_CTRL: u32 = 0x409;

/// `NT_FREEBSD_ABI_TAG` (owner `"FreeBSD"`): the `FreeBSD` ABI version.
pub const NT_FREEBSD_ABI_TAG: u32 = 1;
/// `NT_NETBSD_IDENT` (owner `"NetBSD"`): the `NetBSD` version.
pub const NT_NETBSD_IDENT: u32 = 1;
/// `NT_ANDROID_TYPE_IDENT` (owner `"Android"`): the Android API level.
pub const NT_ANDROID_TYPE_IDENT: u32 = 1;
/// `NT_GO_BUILD_ID` (owner `"Go"`): the Go build ID.
pub const NT_GO_BUILD_ID: u32 = 4;

/// The size of an `Elf32_Nhdr` or `Elf64_Nhdr`.
const NOTE_HEADER_SIZE: usize = 12;

/// One note entry (`Elf32_Nhdr` or `Elf64_Nhdr` with its name and descriptor).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Note {
    /// The owner name, without the terminating NUL.
    pub name: Vec<u8>,
    /// The note type (`n_type`). Its meaning depends on the owner name.
    pub n_type: u32,
    /// The descriptor bytes, without padding.
    pub desc: Vec<u8>,
}

impl Note {
    /// Create a note.
    #[must_use]
    pub fn new(name: impl Into<Vec<u8>>, note_type: u32, desc: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            n_type: note_type,
            desc: desc.into(),
        }
    }

    /// Create a GNU `NT_GNU_BUILD_ID` note with the build ID `id`.
    #[must_use]
    pub fn gnu_build_id(id: Vec<u8>) -> Self {
        Self::new(ELF_NOTE_GNU, NT_GNU_BUILD_ID, id)
    }

    /// Return the owner name as UTF-8, or `None` if it is not valid UTF-8.
    #[must_use]
    pub fn name_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.name).ok()
    }

    /// Return `true` if the owner name is `name` and the type is `note_type`.
    #[must_use]
    pub fn is(&self, name: &[u8], note_type: u32) -> bool {
        self.name == name && self.n_type == note_type
    }

    /// Return the specification name of the note type, for example `"NT_GNU_BUILD_ID"`.
    ///
    /// The name depends on the owner name. The function knows the `NT_*` constants of this
    /// module for these owners:
    ///
    /// - `"GNU"`, and an owner that starts with `"GA"` for the build attribute notes.
    /// - `"CORE"` and `"LINUX"`. Both owners use the same core file note types.
    /// - `"FreeBSD"`, `"NetBSD"`, `"Android"` and `"Go"`.
    ///
    /// Return `None` for another owner or an unknown type.
    ///
    /// # Examples
    ///
    /// ```
    /// use elfex::note::{ELF_NOTE_CORE, ELF_NOTE_GNU, NT_GNU_ABI_TAG, Note};
    ///
    /// let note = Note::new(ELF_NOTE_GNU, NT_GNU_ABI_TAG, [0; 16]);
    /// assert_eq!(note.type_name(), Some("NT_GNU_ABI_TAG"));
    /// // Type 1 has a different meaning for the owner "CORE".
    /// assert_eq!(Note::new(ELF_NOTE_CORE, 1, []).type_name(), Some("NT_PRSTATUS"));
    /// assert_eq!(Note::new("other", 1, []).type_name(), None);
    /// ```
    #[must_use]
    pub fn type_name(&self) -> Option<&'static str> {
        let name = self.name.as_slice();
        if name == ELF_NOTE_GNU {
            gnu_type_name(self.n_type)
        } else if name.starts_with(b"GA") {
            match self.n_type {
                NT_GNU_BUILD_ATTRIBUTE_OPEN => Some("NT_GNU_BUILD_ATTRIBUTE_OPEN"),
                NT_GNU_BUILD_ATTRIBUTE_FUNC => Some("NT_GNU_BUILD_ATTRIBUTE_FUNC"),
                _ => None,
            }
        } else if name == ELF_NOTE_CORE || name == ELF_NOTE_LINUX {
            core_type_name(self.n_type)
        } else {
            let known = match name {
                ELF_NOTE_FREEBSD => (NT_FREEBSD_ABI_TAG, "NT_FREEBSD_ABI_TAG"),
                ELF_NOTE_NETBSD => (NT_NETBSD_IDENT, "NT_NETBSD_IDENT"),
                ELF_NOTE_ANDROID => (NT_ANDROID_TYPE_IDENT, "NT_ANDROID_TYPE_IDENT"),
                ELF_NOTE_GO => (NT_GO_BUILD_ID, "NT_GO_BUILD_ID"),
                _ => return None,
            };
            (self.n_type == known.0).then_some(known.1)
        }
    }

    /// Decode the descriptor of a GNU `NT_GNU_ABI_TAG` note.
    ///
    /// Return `None` if the note is not a GNU ABI tag note.
    #[must_use]
    pub fn gnu_abi_tag(&self, encoding: Encoding) -> Option<Result<GnuAbiTag>> {
        self.is(ELF_NOTE_GNU, NT_GNU_ABI_TAG)
            .then(|| GnuAbiTag::parse(&self.desc, encoding))
    }

    /// Decode the descriptor of a GNU `NT_GNU_PROPERTY_TYPE_0` note.
    ///
    /// Return `None` if the note is not a GNU property note.
    #[must_use]
    pub fn gnu_properties(&self, encoding: Encoding) -> Option<Result<Vec<GnuProperty>>> {
        self.is(ELF_NOTE_GNU, NT_GNU_PROPERTY_TYPE_0)
            .then(|| parse_gnu_properties(&self.desc, encoding))
    }
}

/// Return the name of a GNU note type.
const fn gnu_type_name(note_type: u32) -> Option<&'static str> {
    Some(match note_type {
        NT_GNU_ABI_TAG => "NT_GNU_ABI_TAG",
        NT_GNU_HWCAP => "NT_GNU_HWCAP",
        NT_GNU_BUILD_ID => "NT_GNU_BUILD_ID",
        NT_GNU_GOLD_VERSION => "NT_GNU_GOLD_VERSION",
        NT_GNU_PROPERTY_TYPE_0 => "NT_GNU_PROPERTY_TYPE_0",
        _ => return None,
    })
}

/// Return the name of a core file note type (owner `"CORE"` or `"LINUX"`).
const fn core_type_name(note_type: u32) -> Option<&'static str> {
    Some(match note_type {
        NT_PRSTATUS => "NT_PRSTATUS",
        NT_PRFPREG => "NT_PRFPREG",
        NT_PRPSINFO => "NT_PRPSINFO",
        NT_TASKSTRUCT => "NT_TASKSTRUCT",
        NT_AUXV => "NT_AUXV",
        NT_SIGINFO => "NT_SIGINFO",
        NT_FILE => "NT_FILE",
        NT_PRXFPREG => "NT_PRXFPREG",
        NT_X86_XSTATE => "NT_X86_XSTATE",
        NT_ARM_VFP => "NT_ARM_VFP",
        NT_ARM_TLS => "NT_ARM_TLS",
        NT_ARM_HW_BREAK => "NT_ARM_HW_BREAK",
        NT_ARM_HW_WATCH => "NT_ARM_HW_WATCH",
        NT_ARM_SVE => "NT_ARM_SVE",
        NT_ARM_PAC_MASK => "NT_ARM_PAC_MASK",
        NT_ARM_TAGGED_ADDR_CTRL => "NT_ARM_TAGGED_ADDR_CTRL",
        _ => return None,
    })
}

/// Convert a note alignment (`sh_addralign` or `p_align`) to the entry alignment: 4 or 8.
fn note_align(align: u64) -> Result<usize> {
    match align {
        0..=4 => Ok(4),
        8 => Ok(8),
        _ => Err(Error::invalid_table(format!(
            "unsupported note alignment {align}"
        ))),
    }
}

/// Round `value` up to a multiple of `align` (a power of two), or return `None` on overflow.
fn align_up(value: usize, align: usize) -> Option<usize> {
    Some(value.checked_add(align - 1)? & !(align - 1))
}

/// A table of notes (the contents of an `SHT_NOTE` section or a `PT_NOTE` segment).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NoteTable {
    /// The notes, in file order.
    pub notes: Vec<Note>,
}

impl NoteTable {
    /// Parse a note table.
    ///
    /// `align` is the `sh_addralign` or `p_align` value: 0 to 4 select 4-byte alignment, 8 selects
    /// 8-byte alignment. The descriptor starts at the first aligned offset after the header and
    /// the name, and the next entry starts at the first aligned offset after the descriptor
    /// (the layout that the GNU tools use).
    ///
    /// When all the remaining bytes are zero, the parser stops: these bytes are padding, not
    /// entries. Thus, an entry with all header fields zero is a note only if non-zero bytes
    /// follow it.
    ///
    /// # Errors
    ///
    /// Return [`crate::ErrorKind::InvalidTable`] if `align` is not supported, or if an entry is
    /// truncated.
    pub fn parse(bytes: &[u8], encoding: Encoding, align: u64) -> Result<Self> {
        let align = note_align(align)?;
        let mut notes = Vec::new();
        let mut pos = 0usize;
        while pos < bytes.len() {
            let rest = &bytes[pos..];
            if rest.iter().all(|b| *b == 0) {
                break;
            }
            if rest.len() < NOTE_HEADER_SIZE {
                return Err(Self::truncated(pos));
            }
            let (note, size) = Self::parse_entry(rest, encoding, align)
                .map_err(|e| e.in_structure("Elf_Nhdr").at_offset(pos as u64))?;
            notes.push(note);
            pos = pos.saturating_add(size);
        }
        Ok(Self { notes })
    }

    /// Return a truncated-entry error at `pos`.
    fn truncated(pos: usize) -> Error {
        Error::invalid_table("truncated note entry")
            .in_structure("Elf_Nhdr")
            .at_offset(pos as u64)
    }

    /// Parse one entry at the start of `rest`. Return the note and the padded entry size.
    fn parse_entry(rest: &[u8], encoding: Encoding, align: usize) -> Result<(Note, usize)> {
        let truncated = || Error::invalid_table("truncated note entry");
        // A `usize` has at least 32 bits, so the sizes convert without loss.
        let namesz = usize::try_from(encoding.read_u32(rest, 0)?).unwrap_or(usize::MAX);
        let descsz = usize::try_from(encoding.read_u32(rest, 4)?).unwrap_or(usize::MAX);
        let note_type = encoding.read_u32(rest, 8)?;
        let name_end = NOTE_HEADER_SIZE.checked_add(namesz).ok_or_else(truncated)?;
        let raw_name = rest.get(NOTE_HEADER_SIZE..name_end).ok_or_else(truncated)?;
        let name = match raw_name.iter().position(|b| *b == 0) {
            Some(nul) => &raw_name[..nul],
            None => raw_name,
        };
        let desc_start = align_up(name_end, align).ok_or_else(truncated)?;
        let desc_end = desc_start.checked_add(descsz).ok_or_else(truncated)?;
        let desc = rest.get(desc_start..desc_end).ok_or_else(truncated)?;
        // Padding after the last descriptor can be missing.
        let next = align_up(desc_end, align)
            .ok_or_else(truncated)?
            .min(rest.len());
        Ok((Note::new(name, note_type, desc), next))
    }

    /// Serialize the note table with entries aligned to `align` (see [`NoteTable::parse`]).
    ///
    /// A non-empty name is written with a terminating NUL. An empty name has `n_namesz` 0.
    ///
    /// # Errors
    ///
    /// - Return [`crate::ErrorKind::InvalidTable`] if `align` is not supported.
    /// - Return [`crate::ErrorKind::ValueOutOfRange`] if a name or descriptor size does not fit
    ///   in 32 bits.
    pub fn write(&self, encoding: Encoding, align: u64) -> Result<Vec<u8>> {
        let align = note_align(align)?;
        let mut out = Vec::new();
        for note in &self.notes {
            let namesz = if note.name.is_empty() {
                0
            } else {
                note.name.len().saturating_add(1)
            };
            let namesz = u32::try_from(namesz)
                .map_err(|_| Error::value_out_of_range("note name is too long"))?;
            let descsz = u32::try_from(note.desc.len())
                .map_err(|_| Error::value_out_of_range("note descriptor is too long"))?;
            let start = out.len();
            encoding.write_u32(&mut out, namesz);
            encoding.write_u32(&mut out, descsz);
            encoding.write_u32(&mut out, note.n_type);
            if namesz != 0 {
                out.extend_from_slice(&note.name);
                out.push(0);
            }
            Self::pad(&mut out, start, align);
            out.extend_from_slice(&note.desc);
            Self::pad(&mut out, start, align);
        }
        Ok(out)
    }

    /// Append zero bytes until the length from `start` is a multiple of `align`.
    fn pad(out: &mut Vec<u8>, start: usize, align: usize) {
        while !(out.len() - start).is_multiple_of(align) {
            out.push(0);
        }
    }

    /// Return an iterator over the notes.
    pub fn iter(&self) -> core::slice::Iter<'_, Note> {
        self.notes.iter()
    }

    /// Return the first note with the owner name `name` and the type `note_type`.
    #[must_use]
    pub fn find(&self, name: &[u8], note_type: u32) -> Option<&Note> {
        self.notes.iter().find(|n| n.is(name, note_type))
    }

    /// Return the descriptor of the GNU `NT_GNU_BUILD_ID` note.
    #[must_use]
    pub fn build_id(&self) -> Option<&[u8]> {
        self.find(ELF_NOTE_GNU, NT_GNU_BUILD_ID)
            .map(|n| n.desc.as_slice())
    }
}

impl<'a> IntoIterator for &'a NoteTable {
    type Item = &'a Note;
    type IntoIter = core::slice::Iter<'a, Note>;

    fn into_iter(self) -> Self::IntoIter {
        self.notes.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    const ALL: [Encoding; 4] = [
        Encoding::ELF32_LE,
        Encoding::ELF32_BE,
        Encoding::ELF64_LE,
        Encoding::ELF64_BE,
    ];

    fn sample() -> NoteTable {
        NoteTable {
            notes: vec![
                Note::gnu_build_id(vec![0xde, 0xad, 0xbe, 0xef, 0x01]),
                Note::new(b"", 7, vec![1, 2, 3]),
                Note::new(b"CORE", NT_PRSTATUS, vec![9; 13]),
                Note::new(b"Go", NT_GO_BUILD_ID, Vec::new()),
            ],
        }
    }

    #[test]
    fn names_note_types_by_owner() {
        let name = |owner: &[u8], note_type| Note::new(owner, note_type, []).type_name();
        assert_eq!(name(ELF_NOTE_GNU, NT_GNU_BUILD_ID), Some("NT_GNU_BUILD_ID"));
        assert_eq!(
            name(ELF_NOTE_GNU, NT_GNU_PROPERTY_TYPE_0),
            Some("NT_GNU_PROPERTY_TYPE_0")
        );
        assert_eq!(name(ELF_NOTE_GNU, NT_FILE), None);
        assert_eq!(
            name(b"GA$\x013a1", NT_GNU_BUILD_ATTRIBUTE_OPEN),
            Some("NT_GNU_BUILD_ATTRIBUTE_OPEN")
        );
        assert_eq!(name(b"GA$\x013a1", NT_GNU_BUILD_ID), None);
        // Type 1 has a different name for each owner.
        assert_eq!(name(ELF_NOTE_CORE, 1), Some("NT_PRSTATUS"));
        assert_eq!(name(ELF_NOTE_LINUX, 1), Some("NT_PRSTATUS"));
        assert_eq!(name(ELF_NOTE_LINUX, NT_X86_XSTATE), Some("NT_X86_XSTATE"));
        assert_eq!(name(ELF_NOTE_CORE, NT_FILE), Some("NT_FILE"));
        assert_eq!(name(ELF_NOTE_FREEBSD, 1), Some("NT_FREEBSD_ABI_TAG"));
        assert_eq!(name(ELF_NOTE_NETBSD, 1), Some("NT_NETBSD_IDENT"));
        assert_eq!(name(ELF_NOTE_ANDROID, 1), Some("NT_ANDROID_TYPE_IDENT"));
        assert_eq!(name(ELF_NOTE_GO, NT_GO_BUILD_ID), Some("NT_GO_BUILD_ID"));
        assert_eq!(name(ELF_NOTE_GO, 1), None);
        assert_eq!(name(ELF_NOTE_CORE, 0x9999), None);
        assert_eq!(name(b"", 1), None);
        assert_eq!(name(b"Xen", 1), None);
    }

    #[test]
    fn round_trip_all_encodings_and_alignments() {
        for encoding in ALL {
            for align in [0, 4, 8] {
                let table = sample();
                let bytes = table.write(encoding, align).unwrap();
                let a = if align == 8 { 8 } else { 4 };
                assert_eq!(bytes.len() % a, 0);
                assert_eq!(NoteTable::parse(&bytes, encoding, align).unwrap(), table);
            }
        }
    }

    #[test]
    fn parse_hand_written_build_id() {
        let bytes = [
            4, 0, 0, 0, // namesz
            4, 0, 0, 0, // descsz
            3, 0, 0, 0, // NT_GNU_BUILD_ID
            b'G', b'N', b'U', 0, // name
            0x12, 0x34, 0x56, 0x78, // desc
            0, 0, 0, 0, // trailing padding
        ];
        let table = NoteTable::parse(&bytes, Encoding::ELF64_LE, 4).unwrap();
        assert_eq!(table.notes.len(), 1);
        assert_eq!(table.notes[0].name_str(), Some("GNU"));
        assert_eq!(table.build_id(), Some(&[0x12, 0x34, 0x56, 0x78][..]));
        assert_eq!(table.write(Encoding::ELF64_LE, 4).unwrap(), bytes[..20]);
    }

    #[test]
    fn parse_big_endian_header() {
        let bytes = [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 9, 0xaa, 0, 0, 0];
        let table = NoteTable::parse(&bytes, Encoding::ELF32_BE, 4).unwrap();
        assert_eq!(table.notes, [Note::new(b"", 9, vec![0xaa])]);
    }

    #[test]
    fn empty_name() {
        let table = NoteTable {
            notes: vec![Note::new(b"", 1, vec![5, 6, 7, 8])],
        };
        let bytes = table.write(Encoding::ELF32_LE, 4).unwrap();
        assert_eq!(bytes, [0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 5, 6, 7, 8]);
        let parsed = NoteTable::parse(&bytes, Encoding::ELF32_LE, 4).unwrap();
        assert_eq!(parsed, table);
        assert_eq!(parsed.notes[0].name_str(), Some(""));
    }

    #[test]
    fn trailing_zero_bytes_are_padding() {
        let mut bytes = vec![
            4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0, b'G', b'N', b'U', 0, 1, 2, 3, 4,
        ];
        for count in [12, 16, 64] {
            bytes.resize(20 + count, 0);
            let table = NoteTable::parse(&bytes, Encoding::ELF64_LE, 4).unwrap();
            assert_eq!(table.notes.len(), 1, "{count} trailing zero bytes");
        }
        // A note with all header fields zero is a note if a non-zero entry follows it.
        let mut bytes = vec![0; 12];
        bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0]);
        let table = NoteTable::parse(&bytes, Encoding::ELF64_LE, 4).unwrap();
        assert_eq!(
            table.notes,
            [Note::new(b"", 0, vec![]), Note::new(b"", 7, vec![])]
        );
    }

    #[test]
    fn truncated_entries_error() {
        let bytes = sample().write(Encoding::ELF64_LE, 4).unwrap();
        // Cut inside the descriptor of the first note.
        let err = NoteTable::parse(&bytes[..18], Encoding::ELF64_LE, 4).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        // A short non-zero header.
        let err = NoteTable::parse(&[1, 0, 0], Encoding::ELF64_LE, 4).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        // A huge name size.
        let bytes = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 1, 0, 0, 0];
        let err = NoteTable::parse(&bytes, Encoding::ELF64_LE, 4).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn bad_alignment() {
        let err = NoteTable::parse(&[], Encoding::ELF64_LE, 16).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        assert!(NoteTable::default().write(Encoding::ELF64_LE, 2).is_ok());
    }

    #[test]
    fn find_and_iter() {
        let table = sample();
        assert_eq!(table.iter().count(), 4);
        assert!(table.find(ELF_NOTE_CORE, NT_PRSTATUS).is_some());
        assert!(table.find(ELF_NOTE_GNU, NT_PRSTATUS).is_none());
        assert_eq!((&table).into_iter().count(), 4);
    }
}
