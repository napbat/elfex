//! GNU note descriptors: the ABI tag (`NT_GNU_ABI_TAG`) and program properties
//! (`NT_GNU_PROPERTY_TYPE_0`).

use crate::prelude::*;
use crate::{Encoding, Error, Result};

/// `GNU_ABI_TAG_LINUX`: the ABI tag operating system Linux.
pub const GNU_ABI_TAG_LINUX: u32 = 0;
/// `GNU_ABI_TAG_HURD`: the ABI tag operating system GNU Hurd.
pub const GNU_ABI_TAG_HURD: u32 = 1;
/// `GNU_ABI_TAG_SOLARIS`: the ABI tag operating system Solaris.
pub const GNU_ABI_TAG_SOLARIS: u32 = 2;
/// `GNU_ABI_TAG_FREEBSD`: the ABI tag operating system `FreeBSD`.
pub const GNU_ABI_TAG_FREEBSD: u32 = 3;
/// `GNU_ABI_TAG_NETBSD`: the ABI tag operating system `NetBSD`.
pub const GNU_ABI_TAG_NETBSD: u32 = 4;
/// `GNU_ABI_TAG_SYLLABLE`: the ABI tag operating system Syllable.
pub const GNU_ABI_TAG_SYLLABLE: u32 = 5;
/// `GNU_ABI_TAG_NACL`: the ABI tag operating system Native Client.
pub const GNU_ABI_TAG_NACL: u32 = 6;

/// `GNU_PROPERTY_STACK_SIZE`: the stack size (class-sized value).
pub const GNU_PROPERTY_STACK_SIZE: u32 = 1;
/// `GNU_PROPERTY_NO_COPY_ON_PROTECTED`: no copy relocations on protected data symbols.
pub const GNU_PROPERTY_NO_COPY_ON_PROTECTED: u32 = 2;
/// `GNU_PROPERTY_1_NEEDED`: bits of features that the object needs.
pub const GNU_PROPERTY_1_NEEDED: u32 = 0xb000_8000;
/// `GNU_PROPERTY_X86_FEATURE_1_AND`: x86 features (`GNU_PROPERTY_X86_FEATURE_1_*` bits).
pub const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
/// `GNU_PROPERTY_X86_ISA_1_NEEDED`: x86 ISA levels that the object needs.
pub const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc000_8002;
/// `GNU_PROPERTY_X86_ISA_1_USED`: x86 ISA levels that the object uses.
pub const GNU_PROPERTY_X86_ISA_1_USED: u32 = 0xc001_0002;
/// `GNU_PROPERTY_AARCH64_FEATURE_1_AND`: `AArch64` features (`GNU_PROPERTY_AARCH64_FEATURE_1_*`).
pub const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
/// `GNU_PROPERTY_RISCV_FEATURE_1_AND`: RISC-V features (`GNU_PROPERTY_RISCV_FEATURE_1_*`).
///
/// This value is the same as [`GNU_PROPERTY_AARCH64_FEATURE_1_AND`]: the meaning depends on
/// the machine.
pub const GNU_PROPERTY_RISCV_FEATURE_1_AND: u32 = 0xc000_0000;

/// `GNU_PROPERTY_X86_FEATURE_1_IBT`: indirect branch tracking.
pub const GNU_PROPERTY_X86_FEATURE_1_IBT: u32 = 1;
/// `GNU_PROPERTY_X86_FEATURE_1_SHSTK`: shadow stack.
pub const GNU_PROPERTY_X86_FEATURE_1_SHSTK: u32 = 2;
/// `GNU_PROPERTY_AARCH64_FEATURE_1_BTI`: branch target identification.
pub const GNU_PROPERTY_AARCH64_FEATURE_1_BTI: u32 = 1;
/// `GNU_PROPERTY_AARCH64_FEATURE_1_PAC`: pointer authentication.
pub const GNU_PROPERTY_AARCH64_FEATURE_1_PAC: u32 = 2;
/// `GNU_PROPERTY_AARCH64_FEATURE_1_GCS`: guarded control stack.
pub const GNU_PROPERTY_AARCH64_FEATURE_1_GCS: u32 = 4;
/// `GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED`: unlabeled landing pads.
pub const GNU_PROPERTY_RISCV_FEATURE_1_CFI_LP_UNLABELED: u32 = 1;
/// `GNU_PROPERTY_RISCV_FEATURE_1_CFI_SS`: shadow stack.
pub const GNU_PROPERTY_RISCV_FEATURE_1_CFI_SS: u32 = 2;

/// The descriptor of a GNU `NT_GNU_ABI_TAG` note: four 32-bit words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct GnuAbiTag {
    /// The operating system (`GNU_ABI_TAG_*`).
    pub os: u32,
    /// The major version of the minimum ABI.
    pub major: u32,
    /// The minor version of the minimum ABI.
    pub minor: u32,
    /// The subminor version of the minimum ABI.
    pub subminor: u32,
}

impl GnuAbiTag {
    /// Parse an `NT_GNU_ABI_TAG` descriptor.
    ///
    /// # Errors
    ///
    /// Return [`crate::ErrorKind::InvalidTable`] if the descriptor is shorter than 16 bytes.
    pub fn parse(desc: &[u8], encoding: Encoding) -> Result<Self> {
        let word = |i: usize| {
            encoding.read_u32(desc, i * 4).map_err(|_| {
                Error::invalid_table("truncated GNU ABI tag").in_structure("NT_GNU_ABI_TAG")
            })
        };
        Ok(Self {
            os: word(0)?,
            major: word(1)?,
            minor: word(2)?,
            subminor: word(3)?,
        })
    }

    /// Serialize the descriptor (16 bytes).
    #[must_use]
    pub fn to_bytes(self, encoding: Encoding) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        for v in [self.os, self.major, self.minor, self.subminor] {
            encoding.write_u32(&mut out, v);
        }
        out
    }
}

/// One GNU program property in an `NT_GNU_PROPERTY_TYPE_0` descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GnuProperty {
    /// The property type (`pr_type`, `GNU_PROPERTY_*`).
    pub pr_type: u32,
    /// The property data (`pr_datasz` bytes, without padding).
    pub data: Vec<u8>,
}

impl GnuProperty {
    /// Create a property with a 4-byte value.
    #[must_use]
    pub fn with_u32(pr_type: u32, value: u32, encoding: Encoding) -> Self {
        let mut data = Vec::with_capacity(4);
        encoding.write_u32(&mut data, value);
        Self { pr_type, data }
    }

    /// Return the data as a `u32` if it is exactly 4 bytes (for example the
    /// `GNU_PROPERTY_X86_FEATURE_1_AND` bits).
    #[must_use]
    pub fn as_u32(&self, encoding: Encoding) -> Option<u32> {
        if self.data.len() == 4 {
            encoding.read_u32(&self.data, 0).ok()
        } else {
            None
        }
    }
}

/// Parse the descriptor of an `NT_GNU_PROPERTY_TYPE_0` note.
///
/// Each property has a 32-bit `pr_type`, a 32-bit `pr_datasz` and the data, padded to 8 bytes in
/// ELF64 and to 4 bytes in ELF32.
///
/// # Errors
///
/// Return [`crate::ErrorKind::InvalidTable`] if a property is truncated.
pub fn parse_gnu_properties(desc: &[u8], encoding: Encoding) -> Result<Vec<GnuProperty>> {
    let align = encoding.addr_size();
    let truncated = |pos: usize| {
        Error::invalid_table("truncated GNU property")
            .in_structure("NT_GNU_PROPERTY_TYPE_0")
            .at_offset(pos as u64)
    };
    let mut props = Vec::new();
    let mut pos = 0usize;
    while pos < desc.len() {
        let pr_type = encoding.read_u32(desc, pos).map_err(|_| truncated(pos))?;
        let datasz = encoding
            .read_u32(desc, pos + 4)
            .map_err(|_| truncated(pos))?;
        // A `usize` has at least 32 bits, so the size converts without loss.
        let datasz = usize::try_from(datasz).unwrap_or(usize::MAX);
        let start = pos + 8;
        let end = start.checked_add(datasz).ok_or_else(|| truncated(pos))?;
        let data = desc.get(start..end).ok_or_else(|| truncated(pos))?;
        props.push(GnuProperty {
            pr_type,
            data: data.to_vec(),
        });
        // `end` is at most the length of `desc`, so the padding does not overflow.
        pos = end.saturating_add(align - 1) & !(align - 1);
    }
    Ok(props)
}

/// Serialize the descriptor of an `NT_GNU_PROPERTY_TYPE_0` note (see [`parse_gnu_properties`]).
///
/// # Errors
///
/// Return [`crate::ErrorKind::ValueOutOfRange`] if the data of a property is longer than
/// `u32::MAX` bytes.
pub fn write_gnu_properties(props: &[GnuProperty], encoding: Encoding) -> Result<Vec<u8>> {
    let align = encoding.addr_size();
    let mut out = Vec::new();
    for prop in props {
        let datasz = u32::try_from(prop.data.len())
            .map_err(|_| Error::value_out_of_range("GNU property data is too long"))?;
        encoding.write_u32(&mut out, prop.pr_type);
        encoding.write_u32(&mut out, datasz);
        out.extend_from_slice(&prop.data);
        while out.len() % align != 0 {
            out.push(0);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;
    use crate::note::{ELF_NOTE_GNU, NT_GNU_PROPERTY_TYPE_0, Note, NoteTable};

    #[test]
    fn abi_tag() {
        let tag = GnuAbiTag {
            os: GNU_ABI_TAG_LINUX,
            major: 3,
            minor: 2,
            subminor: 0,
        };
        for enc in [Encoding::ELF32_BE, Encoding::ELF64_LE] {
            let note = Note::new(ELF_NOTE_GNU, crate::note::NT_GNU_ABI_TAG, tag.to_bytes(enc));
            assert_eq!(note.gnu_abi_tag(enc).unwrap().unwrap(), tag);
        }
        assert!(GnuAbiTag::parse(&[0; 15], Encoding::ELF64_LE).is_err());
        assert!(
            Note::gnu_build_id(vec![1])
                .gnu_abi_tag(Encoding::ELF64_LE)
                .is_none()
        );
    }

    #[test]
    fn properties_elf64() {
        let desc = [
            0x02, 0x00, 0x00, 0xc0, // GNU_PROPERTY_X86_FEATURE_1_AND
            0x04, 0x00, 0x00, 0x00, // pr_datasz
            0x03, 0x00, 0x00, 0x00, // IBT | SHSTK
            0x00, 0x00, 0x00, 0x00, // padding to 8
            0x02, 0x80, 0x00, 0xc0, // GNU_PROPERTY_X86_ISA_1_NEEDED
            0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let enc = Encoding::ELF64_LE;
        let props = parse_gnu_properties(&desc, enc).unwrap();
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].pr_type, GNU_PROPERTY_X86_FEATURE_1_AND);
        assert_eq!(
            props[0].as_u32(enc),
            Some(GNU_PROPERTY_X86_FEATURE_1_IBT | GNU_PROPERTY_X86_FEATURE_1_SHSTK)
        );
        assert_eq!(props[1].pr_type, GNU_PROPERTY_X86_ISA_1_NEEDED);
        assert_eq!(write_gnu_properties(&props, enc).unwrap(), desc);

        // Through a note table with 8-byte alignment.
        let table = NoteTable {
            notes: vec![Note::new(
                ELF_NOTE_GNU,
                NT_GNU_PROPERTY_TYPE_0,
                desc.to_vec(),
            )],
        };
        let bytes = table.write(enc, 8).unwrap();
        let parsed = NoteTable::parse(&bytes, enc, 8).unwrap();
        assert_eq!(parsed.notes[0].gnu_properties(enc).unwrap().unwrap(), props);
    }

    #[test]
    fn properties_elf32() {
        let enc = Encoding::ELF32_BE;
        let props = vec![
            GnuProperty::with_u32(GNU_PROPERTY_AARCH64_FEATURE_1_AND, 3, enc),
            GnuProperty {
                pr_type: GNU_PROPERTY_NO_COPY_ON_PROTECTED,
                data: Vec::new(),
            },
            GnuProperty {
                pr_type: GNU_PROPERTY_STACK_SIZE,
                data: vec![0, 0, 1, 0],
            },
        ];
        let bytes = write_gnu_properties(&props, enc).unwrap();
        assert_eq!(bytes.len(), 12 + 8 + 12);
        assert_eq!(&bytes[..8], [0xc0, 0, 0, 0, 0, 0, 0, 4]);
        assert_eq!(parse_gnu_properties(&bytes, enc).unwrap(), props);
    }

    #[test]
    fn properties_truncated() {
        let enc = Encoding::ELF64_LE;
        // The data, then `pr_datasz`, then `pr_type` is cut. The error is at the property.
        for (desc, offset) in [
            (&[2, 0, 0, 0xc0, 8, 0, 0, 0, 1, 0][..], 0),
            (&[2, 0, 0, 0xc0, 0, 0, 0, 0, 2, 0, 0, 0xc0, 4][..], 8),
            (&[2, 0, 0][..], 0),
        ] {
            let err = parse_gnu_properties(desc, enc).unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
            let context = err.context().unwrap();
            assert_eq!(context.structure.as_deref(), Some("NT_GNU_PROPERTY_TYPE_0"));
            assert_eq!(context.file_offset, Some(offset));
        }
    }

    #[test]
    fn property_as_u32_needs_four_bytes() {
        let enc = Encoding::ELF32_LE;
        for data in [vec![], vec![1, 2, 3], vec![1, 2, 3, 4, 5, 6, 7, 8]] {
            let prop = GnuProperty {
                pr_type: GNU_PROPERTY_STACK_SIZE,
                data,
            };
            assert_eq!(prop.as_u32(enc), None);
        }
    }
}
