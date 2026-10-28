//! The ELF identification bytes (`e_ident`).

use crate::endian::{Class, Encoding, Endian};
use crate::{Error, Result};

/// The four magic bytes at the start of each ELF file: `\x7fELF`.
pub const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

/// The size of `e_ident` in bytes (`EI_NIDENT`).
pub const EI_NIDENT: usize = 16;

/// The current ELF version (`EV_CURRENT`).
pub const EV_CURRENT: u8 = 1;

elf_value_type! {
    /// The operating system and ABI of an ELF file (`EI_OSABI`).
    pub struct OsAbi(u8);
    /// `ELFOSABI_NONE`: UNIX System V ABI.
    SYSV = 0, "ELFOSABI_SYSV";
    /// `ELFOSABI_HPUX`: HP-UX.
    HPUX = 1, "ELFOSABI_HPUX";
    /// `ELFOSABI_NETBSD`: NetBSD.
    NETBSD = 2, "ELFOSABI_NETBSD";
    /// `ELFOSABI_GNU`: GNU/Linux. The old name is `ELFOSABI_LINUX`.
    GNU = 3, "ELFOSABI_GNU";
    /// `ELFOSABI_SOLARIS`: Solaris.
    SOLARIS = 6, "ELFOSABI_SOLARIS";
    /// `ELFOSABI_AIX`: IBM AIX.
    AIX = 7, "ELFOSABI_AIX";
    /// `ELFOSABI_IRIX`: SGI IRIX.
    IRIX = 8, "ELFOSABI_IRIX";
    /// `ELFOSABI_FREEBSD`: FreeBSD.
    FREEBSD = 9, "ELFOSABI_FREEBSD";
    /// `ELFOSABI_TRU64`: Compaq TRU64 UNIX.
    TRU64 = 10, "ELFOSABI_TRU64";
    /// `ELFOSABI_MODESTO`: Novell Modesto.
    MODESTO = 11, "ELFOSABI_MODESTO";
    /// `ELFOSABI_OPENBSD`: OpenBSD.
    OPENBSD = 12, "ELFOSABI_OPENBSD";
    /// `ELFOSABI_ARM_AEABI`: ARM EABI.
    ARM_AEABI = 64, "ELFOSABI_ARM_AEABI";
    /// `ELFOSABI_ARM`: ARM.
    ARM = 97, "ELFOSABI_ARM";
    /// `ELFOSABI_STANDALONE`: a standalone (embedded) application.
    STANDALONE = 255, "ELFOSABI_STANDALONE";
}

/// The ELF identification bytes (`e_ident`).
///
/// The identification gives the class and the byte order of the rest of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ident {
    /// The file class (`EI_CLASS`).
    pub class: Class,
    /// The byte order (`EI_DATA`).
    pub endian: Endian,
    /// The ELF version (`EI_VERSION`). The value is `EV_CURRENT` in a valid file.
    pub version: u8,
    /// The operating system and ABI (`EI_OSABI`).
    pub os_abi: OsAbi,
    /// The ABI version (`EI_ABIVERSION`).
    pub abi_version: u8,
    /// The padding bytes (`EI_PAD`). A valid file has zeros, but the parser keeps the values.
    pub padding: [u8; 7],
}

impl Ident {
    /// Create an identification with `EV_CURRENT`, the System V ABI and zero padding.
    #[must_use]
    pub const fn new(encoding: Encoding) -> Self {
        Self {
            class: encoding.class,
            endian: encoding.endian,
            version: EV_CURRENT,
            os_abi: OsAbi::SYSV,
            abi_version: 0,
            padding: [0; 7],
        }
    }

    /// Parse the identification from the first 16 bytes of `bytes`.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` has
    ///   fewer than 16 bytes.
    /// - Return [`ErrorKind::InvalidMagic`](crate::ErrorKind::InvalidMagic) if the magic bytes
    ///   are wrong.
    /// - Return [`ErrorKind::InvalidClass`](crate::ErrorKind::InvalidClass) or
    ///   [`ErrorKind::InvalidDataEncoding`](crate::ErrorKind::InvalidDataEncoding) for an
    ///   unknown class or byte order.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let ident = bytes
            .get(..EI_NIDENT)
            .ok_or_else(|| Error::buffer_too_small(EI_NIDENT, bytes.len()))?;
        if ident[..4] != ELF_MAGIC {
            return Err(Error::invalid_magic());
        }
        let mut padding = [0u8; 7];
        padding.copy_from_slice(&ident[9..16]);
        Ok(Self {
            class: Class::from_ident_byte(ident[4])?,
            endian: Endian::from_ident_byte(ident[5])?,
            version: ident[6],
            os_abi: OsAbi(ident[7]),
            abi_version: ident[8],
            padding,
        })
    }

    /// Return the class and the byte order of the file.
    #[must_use]
    pub const fn encoding(&self) -> Encoding {
        Encoding::new(self.class, self.endian)
    }

    /// Serialize the identification to its 16 bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; EI_NIDENT] {
        let mut out = [0u8; EI_NIDENT];
        out[..4].copy_from_slice(&ELF_MAGIC);
        out[4] = self.class.ident_byte();
        out[5] = self.endian.ident_byte();
        out[6] = self.version;
        out[7] = self.os_abi.0;
        out[8] = self.abi_version;
        out[9..].copy_from_slice(&self.padding);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    #[test]
    fn round_trips_and_rejects_bad_values() {
        let mut ident = Ident::new(Encoding::ELF64_BE);
        ident.os_abi = OsAbi::FREEBSD;
        ident.padding[6] = 0xaa;
        let bytes = ident.to_bytes();
        assert_eq!(Ident::parse(&bytes).unwrap(), ident);
        assert_eq!(ident.os_abi.name(), Some("ELFOSABI_FREEBSD"));

        let mut bad = bytes;
        bad[4] = 3;
        assert!(matches!(
            Ident::parse(&bad).unwrap_err().kind(),
            ErrorKind::InvalidClass(3)
        ));
        bad = bytes;
        bad[0] = 0;
        assert!(matches!(
            Ident::parse(&bad).unwrap_err().kind(),
            ErrorKind::InvalidMagic
        ));
        assert!(Ident::parse(&bytes[..15]).is_err());
    }
}
