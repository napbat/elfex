//! Core file note descriptors: mapped files (`NT_FILE`) and the auxiliary vector (`NT_AUXV`).

use crate::endian::ByteReader;
use crate::prelude::*;
use crate::{Encoding, Error, Result};

/// `AT_NULL`: the end of the auxiliary vector.
pub const AT_NULL: u64 = 0;
/// `AT_IGNORE`: an entry to ignore.
pub const AT_IGNORE: u64 = 1;
/// `AT_EXECFD`: the file descriptor of the program.
pub const AT_EXECFD: u64 = 2;
/// `AT_PHDR`: the virtual address of the program header table.
pub const AT_PHDR: u64 = 3;
/// `AT_PHENT`: the size of a program header.
pub const AT_PHENT: u64 = 4;
/// `AT_PHNUM`: the number of program headers.
pub const AT_PHNUM: u64 = 5;
/// `AT_PAGESZ`: the page size.
pub const AT_PAGESZ: u64 = 6;
/// `AT_BASE`: the virtual address of the interpreter.
pub const AT_BASE: u64 = 7;
/// `AT_FLAGS`: flags.
pub const AT_FLAGS: u64 = 8;
/// `AT_ENTRY`: the virtual address of the program entry point.
pub const AT_ENTRY: u64 = 9;
/// `AT_NOTELF`: the program is not ELF.
pub const AT_NOTELF: u64 = 10;
/// `AT_UID`: the real user ID.
pub const AT_UID: u64 = 11;
/// `AT_EUID`: the effective user ID.
pub const AT_EUID: u64 = 12;
/// `AT_GID`: the real group ID.
pub const AT_GID: u64 = 13;
/// `AT_EGID`: the effective group ID.
pub const AT_EGID: u64 = 14;
/// `AT_PLATFORM`: the virtual address of the platform string.
pub const AT_PLATFORM: u64 = 15;
/// `AT_HWCAP`: hardware capabilities.
pub const AT_HWCAP: u64 = 16;
/// `AT_CLKTCK`: the frequency of `times()`.
pub const AT_CLKTCK: u64 = 17;
/// `AT_FPUCW`: the FPU control word.
pub const AT_FPUCW: u64 = 18;
/// `AT_DCACHEBSIZE`: the data cache block size.
pub const AT_DCACHEBSIZE: u64 = 19;
/// `AT_ICACHEBSIZE`: the instruction cache block size.
pub const AT_ICACHEBSIZE: u64 = 20;
/// `AT_UCACHEBSIZE`: the unified cache block size.
pub const AT_UCACHEBSIZE: u64 = 21;
/// `AT_IGNOREPPC`: an entry to ignore (PowerPC).
pub const AT_IGNOREPPC: u64 = 22;
/// `AT_SECURE`: the program runs in secure mode.
pub const AT_SECURE: u64 = 23;
/// `AT_BASE_PLATFORM`: the virtual address of the base platform string.
pub const AT_BASE_PLATFORM: u64 = 24;
/// `AT_RANDOM`: the virtual address of 16 random bytes.
pub const AT_RANDOM: u64 = 25;
/// `AT_HWCAP2`: more hardware capabilities.
pub const AT_HWCAP2: u64 = 26;
/// `AT_EXECFN`: the virtual address of the program file name.
pub const AT_EXECFN: u64 = 31;
/// `AT_SYSINFO`: the virtual address of the system call entry point.
pub const AT_SYSINFO: u64 = 32;
/// `AT_SYSINFO_EHDR`: the virtual address of the vDSO ELF header.
pub const AT_SYSINFO_EHDR: u64 = 33;
/// `AT_MINSIGSTKSZ`: the minimum signal stack size.
pub const AT_MINSIGSTKSZ: u64 = 51;

/// One mapped file range in an `NT_FILE` descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileMapping {
    /// The virtual address of the start of the range.
    pub start: u64,
    /// The virtual address of the end of the range (exclusive).
    pub end: u64,
    /// The file offset of the range in bytes (the page offset multiplied by the page size).
    pub file_offset: u64,
    /// The path of the mapped file.
    pub path: String,
}

/// Parse the descriptor of an `NT_FILE` note.
///
/// The descriptor has a class-sized count, a class-sized page size, `count` triples of
/// class-sized words (start, end, page offset) and `count` NUL-terminated paths.
/// Return the page size and the mappings.
///
/// # Errors
///
/// - Return [`crate::ErrorKind::InvalidTable`] if the descriptor is truncated, if the count is
///   too large for the descriptor, or if a file offset overflows.
/// - Return [`crate::ErrorKind::InvalidUtf8`] if a path is not valid UTF-8.
pub fn parse_nt_file(desc: &[u8], encoding: Encoding) -> Result<(u64, Vec<FileMapping>)> {
    let err = |msg: &str| Error::invalid_table(msg).in_structure("NT_FILE");
    let mut reader = ByteReader::new(desc, encoding);
    let count = reader.addr().map_err(|_| err("truncated NT_FILE header"))?;
    let page_size = reader.addr().map_err(|_| err("truncated NT_FILE header"))?;
    let entry_size = encoding.addr_size() * 3;
    // Each entry also needs at least one NUL byte for its path.
    let count = usize::try_from(count)
        .ok()
        .filter(|c| {
            c.checked_mul(entry_size + 1)
                .is_some_and(|n| n <= reader.remaining())
        })
        .ok_or_else(|| err("NT_FILE count is too large"))?;
    let mut mappings = Vec::with_capacity(count);
    for _ in 0..count {
        let start = reader.addr()?;
        let end = reader.addr()?;
        let page_offset = reader.addr()?;
        let file_offset = page_offset
            .checked_mul(page_size)
            .ok_or_else(|| err("NT_FILE file offset overflows"))?;
        mappings.push(FileMapping {
            start,
            end,
            file_offset,
            path: String::new(),
        });
    }
    let mut names = &desc[reader.position()..];
    for mapping in &mut mappings {
        let nul = names
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| err("truncated NT_FILE path"))?;
        mapping.path = core::str::from_utf8(&names[..nul])
            .map_err(|_| Error::invalid_utf8().in_structure("NT_FILE"))?
            .to_string();
        names = &names[nul + 1..];
    }
    Ok((page_size, mappings))
}

/// Serialize the descriptor of an `NT_FILE` note (see [`parse_nt_file`]).
///
/// # Errors
///
/// - Return [`crate::ErrorKind::ValueOutOfRange`] if a value does not fit an ELF32 word.
/// - Return [`crate::ErrorKind::InvalidTable`] if `page_size` is 0, a file offset is not a
///   multiple of `page_size`, or a path contains a NUL byte.
pub fn write_nt_file(
    page_size: u64,
    mappings: &[FileMapping],
    encoding: Encoding,
) -> Result<Vec<u8>> {
    let err = |msg: &str| Error::invalid_table(msg).in_structure("NT_FILE");
    if page_size == 0 {
        return Err(err("NT_FILE page size is 0"));
    }
    let mut out = Vec::new();
    encoding.write_addr(&mut out, mappings.len() as u64)?;
    encoding.write_addr(&mut out, page_size)?;
    for m in mappings {
        if m.file_offset % page_size != 0 {
            return Err(err("NT_FILE file offset is not page-aligned"));
        }
        encoding.write_addr(&mut out, m.start)?;
        encoding.write_addr(&mut out, m.end)?;
        encoding.write_addr(&mut out, m.file_offset / page_size)?;
    }
    for m in mappings {
        if m.path.as_bytes().contains(&0) {
            return Err(err("NT_FILE path contains a NUL byte"));
        }
        out.extend_from_slice(m.path.as_bytes());
        out.push(0);
    }
    Ok(out)
}

/// One auxiliary vector entry (`Elf32_auxv_t` or `Elf64_auxv_t`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AuxvEntry {
    /// The entry type (`a_type`, `AT_*`).
    pub key: u64,
    /// The value (`a_val`).
    pub value: u64,
}

/// Parse the descriptor of an `NT_AUXV` note.
///
/// The entries are pairs of class-sized words. Parsing stops at `AT_NULL` (not included in the
/// result) or at the end of the descriptor.
///
/// # Errors
///
/// Return [`crate::ErrorKind::InvalidTable`] if the descriptor ends inside an entry.
pub fn parse_auxv(desc: &[u8], encoding: Encoding) -> Result<Vec<AuxvEntry>> {
    let mut reader = ByteReader::new(desc, encoding);
    let mut entries = Vec::new();
    while reader.remaining() > 0 {
        let pos = reader.position();
        let mut pair = || -> Result<AuxvEntry> {
            Ok(AuxvEntry {
                key: reader.addr()?,
                value: reader.addr()?,
            })
        };
        let entry = pair().map_err(|_| {
            Error::invalid_table("truncated auxiliary vector entry")
                .in_structure("auxv_t")
                .at_offset(pos as u64)
        })?;
        if entry.key == AT_NULL {
            break;
        }
        entries.push(entry);
    }
    Ok(entries)
}

/// Serialize an auxiliary vector, terminated by an `AT_NULL` entry.
///
/// # Errors
///
/// Return [`crate::ErrorKind::ValueOutOfRange`] if a value does not fit an ELF32 word.
pub fn write_auxv(entries: &[AuxvEntry], encoding: Encoding) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for e in entries
        .iter()
        .chain(core::iter::once(&AuxvEntry::default()))
    {
        encoding.write_addr(&mut out, e.key)?;
        encoding.write_addr(&mut out, e.value)?;
    }
    Ok(out)
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

    fn mappings() -> Vec<FileMapping> {
        vec![
            FileMapping {
                start: 0x1000,
                end: 0x3000,
                file_offset: 0,
                path: "/bin/true".to_string(),
            },
            FileMapping {
                start: 0x5000,
                end: 0x6000,
                file_offset: 0x2000,
                path: "/lib/libc.so.6".to_string(),
            },
        ]
    }

    #[test]
    fn nt_file_round_trip() {
        for enc in ALL {
            let bytes = write_nt_file(0x1000, &mappings(), enc).unwrap();
            let (page, parsed) = parse_nt_file(&bytes, enc).unwrap();
            assert_eq!(page, 0x1000);
            assert_eq!(parsed, mappings());
        }
    }

    #[test]
    fn nt_file_hand_written_elf32() {
        let mut d = vec![
            1, 0, 0, 0, // count
            0, 0x10, 0, 0, // page size
            0, 0x20, 0, 0, // start
            0, 0x30, 0, 0, // end
            2, 0, 0, 0, // page offset
        ];
        d.extend_from_slice(b"/a\0");
        let (page, m) = parse_nt_file(&d, Encoding::ELF32_LE).unwrap();
        assert_eq!(page, 0x1000);
        assert_eq!(m[0].file_offset, 0x2000);
        assert_eq!(m[0].path, "/a");
        // Missing NUL.
        let err = parse_nt_file(&d[..d.len() - 1], Encoding::ELF32_LE).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    }

    #[test]
    fn nt_file_huge_count() {
        for enc in [Encoding::ELF32_LE, Encoding::ELF64_BE] {
            let mut d = Vec::new();
            enc.write_addr(&mut d, u64::from(u32::MAX)).unwrap();
            enc.write_addr(&mut d, 0x1000).unwrap();
            d.extend_from_slice(&[0; 64]);
            let err = parse_nt_file(&d, enc).unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        }
        let mut d = Vec::new();
        Encoding::ELF64_LE.write_u64(&mut d, u64::MAX);
        Encoding::ELF64_LE.write_u64(&mut d, 0x1000);
        assert!(parse_nt_file(&d, Encoding::ELF64_LE).is_err());
        assert!(parse_nt_file(&[1, 2], Encoding::ELF64_LE).is_err());
    }

    #[test]
    fn auxv_round_trip() {
        let entries = vec![
            AuxvEntry {
                key: AT_PAGESZ,
                value: 0x1000,
            },
            AuxvEntry {
                key: AT_ENTRY,
                value: 0x40_1000,
            },
            AuxvEntry {
                key: AT_SYSINFO_EHDR,
                value: 0x7fff_0000,
            },
        ];
        for enc in ALL {
            let mut bytes = write_auxv(&entries, enc).unwrap();
            assert_eq!(bytes.len(), 4 * 2 * enc.addr_size());
            // Bytes after AT_NULL are ignored.
            bytes.extend_from_slice(&[0xff; 3]);
            assert_eq!(parse_auxv(&bytes, enc).unwrap(), entries);
        }
    }

    #[test]
    fn auxv_hand_written_and_truncated() {
        let d = [
            0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0x10, 0, // AT_PAGESZ
        ];
        let e = parse_auxv(&d, Encoding::ELF64_BE).unwrap();
        assert_eq!(
            e,
            [AuxvEntry {
                key: AT_PAGESZ,
                value: 0x1000
            }]
        );
        let e = parse_auxv(&d, Encoding::ELF32_BE).unwrap();
        assert_eq!(e, []);
        let err = parse_auxv(&d[..12], Encoding::ELF64_BE).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    }
}
