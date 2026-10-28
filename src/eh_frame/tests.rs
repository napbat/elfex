mod pointer;

use super::*;
use crate::ErrorKind;
use crate::prelude::*;

const SECTION: u64 = 0x2000;
const FDES: [(u64, u64); 2] = [(0x1000, 0x40), (0x1040, 0x20)];
const CIE_INSNS: [u8; 3] = [0x0c, 0x07, 0x08];
const FDE_INSNS: [u8; 3] = [0x41, 0x0e, 0x10];

fn len_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap()
}

fn to_i32(value: u64) -> i32 {
    i32::try_from(value.cast_signed()).unwrap()
}

/// Build an `.eh_frame` with one `zR` CIE and the FDEs in `FDES`.
fn build(encoding: Encoding, fde_encoding: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cie = Vec::new();
    encoding.write_u32(&mut cie, 0);
    cie.push(1);
    cie.extend_from_slice(b"zR\0");
    cie.extend_from_slice(&[1, 0x78, 16, 1, fde_encoding]);
    cie.extend_from_slice(&CIE_INSNS);
    encoding.write_u32(&mut out, len_u32(cie.len()));
    out.extend_from_slice(&cie);
    for (begin, range) in FDES {
        let start = out.len();
        let mut fde = Vec::new();
        encoding.write_u32(&mut fde, len_u32(start + 4));
        if fde_encoding == DW_EH_PE_PCREL | DW_EH_PE_SDATA4 {
            let field = SECTION + u64::try_from(start + 8).unwrap();
            encoding.write_i32(&mut fde, to_i32(begin.wrapping_sub(field)));
            encoding.write_i32(&mut fde, to_i32(range));
        } else {
            encoding.write_addr(&mut fde, begin).unwrap();
            encoding.write_addr(&mut fde, range).unwrap();
        }
        fde.push(0);
        fde.extend_from_slice(&FDE_INSNS);
        encoding.write_u32(&mut out, len_u32(fde.len()));
        out.extend_from_slice(&fde);
    }
    encoding.write_u32(&mut out, 0);
    out
}

fn check(entries: &[EhFrameEntry], fde_encoding: u8) {
    assert_eq!(entries.len(), 3);
    let EhFrameEntry::Cie(cie) = &entries[0] else {
        panic!("expected a CIE");
    };
    assert_eq!(cie.offset, 0);
    assert_eq!(cie.version, 1);
    assert_eq!(cie.augmentation, "zR");
    assert_eq!(cie.code_alignment_factor, 1);
    assert_eq!(cie.data_alignment_factor, -8);
    assert_eq!(cie.return_address_register, 16);
    assert_eq!(cie.fde_pointer_encoding, fde_encoding);
    assert_eq!(cie.lsda_encoding, None);
    assert_eq!(cie.personality, None);
    assert!(!cie.is_signal_frame);
    assert_eq!(cie.initial_instructions, CIE_INSNS);
    for (entry, (begin, range)) in entries[1..].iter().zip(FDES) {
        let EhFrameEntry::Fde(fde) = entry else {
            panic!("expected an FDE");
        };
        assert_eq!(fde.cie_offset, 0);
        assert_eq!(fde.pc_begin, begin);
        assert_eq!(fde.pc_range, range);
        assert_eq!(fde.lsda, None);
        assert_eq!(fde.instructions, FDE_INSNS);
    }
}

const ALL: [Encoding; 4] = [
    Encoding::ELF32_LE,
    Encoding::ELF32_BE,
    Encoding::ELF64_LE,
    Encoding::ELF64_BE,
];

#[test]
fn parse_pcrel_sdata4() {
    for encoding in ALL {
        let pe = DW_EH_PE_PCREL | DW_EH_PE_SDATA4;
        let bytes = build(encoding, pe);
        let entries = EhFrame::parse(&bytes, encoding, SECTION).unwrap();
        check(&entries, pe);
        let EhFrameEntry::Fde(fde) = &entries[2] else {
            panic!("expected an FDE");
        };
        assert_eq!(fde.offset, 20 + 20);
    }
}

#[test]
fn parse_absptr() {
    for encoding in ALL {
        let bytes = build(encoding, DW_EH_PE_ABSPTR);
        let entries = EhFrame::parse(&bytes, encoding, SECTION).unwrap();
        check(&entries, DW_EH_PE_ABSPTR);
        let EhFrameEntry::Fde(fde) = &entries[2] else {
            panic!("expected an FDE");
        };
        let fde_size = 4 + 4 + 2 * encoding.addr_size() + 1 + 3;
        assert_eq!(fde.offset, u64::try_from(20 + fde_size).unwrap());
    }
}

#[test]
fn parse_without_terminator() {
    let encoding = Encoding::ELF64_LE;
    let bytes = build(encoding, DW_EH_PE_ABSPTR);
    let entries = EhFrame::parse(&bytes[..bytes.len() - 4], encoding, SECTION).unwrap();
    assert_eq!(entries.len(), 3);
}

/// A record with a 64-bit length keeps a 4-byte CIE id and CIE pointer in `.eh_frame`.
#[test]
fn parse_dwarf64_length() {
    for encoding in [Encoding::ELF64_LE, Encoding::ELF64_BE] {
        let mut out = Vec::new();
        let mut cie = Vec::new();
        encoding.write_u32(&mut cie, 0);
        cie.push(3);
        cie.extend_from_slice(b"zR\0");
        cie.extend_from_slice(&[4, 0x7c, 30, 1, DW_EH_PE_UDATA8]);
        encoding.write_u32(&mut out, 0xffff_ffff);
        encoding.write_u64(&mut out, u64::try_from(cie.len()).unwrap());
        out.extend_from_slice(&cie);
        let start = out.len();
        let mut fde = Vec::new();
        encoding.write_u32(&mut fde, u32::try_from(start + 12).unwrap());
        encoding.write_u64(&mut fde, 0x40_0000);
        encoding.write_u64(&mut fde, 0x100);
        fde.extend_from_slice(&[0, 0x41]);
        encoding.write_u32(&mut out, 0xffff_ffff);
        encoding.write_u64(&mut out, u64::try_from(fde.len()).unwrap());
        out.extend_from_slice(&fde);
        let entries = EhFrame::parse(&out, encoding, SECTION).unwrap();
        assert_eq!(entries.len(), 2);
        let EhFrameEntry::Cie(cie) = &entries[0] else {
            panic!("expected a CIE");
        };
        assert_eq!(cie.version, 3);
        assert_eq!(cie.code_alignment_factor, 4);
        assert_eq!(cie.data_alignment_factor, -4);
        assert_eq!(cie.return_address_register, 30);
        let EhFrameEntry::Fde(fde) = &entries[1] else {
            panic!("expected an FDE");
        };
        assert_eq!(fde.offset, u64::try_from(start).unwrap());
        assert_eq!(fde.cie_offset, 0);
        assert_eq!(fde.pc_begin, 0x40_0000);
        assert_eq!(fde.pc_range, 0x100);
        assert_eq!(fde.instructions, [0x41]);
    }
}

#[test]
fn parse_augmentations() {
    let encoding = Encoding::ELF64_LE;
    let mut cie = Vec::new();
    encoding.write_u32(&mut cie, 0);
    cie.push(1);
    cie.extend_from_slice(b"zPLRSBGX\0");
    cie.extend_from_slice(&[1, 0x78, 16]);
    // Augmentation data: P (udata4), L, R, one unknown byte for X.
    cie.extend_from_slice(&[8, DW_EH_PE_UDATA4]);
    encoding.write_u32(&mut cie, 0x5000);
    cie.extend_from_slice(&[DW_EH_PE_UDATA4, DW_EH_PE_UDATA4, 0xee]);
    let mut out = Vec::new();
    encoding.write_u32(&mut out, len_u32(cie.len()));
    out.extend_from_slice(&cie);
    let start = out.len();
    let mut fde = Vec::new();
    encoding.write_u32(&mut fde, len_u32(start + 4));
    encoding.write_u32(&mut fde, 0x1000);
    encoding.write_u32(&mut fde, 0x10);
    fde.push(4);
    encoding.write_u32(&mut fde, 0x6000);
    encoding.write_u32(&mut out, len_u32(fde.len()));
    out.extend_from_slice(&fde);
    let entries = EhFrame::parse(&out, encoding, SECTION).unwrap();
    let EhFrameEntry::Cie(cie) = &entries[0] else {
        panic!("expected a CIE");
    };
    assert_eq!(cie.personality, Some(0x5000));
    assert_eq!(cie.lsda_encoding, Some(DW_EH_PE_UDATA4));
    assert_eq!(cie.fde_pointer_encoding, DW_EH_PE_UDATA4);
    assert!(cie.is_signal_frame);
    assert_eq!(cie.initial_instructions, []);
    let EhFrameEntry::Fde(fde) = &entries[1] else {
        panic!("expected an FDE");
    };
    assert_eq!(fde.lsda, Some(0x6000));
    assert_eq!(fde.instructions, []);
}

#[test]
fn fde_pointing_to_fde_is_invalid() {
    let encoding = Encoding::ELF32_LE;
    let mut bytes = build(encoding, DW_EH_PE_ABSPTR);
    // Point the second FDE (at offset 20 + 20) to the first FDE (at offset 20).
    let second = 20 + 20;
    encoding.put_u32(&mut bytes, second + 4, 24).unwrap();
    let err = EhFrame::parse(&bytes, encoding, SECTION).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
}

#[test]
fn truncated_eh_frame_errors() {
    let encoding = Encoding::ELF64_BE;
    let bytes = build(encoding, DW_EH_PE_PCREL | DW_EH_PE_SDATA4);
    for len in [2, 10, 21, 30, 45] {
        assert!(
            EhFrame::parse(&bytes[..len], encoding, SECTION).is_err(),
            "len {len}"
        );
    }
}

#[test]
fn bad_cie_version_errors() {
    let encoding = Encoding::ELF64_LE;
    let mut bytes = build(encoding, DW_EH_PE_ABSPTR);
    bytes[8] = 2;
    invalid_record(&bytes, encoding, 0);
}

fn sample_hdr() -> EhFrameHdr {
    EhFrameHdr {
        version: 1,
        eh_frame_ptr_encoding: DW_EH_PE_PCREL | DW_EH_PE_SDATA4,
        fde_count_encoding: DW_EH_PE_UDATA4,
        table_encoding: DW_EH_PE_DATAREL | DW_EH_PE_SDATA4,
        eh_frame_ptr: 0x3000,
        entries: vec![
            EhFrameHdrEntry {
                initial_location: 0x1100,
                fde_address: 0x3040,
            },
            EhFrameHdrEntry {
                initial_location: 0x1000,
                fde_address: 0x3020,
            },
            EhFrameHdrEntry {
                initial_location: 0x1200,
                fde_address: 0x3060,
            },
        ],
    }
}

#[test]
fn eh_frame_hdr_round_trip() {
    for encoding in ALL {
        let hdr = sample_hdr();
        let bytes = hdr.write(encoding, SECTION).unwrap();
        assert_eq!(bytes.len(), 12 + 3 * 8);
        let parsed = EhFrameHdr::parse(&bytes, encoding, SECTION).unwrap();
        let mut expected = hdr.clone();
        expected.entries.sort_by_key(|e| e.initial_location);
        assert_eq!(parsed, expected);
    }
}

#[test]
fn eh_frame_hdr_find_fde() {
    let mut hdr = sample_hdr();
    hdr.entries.sort_by_key(|e| e.initial_location);
    assert_eq!(hdr.find_fde(0xfff), None);
    assert_eq!(hdr.find_fde(0x1000), Some(0x3020));
    assert_eq!(hdr.find_fde(0x10ff), Some(0x3020));
    assert_eq!(hdr.find_fde(0x1100), Some(0x3040));
    assert_eq!(hdr.find_fde(0x1200), Some(0x3060));
    assert_eq!(hdr.find_fde(u64::MAX), Some(0x3060));
    assert_eq!(EhFrameHdr::default().find_fde(0x1000), None);
}

#[test]
fn eh_frame_hdr_errors() {
    let encoding = Encoding::ELF32_LE;
    let bytes = sample_hdr().write(encoding, SECTION).unwrap();
    for len in [0, 3, 6, 11, bytes.len() - 1] {
        assert!(
            EhFrameHdr::parse(&bytes[..len], encoding, SECTION).is_err(),
            "len {len}"
        );
    }
    let mut huge = bytes.clone();
    encoding.put_u32(&mut huge, 8, u32::MAX).unwrap();
    assert!(EhFrameHdr::parse(&huge, encoding, SECTION).is_err());
    let mut bad_version = bytes;
    bad_version[0] = 2;
    assert!(EhFrameHdr::parse(&bad_version, encoding, SECTION).is_err());

    let mut far = sample_hdr();
    far.eh_frame_ptr = 0x1_0000_0000;
    assert!(far.write(Encoding::ELF64_LE, SECTION).is_err());
}

#[test]
fn eh_frame_hdr_without_table() {
    let encoding = Encoding::ELF64_LE;
    let mut bytes = vec![1, DW_EH_PE_UDATA8, DW_EH_PE_OMIT, DW_EH_PE_OMIT];
    encoding.write_u64(&mut bytes, 0x3000);
    let hdr = EhFrameHdr::parse(&bytes, encoding, SECTION).unwrap();
    assert_eq!(hdr.eh_frame_ptr, 0x3000);
    assert_eq!(hdr.entries, []);
}

#[test]
fn eh_frame_hdr_malformed_pointers() {
    let encoding = Encoding::ELF64_BE;
    let check = |bytes: &[u8]| {
        let err = EhFrameHdr::parse(bytes, encoding, SECTION).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");
        assert_eq!(
            err.context().unwrap().structure.as_deref(),
            Some(".eh_frame_hdr")
        );
    };
    check(&[1, DW_EH_PE_OMIT, DW_EH_PE_OMIT, DW_EH_PE_OMIT]);
    // The table size of `u64::MAX` FDEs overflows.
    let mut bytes = vec![1, DW_EH_PE_UDATA4, DW_EH_PE_UDATA8, DW_EH_PE_UDATA4];
    encoding.write_u32(&mut bytes, 0x3000);
    encoding.write_u64(&mut bytes, u64::MAX);
    check(&bytes);
}

#[test]
fn eh_frame_hdr_elf32_wraps() {
    let encoding = Encoding::ELF32_BE;
    let hdr = EhFrameHdr {
        eh_frame_ptr: 0x10,
        entries: vec![EhFrameHdrEntry {
            initial_location: 0xffff_fff0,
            fde_address: 0x20,
        }],
        ..sample_hdr()
    };
    let bytes = hdr.write(encoding, 0x8).unwrap();
    let parsed = EhFrameHdr::parse(&bytes, encoding, 0x8).unwrap();
    assert_eq!(parsed.eh_frame_ptr, 0x10);
    assert_eq!(parsed.entries, hdr.entries);
}

/// Return an `.eh_frame` with one CIE whose body after the CIE id is `cie_body`, then one FDE
/// for each entry of `fde_bodies` (the bytes after the CIE pointer).
fn records(encoding: Encoding, cie_body: &[u8], fde_bodies: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    encoding.write_u32(&mut out, len_u32(cie_body.len() + 4));
    encoding.write_u32(&mut out, 0);
    out.extend_from_slice(cie_body);
    for body in fde_bodies {
        let start = out.len();
        encoding.write_u32(&mut out, len_u32(body.len() + 4));
        encoding.write_u32(&mut out, len_u32(start + 4));
        out.extend_from_slice(body);
    }
    out
}

/// Check that `EhFrame::parse` fails with `InvalidTable` in the `.eh_frame` structure at the
/// record offset `offset`.
fn invalid_record(bytes: &[u8], encoding: Encoding, offset: u64) {
    let err = EhFrame::parse(bytes, encoding, SECTION).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");
    let context = err.context().unwrap();
    assert_eq!(context.structure.as_deref(), Some(".eh_frame"));
    assert_eq!(context.file_offset, Some(offset));
}

/// Check that `EhFrame::parse` fails with `BufferTooSmall`.
fn buffer_too_small(bytes: &[u8], encoding: Encoding) {
    let err = EhFrame::parse(bytes, encoding, SECTION).unwrap_err();
    assert!(
        matches!(err.kind(), ErrorKind::BufferTooSmall { .. }),
        "{err:?}"
    );
}

/// The old GCC `eh` augmentation has a class-sized pointer before the alignment factors.
#[test]
fn parse_eh_augmentation() {
    for encoding in ALL {
        let mut cie = vec![1];
        cie.extend_from_slice(b"eh\0");
        encoding.write_addr(&mut cie, 0x1234).unwrap();
        cie.extend_from_slice(&[1, 0x78, 16]);
        cie.extend_from_slice(&CIE_INSNS);
        let mut fde = Vec::new();
        encoding.write_addr(&mut fde, 0x1000).unwrap();
        encoding.write_addr(&mut fde, 0x40).unwrap();
        fde.extend_from_slice(&FDE_INSNS);
        let entries = EhFrame::parse(&records(encoding, &cie, &[&fde]), encoding, SECTION).unwrap();
        let EhFrameEntry::Cie(cie) = &entries[0] else {
            panic!("expected a CIE");
        };
        assert_eq!(cie.augmentation, "eh");
        assert_eq!(cie.return_address_register, 16);
        assert_eq!(cie.initial_instructions, CIE_INSNS);
        let EhFrameEntry::Fde(fde) = &entries[1] else {
            panic!("expected an FDE");
        };
        assert_eq!((fde.pc_begin, fde.pc_range), (0x1000, 0x40));
        assert_eq!(fde.lsda, None);
        assert_eq!(fde.instructions, FDE_INSNS);

        // The `eh` pointer does not fit in the CIE.
        let mut short = vec![1];
        short.extend_from_slice(b"eh\0");
        short.extend_from_slice(&[0; 3]);
        buffer_too_small(&records(encoding, &short, &[]), encoding);
    }
}

/// A version 4 CIE has the address size and the segment selector size.
#[test]
fn parse_cie_version_4() {
    let encoding = Encoding::ELF64_LE;
    let cie = [4, 0, 8, 0, 1, 0x78, 16];
    let fde = [0x00, 0x10, 0, 0, 0, 0, 0, 0, 0x20, 0, 0, 0, 0, 0, 0, 0];
    let entries = EhFrame::parse(&records(encoding, &cie, &[&fde]), encoding, SECTION).unwrap();
    let EhFrameEntry::Cie(cie) = &entries[0] else {
        panic!("expected a CIE");
    };
    assert_eq!(cie.version, 4);
    assert_eq!(cie.augmentation, "");
    assert_eq!(cie.address_size, Some(8));
    assert_eq!(cie.segment_size, Some(0));
    let EhFrameEntry::Fde(fde) = &entries[1] else {
        panic!("expected an FDE");
    };
    assert_eq!((fde.pc_begin, fde.pc_range), (0x1000, 0x20));
    assert_eq!(fde.instructions, []);
    // The segment selector size is missing.
    buffer_too_small(&records(encoding, &[4, 0, 8], &[]), encoding);
}

#[test]
fn malformed_cie_errors() {
    let encoding = Encoding::ELF32_BE;
    // The CIE has no version byte.
    buffer_too_small(&records(encoding, &[], &[]), encoding);
    // The augmentation string has no NUL terminator.
    buffer_too_small(&records(encoding, &[1, b'z', b'R'], &[]), encoding);
    // An unknown augmentation without `z` has no length to skip its data.
    invalid_record(
        &records(encoding, &[1, b'x', 0, 1, 0x78, 16], &[]),
        encoding,
        0,
    );

    let err =
        EhFrame::parse(&records(encoding, &[1, 0xff, 0], &[]), encoding, SECTION).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidUtf8));
    assert_eq!(
        err.context().unwrap().structure.as_deref(),
        Some(".eh_frame")
    );
}

#[test]
fn malformed_fde_errors() {
    let encoding = Encoding::ELF64_LE;
    let cie = [1, 0, 1, 0x78, 16];
    // The CIE pointer of the FDE at offset 13 points before the section.
    let mut bytes = records(encoding, &cie, &[&[0; 16]]);
    encoding.put_u32(&mut bytes, 17, 0x100).unwrap();
    invalid_record(&bytes, encoding, 13);

    // The FDE pointer encoding is `DW_EH_PE_omit`.
    let omit = [1, b'z', b'R', 0, 1, 0x78, 16, 1, DW_EH_PE_OMIT];
    let bytes = records(encoding, &omit, &[&[0; 16]]);
    invalid_record(&bytes, encoding, 17);

    // The augmentation data of the FDE is too short for the LSDA pointer.
    let lsda = [1, b'z', b'L', 0, 1, 0x78, 16, 1, DW_EH_PE_UDATA4];
    let mut fde = vec![0; 16];
    fde.extend_from_slice(&[2, 0, 0]);
    buffer_too_small(&records(encoding, &lsda, &[&fde]), encoding);
}
