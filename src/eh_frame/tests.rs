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
    assert!(EhFrame::parse(&bytes, encoding, SECTION).is_err());
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

#[test]
fn uleb128_values() {
    let mut offset = 0;
    assert_eq!(
        read_uleb128(&[0xe5, 0x8e, 0x26], &mut offset).unwrap(),
        624_485
    );
    assert_eq!(offset, 3);
    let mut max = vec![0xff; 9];
    max.push(0x01);
    let mut offset = 0;
    assert_eq!(read_uleb128(&max, &mut offset).unwrap(), u64::MAX);
    let mut out = Vec::new();
    write_uleb128(&mut out, u64::MAX);
    assert_eq!(out, max);
}

#[test]
fn uleb128_overflow_errors() {
    let mut too_big = vec![0xff; 9];
    too_big.push(0x02);
    let mut offset = 0;
    assert!(read_uleb128(&too_big, &mut offset).is_err());
    assert_eq!(offset, 0);
    let mut too_long = vec![0x80; 10];
    too_long.push(0x01);
    assert!(read_uleb128(&too_long, &mut 0).is_err());
    assert!(read_uleb128(&[0x80, 0x80], &mut 0).is_err());
}

#[test]
fn sleb128_values() {
    for value in [
        0,
        1,
        -1,
        63,
        -64,
        64,
        -65,
        624_485,
        -123_456,
        i64::MIN,
        i64::MAX,
    ] {
        let mut out = Vec::new();
        write_sleb128(&mut out, value);
        let mut offset = 0;
        assert_eq!(read_sleb128(&out, &mut offset).unwrap(), value, "{value}");
        assert_eq!(offset, out.len());
    }
    let mut min = vec![0x80; 9];
    min.push(0x7f);
    assert_eq!(read_sleb128(&min, &mut 0).unwrap(), i64::MIN);
}

#[test]
fn sleb128_overflow_errors() {
    let mut too_big = vec![0x80; 9];
    too_big.push(0x01);
    assert!(read_sleb128(&too_big, &mut 0).is_err());
    let mut too_long = vec![0xff; 10];
    too_long.push(0x00);
    assert!(read_sleb128(&too_long, &mut 0).is_err());
    assert!(read_sleb128(&[0xff], &mut 0).is_err());
}

#[test]
fn omit_returns_none() {
    let bases = PointerBases::default();
    let mut offset = 0;
    let value = read_encoded_pointer(
        &[],
        &mut offset,
        Encoding::ELF64_LE,
        DW_EH_PE_OMIT,
        0,
        &bases,
    )
    .unwrap();
    assert_eq!(value, None);
    assert_eq!(offset, 0);
}

#[test]
fn encoded_pointer_applications() {
    let encoding = Encoding::ELF32_LE;
    let bases = PointerBases {
        pc: None,
        text: Some(0x100),
        data: Some(0x200),
        func: None,
    };
    let bytes = [0xfc, 0xff, 0xff, 0xff];
    let read = |pe: u8, field: u64| {
        let mut offset = 0;
        read_encoded_pointer(&bytes, &mut offset, encoding, pe, field, &bases)
    };
    assert_eq!(
        read(DW_EH_PE_PCREL | DW_EH_PE_SDATA4, 0x10).unwrap(),
        Some(0xc)
    );
    assert_eq!(
        read(DW_EH_PE_TEXTREL | DW_EH_PE_SDATA4, 0).unwrap(),
        Some(0xfc)
    );
    assert_eq!(
        read(DW_EH_PE_DATAREL | DW_EH_PE_UDATA2, 0).unwrap(),
        Some(0x200 + 0xfffc)
    );
    assert!(read(DW_EH_PE_FUNCREL | DW_EH_PE_SDATA4, 0).is_err());
    // ELF32 arithmetic wraps to 32 bits.
    assert_eq!(
        read(DW_EH_PE_PCREL | DW_EH_PE_SDATA4, 0).unwrap(),
        Some(0xffff_fffc)
    );
    assert_eq!(
        read(DW_EH_PE_INDIRECT | DW_EH_PE_PCREL | DW_EH_PE_SDATA4, 0x10).unwrap(),
        Some(0xc)
    );
    assert!(read(0x0d, 0).is_err());
    assert!(read(DW_EH_PE_UDATA8, 0).is_err());

    let aligned = [0, 0, 0, 0, 0x78, 0x56, 0x34, 0x12];
    let mut offset = 1;
    let value = read_encoded_pointer(
        &aligned,
        &mut offset,
        encoding,
        DW_EH_PE_ALIGNED,
        0x1001,
        &bases,
    )
    .unwrap();
    assert_eq!(value, Some(0x1234_5678));
    assert_eq!(offset, 8);
}
