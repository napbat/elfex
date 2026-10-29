//! Tests of [`EhFrame::parse_fde_at`] and [`EhFrame::parse_with_bases`].

use super::*;

/// Return the CIE and the FDEs of `entries`.
fn split(entries: Vec<EhFrameEntry>) -> (Cie, Vec<Fde>) {
    let mut entries = entries.into_iter();
    let Some(EhFrameEntry::Cie(cie)) = entries.next() else {
        panic!("the section starts with a CIE");
    };
    let fdes = entries
        .map(|entry| match entry {
            EhFrameEntry::Fde(fde) => fde,
            EhFrameEntry::Cie(_) => panic!("the section has one CIE"),
        })
        .collect();
    (cie, fdes)
}

#[test]
fn parse_fde_at_gives_the_records_of_parse() {
    let bases = PointerBases::default();
    for encoding in ALL {
        for pe in [DW_EH_PE_PCREL | DW_EH_PE_SDATA4, DW_EH_PE_ABSPTR] {
            let bytes = build(encoding, pe);
            let (cie, fdes) = split(EhFrame::parse(&bytes, encoding, SECTION).unwrap());
            for fde in fdes {
                let offset = usize::try_from(fde.offset).unwrap();
                let parsed =
                    EhFrame::parse_fde_at(&bytes, encoding, SECTION, offset, &bases).unwrap();
                assert_eq!(parsed, (cie.clone(), fde));
            }
        }
    }
}

#[test]
fn parse_fde_at_refuses_a_record_that_is_not_an_fde() {
    let encoding = Encoding::ELF64_LE;
    let bytes = build(encoding, DW_EH_PE_ABSPTR);
    let bases = PointerBases::default();
    // Offset 0 is the CIE, and the last 4 bytes are the terminator.
    for offset in [0, bytes.len() - 4] {
        let err = EhFrame::parse_fde_at(&bytes, encoding, SECTION, offset, &bases).unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");
        let context = err.context().unwrap();
        assert_eq!(context.file_offset, Some(u64::try_from(offset).unwrap()));
    }
}

#[test]
fn parse_fde_at_refuses_a_pointer_to_an_fde() {
    let encoding = Encoding::ELF64_LE;
    let mut bytes = build(encoding, DW_EH_PE_ABSPTR);
    let (_, fdes) = split(EhFrame::parse(&bytes, encoding, SECTION).unwrap());
    let first = usize::try_from(fdes[0].offset).unwrap();
    let second = usize::try_from(fdes[1].offset).unwrap();
    // Point the CIE pointer of the second FDE to the first FDE.
    let pointer = second + 4 - first;
    bytes[second + 4..second + 8].copy_from_slice(&len_u32(pointer).to_le_bytes());
    let err = EhFrame::parse_fde_at(&bytes, encoding, SECTION, second, &PointerBases::default())
        .unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");
}

/// A CIE with the augmentation `zR` whose FDE pointers use `fde_encoding`.
fn cie_body(fde_encoding: u8) -> Vec<u8> {
    let mut body = vec![1];
    body.extend_from_slice(b"zR\0");
    body.extend_from_slice(&[1, 0x78, 16, 1, fde_encoding]);
    body
}

#[test]
fn datarel_pointers_use_the_data_base() {
    let encoding = Encoding::ELF64_LE;
    let mut fde = Vec::new();
    encoding.write_i32(&mut fde, 0x100);
    encoding.write_i32(&mut fde, 0x10);
    fde.push(0);
    let bytes = records(
        encoding,
        &cie_body(DW_EH_PE_DATAREL | DW_EH_PE_SDATA4),
        &[&fde],
    );

    // Without a data base, the pointer has no value.
    let err = EhFrame::parse(&bytes, encoding, SECTION).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)), "{err:?}");

    let bases = PointerBases {
        data: Some(0x4000),
        ..PointerBases::default()
    };
    let (cie, fdes) = split(EhFrame::parse_with_bases(&bytes, encoding, SECTION, &bases).unwrap());
    assert_eq!((fdes[0].pc_begin, fdes[0].pc_range), (0x4100, 0x10));
    let offset = usize::try_from(fdes[0].offset).unwrap();
    let parsed = EhFrame::parse_fde_at(&bytes, encoding, SECTION, offset, &bases).unwrap();
    assert_eq!(parsed, (cie, fdes[0].clone()));
}

#[test]
fn a_funcrel_lsda_is_relative_to_pc_begin() {
    let encoding = Encoding::ELF64_LE;
    let mut cie = vec![1];
    cie.extend_from_slice(b"zLR\0");
    cie.extend_from_slice(&[
        1,
        0x78,
        16,
        2,
        DW_EH_PE_FUNCREL | DW_EH_PE_UDATA4,
        DW_EH_PE_UDATA4,
    ]);
    let mut fde = Vec::new();
    encoding.write_u32(&mut fde, 0x1000);
    encoding.write_u32(&mut fde, 0x10);
    fde.push(4);
    encoding.write_u32(&mut fde, 0x20);
    let bytes = records(encoding, &cie, &[&fde]);

    // A `func` base of the caller does not change the base of the LSDA pointer.
    let bases = PointerBases {
        func: Some(0xdead_0000),
        ..PointerBases::default()
    };
    let (_, fdes) = split(EhFrame::parse_with_bases(&bytes, encoding, SECTION, &bases).unwrap());
    assert_eq!(fdes[0].lsda, Some(0x1020));
}
