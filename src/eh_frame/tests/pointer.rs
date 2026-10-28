use super::ALL;
use crate::ErrorKind;
use crate::eh_frame::pointer::wrap_address;
use crate::eh_frame::*;
use crate::endian::Encoding;
use crate::prelude::*;

/// Return one `(format, bytes, raw value)` case for each `DW_EH_PE_*` value format. Each value
/// is -2 in its format, so the signed formats sign-extend and the unsigned formats do not.
fn format_cases(encoding: Encoding) -> Vec<(u8, Vec<u8>, u64)> {
    let minus_two = (-2_i64).cast_unsigned();
    let mut addr = Vec::new();
    encoding
        .write_addr(&mut addr, wrap_address(encoding, minus_two))
        .unwrap();
    let mut u16_bytes = Vec::new();
    encoding.write_u16(&mut u16_bytes, 0xfffe);
    let mut u32_bytes = Vec::new();
    encoding.write_u32(&mut u32_bytes, 0xffff_fffe);
    let mut u64_bytes = Vec::new();
    encoding.write_u64(&mut u64_bytes, minus_two);
    vec![
        (
            DW_EH_PE_ABSPTR,
            addr.clone(),
            wrap_address(encoding, minus_two),
        ),
        (DW_EH_PE_SIGNED, addr, minus_two),
        (DW_EH_PE_ULEB128, vec![0xfe, 0x7f], 0x3ffe),
        (DW_EH_PE_SLEB128, vec![0x7e], minus_two),
        (DW_EH_PE_UDATA2, u16_bytes.clone(), 0xfffe),
        (DW_EH_PE_SDATA2, u16_bytes, minus_two),
        (DW_EH_PE_UDATA4, u32_bytes.clone(), 0xffff_fffe),
        (DW_EH_PE_SDATA4, u32_bytes, minus_two),
        (DW_EH_PE_UDATA8, u64_bytes.clone(), minus_two),
        (DW_EH_PE_SDATA8, u64_bytes, minus_two),
    ]
}

#[test]
fn encoded_pointer_formats() {
    let bases = PointerBases {
        pc: None,
        text: Some(0x100),
        data: Some(0x200),
        func: Some(0x300),
    };
    for encoding in ALL {
        for (format, bytes, raw) in format_cases(encoding) {
            for (application, base) in [
                (0, 0),
                (DW_EH_PE_PCREL, 0x1000),
                (DW_EH_PE_TEXTREL, 0x100),
                (DW_EH_PE_DATAREL, 0x200),
                (DW_EH_PE_FUNCREL, 0x300),
            ] {
                for pe in [
                    format | application,
                    DW_EH_PE_INDIRECT | format | application,
                ] {
                    let mut offset = 0;
                    let value =
                        read_encoded_pointer(&bytes, &mut offset, encoding, pe, 0x1000, &bases);
                    let expected = wrap_address(encoding, raw.wrapping_add(base));
                    assert_eq!(value.unwrap(), Some(expected), "{encoding:?} {pe:#x}");
                    assert_eq!(offset, bytes.len(), "{encoding:?} {pe:#x}");
                }
            }
            let mut offset = 0;
            let err = read_encoded_pointer(
                &bytes[..bytes.len() - 1],
                &mut offset,
                encoding,
                format,
                0,
                &bases,
            )
            .unwrap_err();
            assert!(
                matches!(err.kind(), ErrorKind::BufferTooSmall { .. }),
                "{encoding:?} {format:#x}"
            );
            assert_eq!(offset, 0);
        }
    }
}

#[test]
fn encoded_pointer_sizes() {
    for encoding in ALL {
        for (format, bytes, _) in format_cases(encoding) {
            let expected = match format {
                DW_EH_PE_ULEB128 | DW_EH_PE_SLEB128 => None,
                _ => Some(bytes.len()),
            };
            for pe in [format, DW_EH_PE_PCREL | format, DW_EH_PE_INDIRECT | format] {
                assert_eq!(encoded_pointer_size(encoding, pe), expected, "{pe:#x}");
            }
        }
        let addr_size = Some(encoding.addr_size());
        assert_eq!(encoded_pointer_size(encoding, DW_EH_PE_ALIGNED), addr_size);
        assert_eq!(
            encoded_pointer_size(encoding, DW_EH_PE_ALIGNED | DW_EH_PE_UDATA2),
            addr_size
        );
        assert_eq!(encoded_pointer_size(encoding, DW_EH_PE_OMIT), None);
        assert_eq!(encoded_pointer_size(encoding, 0x0d), None);
    }
}

#[test]
fn unknown_pointer_application_errors() {
    let bases = PointerBases::default();
    for encoding in ALL {
        for application in [0x60, 0x70] {
            let mut offset = 0;
            let err = read_encoded_pointer(
                &[0; 8],
                &mut offset,
                encoding,
                application | DW_EH_PE_UDATA4,
                0x1234,
                &bases,
            )
            .unwrap_err();
            assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
            assert_eq!(err.context().unwrap().address, Some(0x1234));
            assert_eq!(offset, 0);
        }
    }
}

#[test]
fn missing_base_errors() {
    let bases = PointerBases::default();
    for application in [DW_EH_PE_TEXTREL, DW_EH_PE_DATAREL, DW_EH_PE_FUNCREL] {
        let mut offset = 0;
        let err = read_encoded_pointer(
            &[0; 4],
            &mut offset,
            Encoding::ELF64_LE,
            application | DW_EH_PE_UDATA4,
            0x40,
            &bases,
        )
        .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
        assert_eq!(err.context().unwrap().address, Some(0x40));
        assert_eq!(offset, 0);
    }
}

#[test]
fn unknown_pointer_format_errors() {
    for format in [0x05, 0x06, 0x07, 0x0d, 0x0e, 0x0f] {
        let err = read_encoded_pointer(
            &[0; 8],
            &mut 0,
            Encoding::ELF32_LE,
            format,
            0,
            &PointerBases::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err.kind(), ErrorKind::InvalidTable(_)),
            "{format:#x}"
        );
    }
}

#[test]
fn aligned_pointer() {
    let bases = PointerBases::default();
    for encoding in [Encoding::ELF32_LE, Encoding::ELF64_BE] {
        let size = encoding.addr_size();
        let mut bytes = vec![0; size];
        encoding.write_addr(&mut bytes, 0x1234_5678).unwrap();
        for (start, field) in [
            (1, 0x1001),
            (size - 1, 0x1000 + u64::try_from(size - 1).unwrap()),
        ] {
            let mut offset = start;
            let value = read_encoded_pointer(
                &bytes,
                &mut offset,
                encoding,
                DW_EH_PE_ALIGNED,
                field,
                &bases,
            )
            .unwrap();
            assert_eq!(value, Some(0x1234_5678));
            assert_eq!(offset, 2 * size);
        }
        // An aligned field needs no padding.
        let mut offset = size;
        let value = read_encoded_pointer(
            &bytes,
            &mut offset,
            encoding,
            DW_EH_PE_ALIGNED,
            0x1000,
            &bases,
        )
        .unwrap();
        assert_eq!(value, Some(0x1234_5678));
        // The padding moves the offset past the end of the address space.
        let mut offset = usize::MAX;
        let err = read_encoded_pointer(
            &bytes,
            &mut offset,
            encoding,
            DW_EH_PE_ALIGNED,
            0x1001,
            &bases,
        )
        .unwrap_err();
        assert!(matches!(err.kind(), ErrorKind::BufferTooSmall { .. }));
        assert_eq!(offset, usize::MAX);
    }
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

/// Redundant zero groups after bit 63 are valid padding.
#[test]
fn uleb128_padding_past_64_bits() {
    let mut padded = vec![0x81];
    padded.extend_from_slice(&[0x80; 11]);
    padded.push(0x00);
    let mut offset = 0;
    assert_eq!(read_uleb128(&padded, &mut offset).unwrap(), 1);
    assert_eq!(offset, padded.len());
}

#[test]
fn uleb128_overflow_errors() {
    let mut too_big = vec![0xff; 9];
    too_big.push(0x02);
    let mut offset = 0;
    let err = read_uleb128(&too_big, &mut offset).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    assert_eq!(offset, 0);
    let mut too_long = vec![0x80; 10];
    too_long.push(0x01);
    let mut offset = 0;
    let err = read_uleb128(&too_long, &mut offset).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    let err = read_uleb128(&[0x80, 0x80], &mut 0).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::BufferTooSmall { .. }));
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

/// Redundant sign groups after bit 63 are valid padding.
#[test]
fn sleb128_padding_past_64_bits() {
    let mut negative = vec![0xff; 11];
    negative.push(0x7f);
    let mut offset = 0;
    assert_eq!(read_sleb128(&negative, &mut offset).unwrap(), -1);
    assert_eq!(offset, negative.len());
    let mut positive = vec![0x81];
    positive.extend_from_slice(&[0x80; 10]);
    positive.push(0x00);
    let mut offset = 0;
    assert_eq!(read_sleb128(&positive, &mut offset).unwrap(), 1);
    assert_eq!(offset, positive.len());
}

#[test]
fn sleb128_overflow_errors() {
    let mut too_big = vec![0x80; 9];
    too_big.push(0x01);
    let err = read_sleb128(&too_big, &mut 0).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    let mut too_long = vec![0xff; 10];
    too_long.push(0x00);
    let err = read_sleb128(&too_long, &mut 0).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::InvalidTable(_)));
    let err = read_sleb128(&[0xff], &mut 0).unwrap_err();
    assert!(matches!(err.kind(), ErrorKind::BufferTooSmall { .. }));
}
