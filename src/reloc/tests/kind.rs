//! Tests of the relocation actions and field widths.

use super::*;

#[test]
fn x86_64_types_have_their_action_and_width() {
    for (r_type, kind, width) in [
        (x86_64::R_X86_64_NONE, RelocationKind::None, Some(0)),
        (x86_64::R_X86_64_64, RelocationKind::Absolute, Some(8)),
        (x86_64::R_X86_64_PC32, RelocationKind::Other, Some(4)),
        (x86_64::R_X86_64_PLT32, RelocationKind::Other, Some(4)),
        (x86_64::R_X86_64_COPY, RelocationKind::Copy, None),
        (
            x86_64::R_X86_64_GLOB_DAT,
            RelocationKind::GlobalData,
            Some(8),
        ),
        (
            x86_64::R_X86_64_JUMP_SLOT,
            RelocationKind::JumpSlot,
            Some(8),
        ),
        (x86_64::R_X86_64_RELATIVE, RelocationKind::Relative, Some(8)),
        (x86_64::R_X86_64_16, RelocationKind::Other, Some(2)),
        (x86_64::R_X86_64_PC8, RelocationKind::Other, Some(1)),
        (x86_64::R_X86_64_DTPMOD64, RelocationKind::Tls, Some(8)),
        (x86_64::R_X86_64_DTPOFF64, RelocationKind::Tls, Some(8)),
        (x86_64::R_X86_64_TPOFF64, RelocationKind::Tls, Some(8)),
        (x86_64::R_X86_64_TLSDESC_CALL, RelocationKind::Other, None),
        (x86_64::R_X86_64_TLSDESC, RelocationKind::Tls, Some(16)),
        (
            x86_64::R_X86_64_IRELATIVE,
            RelocationKind::IndirectRelative,
            Some(8),
        ),
        (
            x86_64::R_X86_64_RELATIVE64,
            RelocationKind::Relative,
            Some(8),
        ),
        (
            x86_64::R_X86_64_REX_GOTPCRELX,
            RelocationKind::Other,
            Some(4),
        ),
        (0xff, RelocationKind::Other, None),
    ] {
        let relocation = Relocation::with_addend(0x1000, 0, r_type, 0);
        assert_eq!(relocation.kind(Machine::X86_64), kind, "type {r_type}");
        assert_eq!(
            relocation.width(Machine::X86_64, Class::Elf64),
            width,
            "type {r_type}"
        );
    }
}

#[test]
fn x32_word_types_are_four_bytes_wide() {
    for (r_type, width) in [
        (x86_64::R_X86_64_GLOB_DAT, 4),
        (x86_64::R_X86_64_JUMP_SLOT, 4),
        (x86_64::R_X86_64_RELATIVE, 4),
        (x86_64::R_X86_64_IRELATIVE, 4),
        (x86_64::R_X86_64_TLSDESC, 8),
        // A `word64` field keeps its width in ELF32.
        (x86_64::R_X86_64_64, 8),
    ] {
        assert_eq!(
            relocation_width(Machine::X86_64, Class::Elf32, r_type),
            Some(width),
            "type {r_type}"
        );
    }
}

#[test]
fn i386_types_have_their_action_and_width() {
    for (r_type, kind, width) in [
        (i386::R_386_NONE, RelocationKind::None, Some(0)),
        (i386::R_386_32, RelocationKind::Absolute, Some(4)),
        (i386::R_386_PC32, RelocationKind::Other, Some(4)),
        (i386::R_386_COPY, RelocationKind::Copy, None),
        (i386::R_386_GLOB_DAT, RelocationKind::GlobalData, Some(4)),
        (i386::R_386_JMP_SLOT, RelocationKind::JumpSlot, Some(4)),
        (i386::R_386_RELATIVE, RelocationKind::Relative, Some(4)),
        (i386::R_386_TLS_TPOFF, RelocationKind::Tls, Some(4)),
        (i386::R_386_16, RelocationKind::Other, Some(2)),
        (i386::R_386_PC8, RelocationKind::Other, Some(1)),
        (i386::R_386_TLS_DTPMOD32, RelocationKind::Tls, Some(4)),
        (i386::R_386_TLS_DTPOFF32, RelocationKind::Tls, Some(4)),
        (i386::R_386_TLS_TPOFF32, RelocationKind::Tls, Some(4)),
        (i386::R_386_TLS_DESC_CALL, RelocationKind::Other, None),
        (i386::R_386_TLS_DESC, RelocationKind::Tls, Some(8)),
        (
            i386::R_386_IRELATIVE,
            RelocationKind::IndirectRelative,
            Some(4),
        ),
        (0xff, RelocationKind::Other, None),
    ] {
        assert_eq!(
            relocation_kind(Machine::I386, r_type),
            kind,
            "type {r_type}"
        );
        assert_eq!(
            relocation_width(Machine::I386, Class::Elf32, r_type),
            width,
            "type {r_type}"
        );
    }
}

/// The type values of the machines differ: 37 is `R_X86_64_IRELATIVE` but
/// `R_386_TLS_TPOFF32`, and 42 is `R_386_IRELATIVE` but `R_X86_64_REX_GOTPCRELX`.
#[test]
fn the_machine_selects_the_meaning_of_a_type_value() {
    assert_eq!(
        relocation_kind(Machine::X86_64, 37),
        RelocationKind::IndirectRelative
    );
    assert_eq!(relocation_kind(Machine::I386, 37), RelocationKind::Tls);
    assert_eq!(
        relocation_kind(Machine::I386, 42),
        RelocationKind::IndirectRelative
    );
    assert_eq!(relocation_kind(Machine::X86_64, 42), RelocationKind::Other);
}

#[test]
fn other_machines_are_not_classified() {
    let relative = aarch64::R_AARCH64_RELATIVE;
    assert_eq!(
        relocation_kind(Machine::AARCH64, relative),
        RelocationKind::Other
    );
    assert_eq!(
        relocation_width(Machine::AARCH64, Class::Elf64, relative),
        None
    );
}

#[test]
fn tls_types_name_the_value_that_they_write() {
    use TlsRelocationKind::{
        Descriptor, ModuleId, ModuleOffset, NegatedThreadPointerOffset, ThreadPointerOffset,
    };
    for (machine, r_type, kind) in [
        (Machine::X86_64, x86_64::R_X86_64_DTPMOD64, ModuleId),
        (Machine::X86_64, x86_64::R_X86_64_DTPOFF64, ModuleOffset),
        (Machine::X86_64, x86_64::R_X86_64_DTPOFF32, ModuleOffset),
        (
            Machine::X86_64,
            x86_64::R_X86_64_TPOFF64,
            ThreadPointerOffset,
        ),
        (
            Machine::X86_64,
            x86_64::R_X86_64_TPOFF32,
            ThreadPointerOffset,
        ),
        (Machine::X86_64, x86_64::R_X86_64_TLSDESC, Descriptor),
        (Machine::I386, i386::R_386_TLS_DTPMOD32, ModuleId),
        (Machine::I386, i386::R_386_TLS_DTPOFF32, ModuleOffset),
        (Machine::I386, i386::R_386_TLS_LDO_32, ModuleOffset),
        (Machine::I386, i386::R_386_TLS_TPOFF, ThreadPointerOffset),
        (Machine::I386, i386::R_386_TLS_LE, ThreadPointerOffset),
        (
            Machine::I386,
            i386::R_386_TLS_TPOFF32,
            NegatedThreadPointerOffset,
        ),
        (
            Machine::I386,
            i386::R_386_TLS_LE_32,
            NegatedThreadPointerOffset,
        ),
        (Machine::I386, i386::R_386_TLS_DESC, Descriptor),
    ] {
        let relocation = Relocation::new(0x1000, 1, r_type);
        assert_eq!(
            relocation.tls_kind(machine),
            Some(kind),
            "{machine} type {r_type}"
        );
    }
}

#[test]
fn other_types_write_no_tls_value() {
    for (machine, r_type) in [
        (Machine::X86_64, x86_64::R_X86_64_RELATIVE),
        (Machine::X86_64, x86_64::R_X86_64_GOTTPOFF),
        (Machine::X86_64, x86_64::R_X86_64_TLSGD),
        (Machine::X86_64, x86_64::R_X86_64_TLSDESC_CALL),
        (Machine::I386, i386::R_386_RELATIVE),
        (Machine::I386, i386::R_386_TLS_IE),
        (Machine::I386, i386::R_386_TLS_DESC_CALL),
        (Machine::AARCH64, aarch64::R_AARCH64_TLS_DTPMOD),
    ] {
        assert_eq!(
            tls_relocation_kind(machine, r_type),
            None,
            "{machine} type {r_type}"
        );
    }
}
