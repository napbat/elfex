//! Compare the notes, the section groups and the symbol versions.

use std::borrow::Cow;
use std::fmt::Write;

use elfex::{ElfFile, StringTable};
use serde_json::Value;

use crate::reference::{Definition, Group, Reference, Requirement, array, get, number, string};
use crate::report::{Findings, GROUPS, NOTES, VERSIONS};

/// The `VER_FLG_BASE` flag of a version definition.
const VER_FLG_BASE: u16 = 1;

/// The `GRP_COMDAT` flag of a section group.
const GRP_COMDAT: u32 = 1;

/// The note type names that `llvm-readelf` prints, with their values.
const NOTE_TYPES: &[(&str, u32)] = &[
    ("NT_VERSION", 1),
    ("NT_ARCH", 2),
    ("NT_GNU_ABI_TAG", 1),
    ("NT_GNU_HWCAP", 2),
    ("NT_GNU_BUILD_ID", 3),
    ("NT_GNU_GOLD_VERSION", 4),
    ("NT_GNU_PROPERTY_TYPE_0", 5),
    ("NT_GNU_BUILD_ATTRIBUTE_OPEN", 0x100),
    ("NT_GNU_BUILD_ATTRIBUTE_FUNC", 0x101),
    ("NT_STAPSDT", 3),
    ("NT_FREEBSD_ABI_TAG", 1),
    ("NT_NETBSD_IDENT", 1),
    ("NT_ANDROID_TYPE_IDENT", 1),
    ("NT_ANDROID_TYPE_KUSER", 3),
    ("NT_ANDROID_TYPE_MEMTAG", 4),
    ("FDO_PACKAGING_METADATA", 0xcafe_1a7e),
    // `llvm-readelf` and GNU readelf name types 0x100 and 0x101 as the GNU build attribute
    // notes for all owners. The Linux kernel uses these values for `LINUX_ELFNOTE_BUILD_SALT`
    // and `LINUX_ELFNOTE_LTO_INFO` in `.note.Linux`.
    ("OPEN", 0x100),
    ("func", 0x101),
    ("NT_PRSTATUS", 1),
    ("NT_FPREGSET", 2),
    ("NT_PRPSINFO", 3),
    ("NT_TASKSTRUCT", 4),
    ("NT_AUXV", 6),
    ("NT_PSTATUS", 10),
    ("NT_FPREGS", 12),
    ("NT_PSINFO", 13),
    ("NT_LWPSTATUS", 16),
    ("NT_LWPSINFO", 17),
    ("NT_WIN32PSTATUS", 18),
    ("NT_FILE", 0x4649_4c45),
    ("NT_PRXFPREG", 0x46e6_2b7f),
    ("NT_SIGINFO", 0x5349_4749),
    ("NT_386_TLS", 0x200),
    ("NT_386_IOPERM", 0x201),
    ("NT_X86_XSTATE", 0x202),
    ("NT_ARM_VFP", 0x400),
    ("NT_ARM_TLS", 0x401),
    ("NT_ARM_HW_BREAK", 0x402),
    ("NT_ARM_HW_WATCH", 0x403),
    ("NT_ARM_SVE", 0x405),
    ("NT_ARM_PAC_MASK", 0x406),
    ("NT_ARM_TAGGED_ADDR_CTRL", 0x409),
];

/// Compare the notes, the section groups and the version tables.
pub fn compare(file: &ElfFile, reference: &Reference, findings: &mut Findings) {
    notes(file, &reference.json, findings);
    groups(file, &reference.text.groups, findings);
    versions(
        file,
        &reference.text.definitions,
        &reference.text.requirements,
        findings,
    );
}

/// Return the value of a note type string, for example
/// `"NT_GNU_BUILD_ID (unique build ID bitstring)"` or `"Unknown note type: (0x00000100)"`.
fn note_type(text: &str) -> Option<u32> {
    if let Some((_, hex)) = text.rsplit_once("(0x") {
        return u32::from_str_radix(hex.trim_end_matches(')'), 16).ok();
    }
    let name = text.split_whitespace().next()?;
    NOTE_TYPES
        .iter()
        .find(|(known, _)| *known == name)
        .map(|(_, value)| *value)
}

/// Return the bytes as lowercase hexadecimal digits.
fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// Compare the notes of all note sections, or of all note segments.
fn notes(file: &ElfFile, json: &Value, findings: &mut Findings) {
    let notes = match file.notes() {
        Ok(notes) => notes,
        Err(error) => {
            findings.fail(NOTES, format!("notes: {error}"));
            return;
        }
    };
    let items: Vec<&Value> = array(json, &["NoteSections"])
        .iter()
        .flat_map(|section| array(section, &["NoteSection", "Notes"]))
        .collect();
    findings.check(NOTES, "note count", items.len(), notes.len());
    for (index, (item, note)) in items.iter().zip(&notes).enumerate() {
        let what = format!("note {index}");
        // A Go build ID note has `n_namesz` 4 for "Go": the name has two NUL bytes.
        // `llvm-readelf` removes only the last NUL, and elfex ends the name at the first NUL,
        // as GNU readelf does.
        findings.check(
            NOTES,
            format_args!("{what} owner"),
            string(item, &["Owner"])
                .ok()
                .map(|owner| owner.trim_end_matches('\0')),
            note.name_str(),
        );
        findings.check(
            NOTES,
            format_args!("{what} size"),
            number(item, &["Data size"]).ok(),
            u64::try_from(note.desc.len()).ok(),
        );
        match string(item, &["Type"]).map(|text| (text, note_type(text))) {
            Ok((_, Some(value))) => {
                findings.check(NOTES, format_args!("{what} type"), value, note.n_type);
            }
            Ok((text, None)) => {
                findings.fail(
                    NOTES,
                    format!("{what}: unknown type name {text:?} in the harness"),
                );
            }
            Err(error) => findings.fail(NOTES, format!("{what}: {error}")),
        }
        if let Some(build_id) = get(item, &["Build ID"]).and_then(Value::as_str) {
            findings.check(
                NOTES,
                format_args!("{what} build ID"),
                build_id.to_owned(),
                hex_string(&note.desc),
            );
        }
        if get(item, &["Mappings"]).is_some() {
            file_mappings(file, item, findings);
        }
    }
}

/// Compare the `NT_FILE` mappings of a core file. The reference gives the file offset in
/// pages, and elfex in bytes.
fn file_mappings(file: &ElfFile, item: &Value, findings: &mut Findings) {
    let (page_size, mappings) = match file.core_file_mappings() {
        Ok(Some(found)) => found,
        Ok(None) => {
            findings.fail(NOTES, "core_file_mappings gives None");
            return;
        }
        Err(error) => {
            findings.fail(NOTES, format!("core_file_mappings: {error}"));
            return;
        }
    };
    findings.check(
        NOTES,
        "NT_FILE page size",
        number(item, &["Page Size"]).ok(),
        Some(page_size),
    );
    let expected: Vec<_> = array(item, &["Mappings"])
        .iter()
        .map(|mapping| {
            (
                number(mapping, &["Start"]).ok(),
                number(mapping, &["End"]).ok(),
                number(mapping, &["Offset"])
                    .ok()
                    .and_then(|pages| pages.checked_mul(page_size)),
                string(mapping, &["Filename"]).ok().map(str::to_owned),
            )
        })
        .collect();
    let actual: Vec<_> = mappings
        .into_iter()
        .map(|mapping| {
            (
                Some(mapping.start),
                Some(mapping.end),
                Some(mapping.file_offset),
                Some(mapping.path),
            )
        })
        .collect();
    findings.check(NOTES, "NT_FILE mappings", expected, actual);
}

/// Compare the section groups.
fn groups(file: &ElfFile, expected: &[Group], findings: &mut Findings) {
    let groups = match file.section_groups() {
        Ok(groups) => groups,
        Err(error) => {
            findings.fail(GROUPS, format!("section_groups: {error}"));
            return;
        }
    };
    let actual: Vec<Group> = groups
        .into_iter()
        .map(|group| Group {
            index: group.index,
            comdat: group.flags == GRP_COMDAT,
            signature: group.signature.unwrap_or_default(),
            members: group.members,
        })
        .collect();
    findings.check(GROUPS, "section groups", expected, actual.as_slice());
}

/// Compare the version definitions and the version requirements.
fn versions(
    file: &ElfFile,
    definitions: &[Definition],
    requirements: &[Requirement],
    findings: &mut Findings,
) {
    let (tables, strings) = match (file.version_tables(), file.dynamic_strings()) {
        (Ok(tables), Ok(strings)) => (
            tables,
            strings.unwrap_or_else(|| StringTable::new(Vec::new())),
        ),
        (Err(error), _) | (_, Err(error)) => {
            findings.fail(VERSIONS, format!("version_tables: {error}"));
            return;
        }
    };
    let name = |offset: u32| {
        strings
            .get_lossy(offset)
            .map_or_else(|error| format!("<{error}>"), Cow::into_owned)
    };
    let actual: Vec<Definition> = tables
        .definitions
        .iter()
        .flat_map(|table| &table.definitions)
        .map(|definition| Definition {
            index: definition.index,
            base: definition.flags & VER_FLG_BASE != 0,
            name: definition.name().map(name).unwrap_or_default(),
        })
        .collect();
    findings.check(
        VERSIONS,
        "version definitions",
        definitions,
        actual.as_slice(),
    );
    let actual: Vec<Requirement> = tables
        .requirements
        .iter()
        .flat_map(|table| &table.requirements)
        .map(|requirement| Requirement {
            file: name(requirement.file),
            entries: requirement
                .entries
                .iter()
                .map(|entry| (name(entry.name), entry.index))
                .collect(),
        })
        .collect();
    findings.check(
        VERSIONS,
        "version requirements",
        requirements,
        actual.as_slice(),
    );
}
