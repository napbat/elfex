//! Compare the parsed file with the output of the reference tool.

mod notes;
mod relocations;
mod symbols;

use elfex::{DynamicTag, ElfFile, Endian};
use serde_json::Value;

use crate::reference::{self, Reference, array, number};
use crate::report::{DYNAMIC, Findings, HEADER, SECTIONS, SEGMENTS};

/// Compare all items of `file` with `reference`.
pub fn compare(file: &ElfFile, reference: &Reference, findings: &mut Findings) {
    let json = &reference.json;
    header(file, json, findings);
    sections(file, json, findings);
    segments(file, json, findings);
    dynamic(file, json, findings);
    symbols::compare(file, json, findings);
    relocations::compare(file, reference, findings);
    notes::compare(file, reference, findings);
}

/// Compare the numbers at the paths below `item` with the values of elfex.
fn numbers(
    findings: &mut Findings,
    category: &'static str,
    what: &str,
    item: &Value,
    fields: &[(&[&str], u64)],
) {
    for (path, actual) in fields {
        match number(item, path) {
            Ok(expected) => findings.check(
                category,
                format_args!("{what} {}", path.join(".")),
                expected,
                *actual,
            ),
            Err(error) => findings.fail(category, format!("{what}: {error}")),
        }
    }
}

/// Compare the file header (`ElfHeader`).
fn header(file: &ElfFile, json: &Value, findings: &mut Findings) {
    let Some(item) = reference::get(json, &["ElfHeader"]) else {
        findings.fail(HEADER, "the reference has no ElfHeader");
        return;
    };
    let header = file.header();
    let ident = header.ident;
    let class = if file.is_64bit() { 2 } else { 1 };
    let data = if ident.endian == Endian::Little { 1 } else { 2 };
    // The type is a string, for example "SharedObject (0x3)".
    let file_type = reference::string(item, &["Type"]).map(|text| {
        let hex = text
            .rsplit_once("(0x")
            .map_or(text, |(_, rest)| rest.trim_end_matches(')'));
        reference::hex(hex)
    });
    findings.check(
        HEADER,
        "Type",
        file_type,
        Ok(Some(u64::from(header.file_type.0))),
    );
    numbers(
        findings,
        HEADER,
        "file header",
        item,
        &[
            (&["Ident", "Class", "Value"], class),
            (&["Ident", "DataEncoding", "Value"], data),
            (&["Ident", "FileVersion"], u64::from(ident.version)),
            (&["Ident", "OS/ABI", "Value"], u64::from(ident.os_abi.0)),
            (&["Ident", "ABIVersion"], u64::from(ident.abi_version)),
            (&["Machine", "Value"], u64::from(header.machine.0)),
            (&["Version"], u64::from(header.version)),
            (&["Entry"], header.entry),
            (&["ProgramHeaderOffset"], header.phoff),
            (&["SectionHeaderOffset"], header.shoff),
            (&["Flags", "Value"], u64::from(header.flags)),
            (&["HeaderSize"], u64::from(header.ehsize)),
            (&["ProgramHeaderEntrySize"], u64::from(header.phentsize)),
            (&["ProgramHeaderCount"], u64::from(header.phnum)),
            (&["SectionHeaderEntrySize"], u64::from(header.shentsize)),
            (&["SectionHeaderCount"], u64::from(header.shnum)),
            (&["StringTableSectionIndex"], u64::from(header.shstrndx)),
        ],
    );
}

/// Compare the section headers and the section names.
fn sections(file: &ElfFile, json: &Value, findings: &mut Findings) {
    let items = array(json, &["Sections"]);
    let headers = file.section_headers();
    findings.check(SECTIONS, "section count", items.len(), headers.len());
    for (index, (item, header)) in items.iter().zip(headers).enumerate() {
        let item = &item["Section"];
        let what = format!("section {index}");
        let name = file.section_names().get(index).map(String::as_str);
        findings.check(
            SECTIONS,
            format_args!("{what} name"),
            reference::string(item, &["Name", "Name"]).ok(),
            name,
        );
        numbers(
            findings,
            SECTIONS,
            &what,
            item,
            &[
                (&["Index"], index as u64),
                (&["Name", "Value"], u64::from(header.name)),
                (&["Type", "Value"], u64::from(header.section_type.0)),
                (&["Flags", "Value"], header.flags),
                (&["Address"], header.addr),
                (&["Offset"], header.offset),
                (&["Size"], header.size),
                (&["Link"], u64::from(header.link)),
                (&["Info"], u64::from(header.info)),
                (&["AddressAlignment"], header.addralign),
                (&["EntrySize"], header.entsize),
            ],
        );
    }
}

/// Compare the program headers.
fn segments(file: &ElfFile, json: &Value, findings: &mut Findings) {
    let items = array(json, &["ProgramHeaders"]);
    let headers = file.program_headers();
    findings.check(SEGMENTS, "program header count", items.len(), headers.len());
    for (index, (item, header)) in items.iter().zip(headers).enumerate() {
        numbers(
            findings,
            SEGMENTS,
            &format!("program header {index}"),
            &item["ProgramHeader"],
            &[
                (&["Type", "Value"], u64::from(header.segment_type.0)),
                (&["Offset"], header.offset),
                (&["VirtualAddress"], header.vaddr),
                (&["PhysicalAddress"], header.paddr),
                (&["FileSize"], header.filesz),
                (&["MemSize"], header.memsz),
                (&["Flags", "Value"], u64::from(header.flags)),
                (&["Alignment"], header.align),
            ],
        );
    }
}

/// Compare the dynamic table, the needed libraries, the soname and the run paths.
fn dynamic(file: &ElfFile, json: &Value, findings: &mut Findings) {
    let items = array(json, &["DynamicSection"]);
    let reference: Vec<(u64, u64)> = items
        .iter()
        .map(|item| {
            (
                number(item, &["Tag"]).unwrap_or(u64::MAX),
                number(item, &["Value"]).unwrap_or(u64::MAX),
            )
        })
        .take_while(|(tag, _)| *tag != 0)
        .collect();
    let entries: Vec<(u64, u64)> = match file.dynamic() {
        Ok(table) => table
            .map(|table| table.entries)
            .unwrap_or_default()
            .iter()
            .map(|entry| (entry.tag.0.cast_unsigned(), entry.value))
            .take_while(|(tag, _)| *tag != 0)
            .collect(),
        Err(error) => {
            findings.fail(DYNAMIC, format!("ElfFile::dynamic: {error}"));
            return;
        }
    };
    findings.check(
        DYNAMIC,
        "dynamic entry count",
        reference.len(),
        entries.len(),
    );
    for (index, (expected, actual)) in reference.iter().zip(&entries).enumerate() {
        findings.check(
            DYNAMIC,
            format_args!("dynamic entry {index}"),
            expected,
            actual,
        );
    }

    // The reference gives the string of a DT_NEEDED or DT_SONAME entry in the field `Library`
    // or `Name`. It splits a DT_RPATH or DT_RUNPATH string at each ':' into the array `Path`.
    let strings = |tag: DynamicTag| -> Vec<String> {
        items
            .iter()
            .filter(|item| number(item, &["Tag"]).ok() == Some(tag.0.cast_unsigned()))
            .filter_map(|item| {
                ["Library", "Name", "Path"]
                    .iter()
                    .find_map(|key| item.get(key))
                    .and_then(|value| match value {
                        Value::String(text) => Some(text.clone()),
                        Value::Array(parts) => parts
                            .iter()
                            .map(|part| part.as_str())
                            .collect::<Option<Vec<_>>>()
                            .map(|parts| parts.join(":")),
                        _ => None,
                    })
            })
            .collect()
    };
    let first = |tag| strings(tag).into_iter().next();
    if let Some(needed) = ok(file.needed_libraries(), "needed_libraries", findings) {
        findings.check(
            DYNAMIC,
            "needed libraries",
            strings(DynamicTag::NEEDED),
            needed,
        );
    }
    if let Some(soname) = ok(file.soname(), "soname", findings) {
        findings.check(DYNAMIC, "soname", first(DynamicTag::SONAME), soname);
    }
    // The reference drops the empty parts of a search path, for example after a final ':'.
    let parts = |path: Option<String>| {
        path.map(|path| {
            path.split(':')
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
    };
    if let Some(rpath) = ok(file.rpath(), "rpath", findings) {
        let expected = parts(first(DynamicTag::RPATH));
        findings.check(DYNAMIC, "rpath", expected, parts(rpath));
    }
    if let Some(runpath) = ok(file.runpath(), "runpath", findings) {
        let expected = parts(first(DynamicTag::RUNPATH));
        findings.check(DYNAMIC, "runpath", expected, parts(runpath));
    }
}

/// Return the value of `result`, or record its error in the dynamic category.
fn ok<T>(result: elfex::Result<T>, what: &str, findings: &mut Findings) -> Option<T> {
    result
        .map_err(|error| findings.fail(DYNAMIC, format!("{what}: {error}")))
        .ok()
}
