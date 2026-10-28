//! Compare the relocation sections and the relocation tables of the dynamic table.

use std::collections::BTreeMap;

use elfex::{DynamicTag, ElfFile, Machine, Relocation, RelocationSection, RelrTable, SectionType};
use serde_json::Value;

use super::numbers;
use super::symbols::display_name;
use crate::reference::{Reference, array, get, number, string};
use crate::report::{DYNAMIC_RELOCATIONS, Findings, RELOCATIONS};

/// `SHT_ANDROID_RELR`: the Android variant of `SHT_RELR`.
const SHT_ANDROID_RELR: u32 = 0x6fff_ff00;

/// Compare the relocation sections (`Relocations`) and the relocation tables of the dynamic
/// table (`--dyn-relocations`).
pub fn compare(file: &ElfFile, reference: &Reference, findings: &mut Findings) {
    sections(file, &reference.json, findings);
    dynamic(file, reference, findings);
}

/// Compare each relocation section.
fn sections(file: &ElfFile, json: &Value, findings: &mut Findings) {
    let list = match file.relocation_sections() {
        Ok(list) => list,
        Err(error) => {
            findings.fail(RELOCATIONS, format!("relocation_sections: {error}"));
            return;
        }
    };
    let mut by_index: BTreeMap<usize, &RelocationSection> = list
        .iter()
        .map(|section| (section.index, section))
        .collect();
    let mut names = SymbolNames::default();
    for item in array(json, &["Relocations"]) {
        let Ok(Ok(index)) = number(item, &["SectionIndex"]).map(usize::try_from) else {
            findings.fail(RELOCATIONS, format!("bad SectionIndex in {item}"));
            continue;
        };
        let entries = array(item, &["Relocs"]);
        let section_type = file
            .section_headers()
            .get(index)
            .map(|header| header.section_type);
        match section_type {
            Some(SectionType::REL | SectionType::RELA) => match by_index.remove(&index) {
                Some(section) => {
                    let names = names.for_table(file, section.symbol_table, findings);
                    table(file, section, entries, names, findings);
                }
                None => findings.fail(RELOCATIONS, format!("section {index} is not listed")),
            },
            Some(kind) if kind == SectionType::RELR || kind.0 == SHT_ANDROID_RELR => {
                relr_section(file, index, entries, findings);
            }
            other => findings.fail(
                RELOCATIONS,
                format!("section {index} of type {other:?} is not a supported relocation section"),
            ),
        }
    }
    for index in by_index.keys() {
        findings.fail(
            RELOCATIONS,
            format!("the reference does not list relocation section {index}"),
        );
    }
}

/// Compare the entries of one `SHT_REL` or `SHT_RELA` section.
fn table(
    file: &ElfFile,
    section: &RelocationSection,
    entries: &[Value],
    names: &[String],
    findings: &mut Findings,
) {
    let relocations = &section.table.relocations;
    findings.check(
        RELOCATIONS,
        format_args!("section {} entry count", section.index),
        entries.len(),
        relocations.len(),
    );
    let machine = file.machine();
    for (number_in_table, (item, relocation)) in entries.iter().zip(relocations).enumerate() {
        let item = &item["Relocation"];
        let what = format!("section {} entry {number_in_table}", section.index);
        numbers(
            findings,
            RELOCATIONS,
            &what,
            item,
            &[
                (&["Offset"], relocation.offset),
                (&["Type", "Value"], u64::from(relocation.r_type)),
                (&["Symbol", "Value"], u64::from(relocation.symbol)),
            ],
        );
        findings.check(
            RELOCATIONS,
            format_args!("{what} type name"),
            string(item, &["Type", "Name"])
                .ok()
                .map(|name| spec_name(machine, name)),
            Some(relocation.type_name(machine).unwrap_or("Unknown")),
        );
        let addend = get(item, &["Addend"]).map(|_| number(item, &["Addend"]).ok());
        findings.check(
            RELOCATIONS,
            format_args!("{what} addend"),
            addend,
            relocation.addend.map(|addend| Some(addend.cast_unsigned())),
        );
        let symbol_name = usize::try_from(relocation.symbol)
            .ok()
            .and_then(|index| names.get(index))
            .filter(|name| !name.is_empty())
            .map_or("-", String::as_str);
        findings.check(
            RELOCATIONS,
            format_args!("{what} symbol name"),
            string(item, &["Symbol", "Name"]).ok(),
            Some(symbol_name),
        );
    }
}

/// The relocation type names of `llvm-readelf` that differ from the spec names of elfex.
///
/// - The i386 psABI and glibc name type 7 `R_386_JMP_SLOT`.
/// - The `AArch64` ELF ABI renamed `R_AARCH64_TLS_DTPMOD64` and its neighbors.
/// - The s390x ABI and glibc name type 13 `R_390_GOTOFF32`.
const TYPE_ALIASES: [(Machine, &str, &str); 5] = [
    (Machine::I386, "R_386_JUMP_SLOT", "R_386_JMP_SLOT"),
    (
        Machine::AARCH64,
        "R_AARCH64_TLS_DTPMOD64",
        "R_AARCH64_TLS_DTPMOD",
    ),
    (
        Machine::AARCH64,
        "R_AARCH64_TLS_DTPREL64",
        "R_AARCH64_TLS_DTPREL",
    ),
    (
        Machine::AARCH64,
        "R_AARCH64_TLS_TPREL64",
        "R_AARCH64_TLS_TPREL",
    ),
    (Machine::S390, "R_390_GOTOFF", "R_390_GOTOFF32"),
];

/// Return the spec name of a type name of `llvm-readelf`.
///
/// For MIPS, return the first name of a name such as `R_MIPS_REL32/R_MIPS_64/R_MIPS_NONE`.
/// An ELF64 MIPS entry has three types. `Relocation::type_name` gives the first one.
fn spec_name(machine: Machine, name: &str) -> &str {
    if machine == Machine::MIPS {
        return name.split('/').next().unwrap_or(name);
    }
    TYPE_ALIASES
        .iter()
        .find(|(alias_machine, alias, _)| *alias_machine == machine && *alias == name)
        .map_or(name, |(_, _, spec)| spec)
}

/// Compare the addresses of a `SHT_RELR` section with the decoded entries of the reference.
fn relr_section(file: &ElfFile, index: usize, entries: &[Value], findings: &mut Findings) {
    let table = file
        .section_data(index)
        .and_then(|data| RelrTable::parse(data, file.encoding()));
    let table = match table {
        Ok(table) => table,
        Err(error) => {
            findings.fail(RELOCATIONS, format!("RELR section {index}: {error}"));
            return;
        }
    };
    let expected: Vec<Option<u64>> = entries
        .iter()
        .map(|item| number(&item["Relocation"], &["Offset"]).ok())
        .collect();
    let actual: Vec<Option<u64>> = table.addresses.iter().copied().map(Some).collect();
    findings.check(
        RELOCATIONS,
        format_args!("RELR section {index} address count"),
        expected.len(),
        actual.len(),
    );
    if expected.len() == actual.len() {
        findings.check(
            RELOCATIONS,
            format_args!("RELR section {index} addresses"),
            expected,
            actual,
        );
    }
    // The table that `DT_RELR` names must give the same addresses. This also covers MIPS,
    // where the reference does not show the `DT_RELR` table (see `dynamic`).
    let address = file.section_headers().get(index).map(|header| header.addr);
    let dynamic = file.dynamic().ok().flatten();
    if dynamic.and_then(|table| table.get(DynamicTag::RELR)) == address {
        match file.dynamic_relocations() {
            Ok(relocations) => findings.check(
                DYNAMIC_RELOCATIONS,
                format_args!("DT_RELR addresses of section {index}"),
                Some(&table.addresses),
                relocations.relr.as_ref().map(|relr| &relr.addresses),
            ),
            Err(error) => findings.fail(DYNAMIC_RELOCATIONS, format!("{error}")),
        }
    }
}

/// The display names of the symbol tables, by section index.
#[derive(Default)]
struct SymbolNames {
    /// The names of each symbol table that a relocation section links to.
    tables: BTreeMap<Option<usize>, Vec<String>>,
}

impl SymbolNames {
    /// Return the display names of the symbol table at `index`, with an empty name at index 0.
    fn for_table(
        &mut self,
        file: &ElfFile,
        index: Option<usize>,
        findings: &mut Findings,
    ) -> &[String] {
        self.tables.entry(index).or_insert_with(|| {
            let section_type = index
                .and_then(|index| file.section_headers().get(index))
                .map(|header| header.section_type);
            let (list, dynamic) = match section_type {
                Some(SectionType::DYNSYM) => (file.dynamic_symbol_list(), true),
                Some(SectionType::SYMTAB) => (file.symbol_list(), false),
                _ => return Vec::new(),
            };
            match list {
                Ok(list) => std::iter::once(String::new())
                    .chain(
                        list.iter()
                            .map(|symbol| display_name(file, symbol, dynamic)),
                    )
                    .collect(),
                Err(error) => {
                    findings.fail(RELOCATIONS, format!("symbol table {index:?}: {error}"));
                    Vec::new()
                }
            }
        })
    }
}

/// Compare the relocation tables of the dynamic table with the text output of the reference.
fn dynamic(file: &ElfFile, reference: &Reference, findings: &mut Findings) {
    let relocations = match file.dynamic_relocations() {
        Ok(relocations) => relocations,
        Err(error) => {
            findings.fail(DYNAMIC_RELOCATIONS, format!("dynamic_relocations: {error}"));
            return;
        }
    };
    let encoding = file.encoding();
    let machine = file.machine();
    // `llvm-readelf` packs the three types of an ELF64 MIPS entry in its own order.
    let compare_info = !(machine == Machine::MIPS && file.is_64bit());
    let info = |relocation: &Relocation| {
        if encoding.is_64bit() {
            (u64::from(relocation.symbol) << 32) | u64::from(relocation.r_type)
        } else {
            (u64::from(relocation.symbol) << 8) | u64::from(relocation.r_type)
        }
    };
    let mut tables: BTreeMap<&str, Vec<(u64, u64)>> = BTreeMap::new();
    for (kind, table) in [
        ("RELA", &relocations.rela),
        ("REL", &relocations.rel),
        ("PLT", &relocations.plt),
    ] {
        if let Some(table) = table.as_ref().filter(|table| !table.is_empty()) {
            let entries = table
                .iter()
                .map(|entry| (entry.offset, info(entry)))
                .collect();
            tables.insert(kind, entries);
        }
    }
    // A RELR entry has no type. `llvm-readelf` shows a type that it selects (0 for PowerPC),
    // so compare only the addresses.
    if let Some(table) = relocations.relr.as_ref().filter(|table| !table.is_empty()) {
        tables.insert("RELR", table.iter().map(|address| (*address, 0)).collect());
    }
    // `llvm-readelf` reads `DT_AARCH64_AUTH_RELR` and `DT_AARCH64_AUTH_RELRSZ` (0x70000012 and
    // 0x70000011) on all machines. On MIPS, these values are `DT_MIPS_UNREFEXTNO` and
    // `DT_MIPS_SYMTABNO`, so the tool shows a wrong RELR table. `relr_section` compares the
    // `DT_RELR` table of MIPS with the `SHT_RELR` section.
    if machine == Machine::MIPS {
        tables.remove("RELR");
    }
    for expected in &reference.text.dynamic_relocations {
        let kind = expected.kind.as_str();
        if kind == "RELR" && machine == Machine::MIPS {
            continue;
        }
        let Some(actual) = tables.remove(kind) else {
            findings.fail(
                DYNAMIC_RELOCATIONS,
                format!(
                    "{kind}: the reference has {} entries, elfex none",
                    expected.entries.len()
                ),
            );
            continue;
        };
        let compare_info = compare_info && kind != "RELR";
        let strip = |entries: &[(u64, u64)]| -> Vec<(u64, u64)> {
            entries
                .iter()
                .map(|(offset, info)| (*offset, if compare_info { *info } else { 0 }))
                .collect()
        };
        let (expected, actual) = (strip(&expected.entries), strip(&actual));
        findings.check(
            DYNAMIC_RELOCATIONS,
            format_args!("{kind} entry count"),
            expected.len(),
            actual.len(),
        );
        if let Some(index) = expected.iter().zip(&actual).position(|(e, a)| e != a) {
            findings.fail(
                DYNAMIC_RELOCATIONS,
                format!(
                    "{kind} entry {index}: reference {:x?}, elfex {:x?}",
                    expected[index], actual[index]
                ),
            );
        }
    }
    for (kind, entries) in tables {
        findings.fail(
            DYNAMIC_RELOCATIONS,
            format!(
                "{kind}: elfex has {} entries, the reference none",
                entries.len()
            ),
        );
    }
}
