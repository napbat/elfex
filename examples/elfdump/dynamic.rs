//! Print the dynamic table and the symbol version tables.

use crate::Failure;
use elfex::version::VER_FLG_BASE;
use elfex::{DynamicTag, ElfFile, StringTable};
use std::borrow::Cow;
use std::io::Write;

/// Return the string at `offset`, or a placeholder if the string table cannot give it.
pub fn string_at(strings: Option<&StringTable<'_>>, offset: u32) -> String {
    strings
        .and_then(|table| table.get_lossy(offset).ok())
        .map_or_else(|| format!("<string {offset:#x}>"), Cow::into_owned)
}

fn has_string_value(tag: DynamicTag) -> bool {
    [
        DynamicTag::NEEDED,
        DynamicTag::SONAME,
        DynamicTag::RPATH,
        DynamicTag::RUNPATH,
    ]
    .contains(&tag)
}

pub fn print_dynamic(file: &ElfFile, out: &mut dyn Write) -> Result<(), Failure> {
    let Some(table) = file.dynamic()? else {
        writeln!(out, "The file has no dynamic table.")?;
        writeln!(out)?;
        return Ok(());
    };
    let strings = file.dynamic_strings()?;
    writeln!(out, "Dynamic table ({} entries):", table.entries.len())?;
    for entry in &table.entries {
        let tag = entry.tag.to_string();
        if has_string_value(entry.tag) {
            let text = u32::try_from(entry.value).map_or_else(
                |_| "<offset too large>".to_owned(),
                |offset| string_at(strings.as_ref(), offset),
            );
            writeln!(out, "  {tag:<24} [{text}]")?;
        } else {
            writeln!(out, "  {tag:<24} {:#x}", entry.value)?;
        }
    }
    writeln!(out)?;
    let none = || "(none)".to_owned();
    let needed = file.needed_libraries()?;
    writeln!(out, "Linking summary:")?;
    if needed.is_empty() {
        writeln!(out, "  Needed:  (none)")?;
    } else {
        writeln!(out, "  Needed:  {}", needed.join(", "))?;
    }
    writeln!(out, "  Soname:  {}", file.soname()?.unwrap_or_else(none))?;
    writeln!(out, "  Rpath:   {}", file.rpath()?.unwrap_or_else(none))?;
    writeln!(out, "  Runpath: {}", file.runpath()?.unwrap_or_else(none))?;
    writeln!(out)?;
    Ok(())
}

pub fn print_versions(file: &ElfFile, out: &mut dyn Write) -> Result<(), Failure> {
    let tables = file.version_tables()?;
    let strings = file.dynamic_strings()?;
    let strings = strings.as_ref();
    if let Some(versym) = &tables.versym {
        writeln!(
            out,
            "Symbol versions (.gnu.version): {} entries",
            versym.entries.len()
        )?;
    }
    if let Some(definitions) = &tables.definitions {
        writeln!(
            out,
            "Version definitions ({}):",
            definitions.definitions.len()
        )?;
        for definition in &definitions.definitions {
            let name = definition
                .name()
                .map_or_else(String::new, |offset| string_at(strings, offset));
            let base = if definition.flags & VER_FLG_BASE == 0 {
                ""
            } else {
                " (base)"
            };
            let parents: Vec<String> = definition
                .parents()
                .iter()
                .map(|&offset| string_at(strings, offset))
                .collect();
            write!(out, "  [{}] {name}{base}", definition.index)?;
            if !parents.is_empty() {
                write!(out, " parents: {}", parents.join(", "))?;
            }
            writeln!(out)?;
        }
    }
    if let Some(requirements) = &tables.requirements {
        writeln!(
            out,
            "Version requirements ({}):",
            requirements.requirements.len()
        )?;
        for requirement in &requirements.requirements {
            writeln!(out, "  {}:", string_at(strings, requirement.file))?;
            for entry in &requirement.entries {
                writeln!(
                    out,
                    "    [{}] {}",
                    entry.index,
                    string_at(strings, entry.name)
                )?;
            }
        }
    }
    if tables.versym.is_none() && tables.definitions.is_none() && tables.requirements.is_none() {
        writeln!(out, "The file has no symbol version tables.")?;
    }
    writeln!(out)?;
    Ok(())
}
