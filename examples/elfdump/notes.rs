//! Print the notes and the validation issues.

use crate::Failure;
use elfex::note::{ELF_NOTE_GNU, NT_GNU_BUILD_ID};
use elfex::{ElfFile, Note};
use std::fmt::Write as _;
use std::io::Write;

/// Return the bytes as lowercase hexadecimal digits.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn note_details(file: &ElfFile, note: &Note) -> Option<String> {
    let encoding = file.encoding();
    if note.is(ELF_NOTE_GNU, NT_GNU_BUILD_ID) {
        return Some(format!("build ID {}", hex(&note.desc)));
    }
    if let Some(tag) = note.gnu_abi_tag(encoding) {
        return Some(match tag {
            Ok(tag) => format!(
                "OS {} ABI {}.{}.{}",
                tag.os, tag.major, tag.minor, tag.subminor
            ),
            Err(error) => format!("<{error}>"),
        });
    }
    if let Some(properties) = note.gnu_properties(encoding) {
        return Some(match properties {
            Ok(properties) => properties
                .iter()
                .map(|property| format!("{:#x}: {}", property.pr_type, hex(&property.data)))
                .collect::<Vec<_>>()
                .join(", "),
            Err(error) => format!("<{error}>"),
        });
    }
    None
}

pub fn print_notes(file: &ElfFile, out: &mut dyn Write) -> Result<(), Failure> {
    let notes = file.notes()?;
    writeln!(out, "Notes ({}):", notes.len())?;
    for note in &notes {
        let owner = String::from_utf8_lossy(&note.name);
        let kind = note
            .type_name()
            .map_or_else(|| format!("{:#x}", note.n_type), str::to_owned);
        write!(out, "  {owner:<8} {kind:<24} {:>5} bytes", note.desc.len())?;
        if let Some(details) = note_details(file, note) {
            write!(out, "  {details}")?;
        }
        writeln!(out)?;
    }
    match file.build_id()? {
        Some(build_id) => writeln!(out, "Build ID: {}", hex(&build_id))?,
        None => writeln!(out, "The file has no build ID.")?,
    }
    writeln!(out)?;
    Ok(())
}

pub fn print_validation(file: &ElfFile, out: &mut dyn Write) -> Result<(), Failure> {
    let result = file.validate();
    if result.is_ok() {
        writeln!(out, "Validation: no issues.")?;
    } else {
        writeln!(out, "Validation issues ({}):", result.issues.len())?;
        for issue in &result.issues {
            let context = issue
                .context
                .as_deref()
                .map_or_else(String::new, |context| format!(" ({context})"));
            writeln!(
                out,
                "  {:?} {:?}: {}{context}",
                issue.level, issue.code, issue.message
            )?;
        }
    }
    writeln!(out)?;
    Ok(())
}
