//! Print the notes and the validation issues.

use elfex::note::{
    ELF_NOTE_CORE, ELF_NOTE_GNU, NT_AUXV, NT_FILE, NT_GNU_ABI_TAG, NT_GNU_BUILD_ID,
    NT_GNU_GOLD_VERSION, NT_GNU_HWCAP, NT_GNU_PROPERTY_TYPE_0, NT_PRFPREG, NT_PRPSINFO,
    NT_PRSTATUS, NT_SIGINFO,
};
use elfex::{ElfFile, Note};
use std::fmt::Write;

/// Return the name of a known note type, or the hexadecimal value.
fn note_type(note: &Note) -> String {
    let name = if note.name == ELF_NOTE_GNU {
        match note.n_type {
            NT_GNU_ABI_TAG => Some("NT_GNU_ABI_TAG"),
            NT_GNU_HWCAP => Some("NT_GNU_HWCAP"),
            NT_GNU_BUILD_ID => Some("NT_GNU_BUILD_ID"),
            NT_GNU_GOLD_VERSION => Some("NT_GNU_GOLD_VERSION"),
            NT_GNU_PROPERTY_TYPE_0 => Some("NT_GNU_PROPERTY_TYPE_0"),
            _ => None,
        }
    } else if note.name == ELF_NOTE_CORE {
        match note.n_type {
            NT_PRSTATUS => Some("NT_PRSTATUS"),
            NT_PRFPREG => Some("NT_PRFPREG"),
            NT_PRPSINFO => Some("NT_PRPSINFO"),
            NT_AUXV => Some("NT_AUXV"),
            NT_FILE => Some("NT_FILE"),
            NT_SIGINFO => Some("NT_SIGINFO"),
            _ => None,
        }
    } else {
        None
    };
    name.map_or_else(|| format!("{:#x}", note.n_type), str::to_owned)
}

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

pub fn print_notes(file: &ElfFile) -> elfex::Result<()> {
    let notes = file.notes()?;
    println!("Notes ({}):", notes.len());
    for note in &notes {
        let owner = String::from_utf8_lossy(&note.name);
        print!(
            "  {owner:<8} {:<24} {:>5} bytes",
            note_type(note),
            note.desc.len()
        );
        if let Some(details) = note_details(file, note) {
            print!("  {details}");
        }
        println!();
    }
    match file.build_id()? {
        Some(build_id) => println!("Build ID: {}", hex(&build_id)),
        None => println!("The file has no build ID."),
    }
    println!();
    Ok(())
}

pub fn print_validation(file: &ElfFile) {
    let result = file.validate();
    if result.is_ok() {
        println!("Validation: no issues.");
    } else {
        println!("Validation issues ({}):", result.issues.len());
        for issue in &result.issues {
            let context = issue
                .context
                .as_deref()
                .map_or_else(String::new, |context| format!(" ({context})"));
            println!(
                "  {:?} {:?}: {}{context}",
                issue.level, issue.code, issue.message
            );
        }
    }
    println!();
}
