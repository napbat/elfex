//! Print a summary of an ELF file, as `readelf` does.
//!
//! ```text
//! cargo run --example elfdump -- [-h] [-l] [-S] [-d] [-s] [-r] [-n] [-V] [-c] [-a] FILE
//! ```
//!
//! Without a part flag, the tool prints all parts.

mod dynamic;
mod headers;
mod notes;
mod symbols;

use elfex::ElfFile;
use std::io::{ErrorKind, Write};
use std::process::ExitCode;

const USAGE: &str = "\
usage: elfdump [OPTIONS] FILE

Print a summary of an ELF file. Without a part option, print all parts.

options:
  -h, --file-header      print the file header
  -l, --segments         print the program headers
  -S, --sections         print the section headers
  -d, --dynamic          print the dynamic table, the needed libraries, the soname and the paths
  -s, --symbols          print the static and the dynamic symbols, with versions
  -r, --relocs           print the relocation sections
  -n, --notes            print the notes and the build ID
  -V, --version-info     print the version definitions and requirements
  -c, --check            print the validation issues
  -a, --all              print all parts
      --help             print this help";

/// A failure of a part: a library error or an output error.
enum Failure {
    /// The library cannot read the part.
    Elf(elfex::Error),
    /// The tool cannot write the output.
    Output(std::io::Error),
}

impl From<elfex::Error> for Failure {
    fn from(error: elfex::Error) -> Self {
        Self::Elf(error)
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Output(error)
    }
}

/// A part of the output: the short flag, the long flags, the name and the print function.
struct Part {
    short: char,
    long: &'static [&'static str],
    name: &'static str,
    print: fn(&ElfFile, &mut dyn Write) -> Result<(), Failure>,
}

/// The parts, in output order.
const PARTS: [Part; 9] = [
    Part {
        short: 'h',
        long: &["file-header"],
        name: "file header",
        print: headers::print_file_header,
    },
    Part {
        short: 'l',
        long: &["segments", "program-headers"],
        name: "program headers",
        print: headers::print_program_headers,
    },
    Part {
        short: 'S',
        long: &["sections", "section-headers"],
        name: "section headers",
        print: headers::print_section_headers,
    },
    Part {
        short: 'd',
        long: &["dynamic"],
        name: "dynamic table",
        print: dynamic::print_dynamic,
    },
    Part {
        short: 'V',
        long: &["version-info"],
        name: "version tables",
        print: dynamic::print_versions,
    },
    Part {
        short: 's',
        long: &["symbols", "syms"],
        name: "symbols",
        print: symbols::print_symbols,
    },
    Part {
        short: 'r',
        long: &["relocs"],
        name: "relocations",
        print: symbols::print_relocations,
    },
    Part {
        short: 'n',
        long: &["notes"],
        name: "notes",
        print: notes::print_notes,
    },
    Part {
        short: 'c',
        long: &["check"],
        name: "validation",
        print: notes::print_validation,
    },
];

/// The parts to print: one value for each item of [`PARTS`].
type Selection = [bool; PARTS.len()];

/// Select the part of a short flag letter. Return `false` for an unknown letter.
fn select_short(selection: &mut Selection, letter: char) -> bool {
    if letter == 'a' {
        *selection = [true; PARTS.len()];
        return true;
    }
    let Some(index) = PARTS.iter().position(|part| part.short == letter) else {
        return false;
    };
    selection[index] = true;
    true
}

/// Select the part of a long flag. Return `false` for an unknown flag.
fn select_long(selection: &mut Selection, flag: &str) -> bool {
    if flag == "all" {
        return select_short(selection, 'a');
    }
    PARTS
        .iter()
        .find(|part| part.long.contains(&flag))
        .is_some_and(|part| select_short(selection, part.short))
}

/// The result of the command line parse.
enum Command {
    Help,
    Dump { selection: Selection, path: String },
}

fn parse_args(args: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut selection = [false; PARTS.len()];
    let mut path = None;
    for arg in args {
        if arg == "--help" {
            return Ok(Command::Help);
        } else if let Some(flag) = arg.strip_prefix("--") {
            if !select_long(&mut selection, flag) {
                return Err(format!("unknown option '{arg}'"));
            }
        } else if let Some(letters) = arg.strip_prefix('-').filter(|rest| !rest.is_empty()) {
            if let Some(letter) = letters
                .chars()
                .find(|&letter| !select_short(&mut selection, letter))
            {
                return Err(format!("unknown option '-{letter}'"));
            }
        } else if path.replace(arg).is_some() {
            return Err("give only one FILE".to_owned());
        }
    }
    let path = path.ok_or_else(|| "give a FILE".to_owned())?;
    if !selection.contains(&true) {
        selection = [true; PARTS.len()];
    }
    Ok(Command::Dump { selection, path })
}

/// Print the selected parts. Print an error for each part that fails, and continue with the
/// next part, as `readelf` does. Stop at the first output error. Return the exit code.
fn dump(path: &str, file: &ElfFile, selection: &Selection, out: &mut dyn Write) -> ExitCode {
    let mut ok = true;
    for (part, _) in PARTS
        .iter()
        .zip(selection)
        .filter(|(_, selected)| **selected)
    {
        match (part.print)(file, out) {
            Ok(()) => {}
            Err(Failure::Elf(error)) => {
                eprintln!("elfdump: {path}: {}: {error}", part.name);
                ok = false;
            }
            Err(Failure::Output(error)) => return output_failure(&error, ok),
        }
    }
    match out.flush() {
        Ok(()) if ok => ExitCode::SUCCESS,
        Ok(()) => ExitCode::FAILURE,
        Err(error) => output_failure(&error, ok),
    }
}

/// Return the exit code for an output error. Exit quietly if the reader closed the pipe.
/// For other errors, print a message.
fn output_failure(error: &std::io::Error, ok: bool) -> ExitCode {
    if error.kind() != ErrorKind::BrokenPipe {
        eprintln!("elfdump: cannot write the output: {error}");
        return ExitCode::FAILURE;
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn main() -> ExitCode {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let (selection, path) = match parse_args(std::env::args().skip(1)) {
        Ok(Command::Dump { selection, path }) => (selection, path),
        Ok(Command::Help) => {
            return match writeln!(out, "{USAGE}").and_then(|()| out.flush()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => output_failure(&error, true),
            };
        }
        Err(message) => {
            eprintln!("elfdump: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match ElfFile::from_file(&path) {
        Ok(file) => dump(&path, &file, &selection, &mut out),
        Err(error) => {
            eprintln!("elfdump: {path}: {error}");
            ExitCode::FAILURE
        }
    }
}
