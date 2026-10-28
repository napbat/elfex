//! Change an ELF file, as `patchelf` does.
//!
//! ```text
//! cargo run --example elfpatch -- [OPTIONS] FILE
//! ```
//!
//! The tool reads FILE, applies the edits in a fixed order and validates the result. Then it
//! writes the result to the `--output` path. It does not change FILE.

use elfex::{ElfFile, NewSection, SectionType};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
usage: elfpatch [OPTIONS] FILE

Change an ELF file. Write the result to a new file.

options:
      --print-interpreter      print the PT_INTERP path
      --print-needed           print the DT_NEEDED libraries
      --set-interpreter PATH   change the PT_INTERP path
      --add-section NAME=FILE  add a section without SHF_ALLOC, with the bytes of FILE
      --remove-section NAME    remove the section with the name
      --set-entry ADDRESS      change the entry point (hexadecimal with 0x, or decimal)
  -o, --output PATH            write the changed file to PATH (necessary for a change)
      --help                   print this help

The tool removes sections, adds sections, sets the interpreter and sets the entry point, in
this order. Before it writes the output, it validates the result.";

/// The command line options.
#[derive(Default)]
struct Options {
    input: Option<String>,
    output: Option<String>,
    print_interpreter: bool,
    print_needed: bool,
    interpreter: Option<String>,
    add_sections: Vec<(String, String)>,
    remove_sections: Vec<String>,
    entry: Option<u64>,
}

impl Options {
    fn has_edits(&self) -> bool {
        self.interpreter.is_some()
            || !self.add_sections.is_empty()
            || !self.remove_sections.is_empty()
            || self.entry.is_some()
    }
}

fn parse_address(text: &str) -> Result<u64, String> {
    let parsed = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => text.parse(),
    };
    parsed.map_err(|_| format!("'{text}' is not a valid address"))
}

/// Parse the command line. Return `Ok(None)` for `--help`.
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Options>, String> {
    let mut options = Options::default();
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("'{arg}' needs a value"));
        match arg.as_str() {
            "--help" => return Ok(None),
            "--print-interpreter" => options.print_interpreter = true,
            "--print-needed" => options.print_needed = true,
            "--set-interpreter" => options.interpreter = Some(value()?),
            "--add-section" => {
                let spec = value()?;
                let (name, file) = spec
                    .split_once('=')
                    .filter(|(name, file)| !name.is_empty() && !file.is_empty())
                    .ok_or_else(|| format!("'{spec}' is not NAME=FILE"))?;
                options
                    .add_sections
                    .push((name.to_owned(), file.to_owned()));
            }
            "--remove-section" => options.remove_sections.push(value()?),
            "--set-entry" => options.entry = Some(parse_address(&value()?)?),
            "-o" | "--output" => options.output = Some(value()?),
            _ if arg.starts_with('-') => return Err(format!("unknown option '{arg}'")),
            _ => {
                if options.input.replace(arg).is_some() {
                    return Err("give only one FILE".to_owned());
                }
            }
        }
    }
    if options.input.is_none() {
        return Err("give a FILE".to_owned());
    }
    if options.has_edits() && options.output.is_none() {
        return Err("give an --output path for the changes".to_owned());
    }
    if !options.has_edits() && !options.print_interpreter && !options.print_needed {
        return Err("give an option".to_owned());
    }
    Ok(Some(options))
}

fn print_info(file: &ElfFile, options: &Options) -> elfex::Result<()> {
    if options.print_interpreter {
        match file.interpreter()? {
            Some(path) => println!("{path}"),
            None => return Err(elfex::Error::generic("the file has no PT_INTERP segment")),
        }
    }
    if options.print_needed {
        for library in file.needed_libraries()? {
            println!("{library}");
        }
    }
    Ok(())
}

fn apply_edits(file: &mut ElfFile, options: &Options) -> elfex::Result<()> {
    for name in &options.remove_sections {
        let index = file
            .section_by_name(name)
            .ok_or_else(|| elfex::Error::invalid_section(format!("no section is named {name}")))?
            .index;
        file.remove_section(index)?;
    }
    for (name, path) in &options.add_sections {
        let data = std::fs::read(path)?;
        file.add_section(NewSection::new(name.as_str(), SectionType::PROGBITS, data))?;
    }
    if let Some(interpreter) = &options.interpreter {
        file.set_interpreter(interpreter)?;
    }
    if let Some(entry) = options.entry {
        file.set_entry_point(entry);
    }
    Ok(())
}

/// Build the changed file and validate it. Return the bytes if the result has no errors.
fn build_checked(file: &ElfFile) -> elfex::Result<Vec<u8>> {
    let bytes = file.try_build()?;
    let result = ElfFile::parse(&bytes)?.validate();
    for issue in &result.issues {
        let context = issue
            .context
            .as_deref()
            .map_or_else(String::new, |context| format!(" ({context})"));
        eprintln!("elfpatch: {:?}: {}{context}", issue.level, issue.message);
    }
    if result.has_errors() {
        return Err(elfex::Error::generic(
            "the changed file has validation errors; the tool did not write it",
        ));
    }
    Ok(bytes)
}

fn write_output(input: &Path, output: &Path, bytes: &[u8]) -> elfex::Result<()> {
    std::fs::write(output, bytes)?;
    // Keep the permissions of the input, for example the execute bits.
    let permissions = std::fs::metadata(input)?.permissions();
    std::fs::set_permissions(output, permissions)?;
    Ok(())
}

fn run(options: &Options) -> elfex::Result<()> {
    let input = Path::new(options.input.as_deref().unwrap_or_default());
    let mut file = ElfFile::from_file(input)?;
    print_info(&file, options)?;
    if let Some(output) = &options.output {
        apply_edits(&mut file, options)?;
        let bytes = build_checked(&file)?;
        write_output(input, Path::new(output), &bytes)?;
        eprintln!("elfpatch: wrote {} bytes to {output}", bytes.len());
    }
    Ok(())
}

fn main() -> ExitCode {
    let options = match parse_args(std::env::args().skip(1)) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("elfpatch: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("elfpatch: {error}");
            ExitCode::FAILURE
        }
    }
}
