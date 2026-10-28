//! Run the reference tool (`llvm-readelf`) and parse its output.
//!
//! The JSON output of LLVM 19 gives the headers, the dynamic table, the symbols, the
//! relocation sections and the notes. It is not correct for these items, so the module parses
//! the GNU-style text output for them:
//!
//! - The version definitions (`--version-info`): the JSON is not valid.
//! - The section groups (`--section-groups`): the JSON repeats the key `Group`.
//! - The relocation tables of the dynamic table (`--dyn-relocations`): the JSON is not valid.

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// The arguments for the JSON output.
const JSON_ARGS: [&str; 10] = [
    "--elf-output-style=JSON",
    "--file-header",
    "--sections",
    "--program-headers",
    "--dynamic-table",
    "--dyn-syms",
    "--symbols",
    "--relocations",
    "--notes",
    "--section-groups",
];

/// The arguments for the GNU-style text output.
const TEXT_ARGS: [&str; 4] = [
    "--elf-output-style=GNU",
    "--section-groups",
    "--version-info",
    "--dyn-relocations",
];

/// Return `true` if `tool --version` runs.
pub fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

/// The output of the reference tool for one file.
pub struct Reference {
    /// The JSON object of the file.
    pub json: Value,
    /// The items from the text output.
    pub text: TextOutput,
}

impl Reference {
    /// Run `tool` on the file at `path` and parse the output.
    pub fn load(tool: &str, path: &Path) -> Result<Self, String> {
        let output = run(tool, &JSON_ARGS, path)?;
        let mut json: Value = serde_json::from_str(&output)
            .map_err(|error| format!("the JSON output does not parse: {error}"))?;
        let json = match json.as_array_mut().map(std::mem::take) {
            Some(array) if array.len() == 1 => array.into_iter().next().unwrap_or_default(),
            _ => return Err("the JSON output is not an array with one object".to_owned()),
        };
        let text = TextOutput::parse(&run(tool, &TEXT_ARGS, path)?)?;
        Ok(Self { json, text })
    }
}

/// Run `tool` with `args` on the file at `path` and return the standard output.
fn run(tool: &str, args: &[&str], path: &Path) -> Result<String, String> {
    let output = Command::new(tool)
        .args(args)
        .arg(path)
        .output()
        .map_err(|error| format!("{tool} does not run: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{tool} fails ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("{tool} output is not UTF-8: {error}"))
}

/// Return the field at `path` below `value`.
pub fn get<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |value, key| value.get(key))
}

/// Return the number at `path` below `value`.
///
/// The number is a JSON number, or a string that starts with a decimal number (for example
/// `"0 (65536)"` for an extended count). The function gives a negative JSON number as its
/// two's complement.
pub fn number(value: &Value, path: &[&str]) -> Result<u64, String> {
    let field = get(value, path).ok_or_else(|| format!("no field {}", path.join(".")))?;
    let parsed = match field {
        Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_i64().map(i64::cast_unsigned)),
        Value::String(text) => {
            let digits: String = text.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        }
        _ => None,
    };
    parsed.ok_or_else(|| format!("field {} is not a number: {field}", path.join(".")))
}

/// Return the string at `path` below `value`.
pub fn string<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str, String> {
    get(value, path)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("no string field {}", path.join(".")))
}

/// Return the array at `path` below `value`, or an empty slice if the field is absent.
pub fn array<'a>(value: &'a Value, path: &[&str]) -> &'a [Value] {
    get(value, path)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Parse a hexadecimal number with an optional `0x` prefix.
pub fn hex(text: &str) -> Option<u64> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16).ok()
}

/// One section group from the text output.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Group {
    /// The index of the `SHT_GROUP` section.
    pub index: usize,
    /// `true` for a COMDAT group.
    pub comdat: bool,
    /// The signature.
    pub signature: String,
    /// The section indices of the members.
    pub members: Vec<u32>,
}

/// One version definition from the text output.
#[derive(Debug, PartialEq, Eq)]
pub struct Definition {
    /// The version index (`vd_ndx`).
    pub index: u16,
    /// `true` for the base definition (`VER_FLG_BASE`).
    pub base: bool,
    /// The version name.
    pub name: String,
}

/// One version requirement from the text output: a file and its versions.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Requirement {
    /// The file name (`vn_file`).
    pub file: String,
    /// The version name and the version index (`vna_other`) of each entry.
    pub entries: Vec<(String, u16)>,
}

/// One relocation table of the dynamic table from the text output.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DynamicRelocationTable {
    /// The table: `RELA`, `REL`, `PLT` or `RELR`.
    pub kind: String,
    /// The offset (`r_offset`) and the `r_info` value of each entry. A `RELR` entry gives the
    /// relocated address and the relative relocation type.
    pub entries: Vec<(u64, u64)>,
}

/// The items of the text output.
#[derive(Debug, Default)]
pub struct TextOutput {
    /// The section groups.
    pub groups: Vec<Group>,
    /// The version definitions.
    pub definitions: Vec<Definition>,
    /// The version requirements.
    pub requirements: Vec<Requirement>,
    /// The relocation tables of the dynamic table.
    pub dynamic_relocations: Vec<DynamicRelocationTable>,
}

/// The part of the text output that a line belongs to.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Part {
    /// A part that the parser does not use.
    Other,
    /// A section group.
    Group,
    /// The version definitions.
    Definitions,
    /// The version requirements.
    Requirements,
    /// A relocation table of the dynamic table.
    Relocations,
}

impl TextOutput {
    /// Parse the GNU-style output of `--section-groups --version-info --dyn-relocations`.
    fn parse(output: &str) -> Result<Self, String> {
        let mut text = Self::default();
        let mut part = Part::Other;
        for line in output.lines() {
            if let Some(next) = text.start_part(line)? {
                part = next;
                continue;
            }
            if line.trim().is_empty() {
                part = Part::Other;
                continue;
            }
            match part {
                Part::Other => {}
                Part::Group => text.group_member(line)?,
                Part::Definitions => text.definition(line)?,
                Part::Requirements => text.requirement(line)?,
                Part::Relocations => text.relocation(line)?,
            }
        }
        Ok(text)
    }

    /// Start a new part if `line` is the heading of a part.
    fn start_part(&mut self, line: &str) -> Result<Option<Part>, String> {
        // For example "There are no section groups in this file." after a relocation table.
        if line.starts_with("There are no ") {
            return Ok(Some(Part::Other));
        }
        if line.contains(" group section [") {
            let index = between(line, "[", "]")
                .and_then(|index| index.trim().parse().ok())
                .ok_or_else(|| format!("bad group heading: {line}"))?;
            let signature = between(line, "' [", "] contains")
                .ok_or_else(|| format!("bad group heading: {line}"))?;
            self.groups.push(Group {
                index,
                comdat: line.starts_with("COMDAT"),
                signature: signature.to_owned(),
                members: Vec::new(),
            });
            return Ok(Some(Part::Group));
        }
        if line.starts_with("Version definition section ") {
            return Ok(Some(Part::Definitions));
        }
        if line.starts_with("Version needs section ") {
            return Ok(Some(Part::Requirements));
        }
        if line.starts_with("Version symbols section ") {
            return Ok(Some(Part::Other));
        }
        if let Some(rest) = line.strip_prefix('\'')
            && line.contains("' relocation section at offset ")
        {
            let kind = rest.split('\'').next().unwrap_or_default();
            self.dynamic_relocations.push(DynamicRelocationTable {
                kind: kind.to_owned(),
                entries: Vec::new(),
            });
            return Ok(Some(Part::Relocations));
        }
        Ok(None)
    }

    /// Parse a member line of a section group: `   [    4]   .text.name`.
    fn group_member(&mut self, line: &str) -> Result<(), String> {
        let trimmed = line.trim_start();
        if trimmed.starts_with("[Index]") {
            return Ok(());
        }
        let index = between(trimmed, "[", "]")
            .and_then(|index| index.trim().parse().ok())
            .ok_or_else(|| format!("bad group member: {line}"))?;
        if let Some(group) = self.groups.last_mut() {
            group.members.push(index);
        }
        Ok(())
    }

    /// Parse a line of the version definitions.
    ///
    /// A definition line is `0x0000: Rev: 1  Flags: BASE  Index: 1  Cnt: 1  Name: name`. The
    /// parser ignores the address lines and the parent lines.
    fn definition(&mut self, line: &str) -> Result<(), String> {
        if !line.contains(" Rev: ") {
            return Ok(());
        }
        let field = |name: &str| {
            field_after(line, name).ok_or_else(|| format!("bad version definition: {line}"))
        };
        let index = field("Index: ")?
            .parse()
            .map_err(|_| format!("bad version index: {line}"))?;
        let name = line
            .split_once("  Name: ")
            .map(|(_, name)| name)
            .ok_or_else(|| format!("bad version definition: {line}"))?;
        self.definitions.push(Definition {
            index,
            base: field("Flags: ")?.contains("BASE"),
            name: name.to_owned(),
        });
        Ok(())
    }

    /// Parse a line of the version requirements.
    ///
    /// A file line is `0x0000: Version: 1  File: libc.so.6  Cnt: 2`. An entry line is
    /// `0x0010:   Name: GLIBC_2.2.5  Flags: none  Version: 3`.
    fn requirement(&mut self, line: &str) -> Result<(), String> {
        if let Some((_, rest)) = line.split_once("  File: ") {
            let file = rest.rsplit_once("  Cnt: ").map_or(rest, |(file, _)| file);
            self.requirements.push(Requirement {
                file: file.to_owned(),
                entries: Vec::new(),
            });
        } else if let Some((_, rest)) = line.split_once("   Name: ") {
            let (name, rest) = rest
                .split_once("  Flags: ")
                .ok_or_else(|| format!("bad version requirement: {line}"))?;
            let index = rest
                .rsplit_once("Version: ")
                .and_then(|(_, index)| index.trim().parse().ok())
                .ok_or_else(|| format!("bad version requirement: {line}"))?;
            if let Some(requirement) = self.requirements.last_mut() {
                requirement.entries.push((name.to_owned(), index));
            }
        }
        Ok(())
    }

    /// Parse a line of a relocation table: the offset and `r_info` in hexadecimal, then the
    /// type and the symbol.
    fn relocation(&mut self, line: &str) -> Result<(), String> {
        let mut words = line.split_whitespace();
        let (Some(offset), Some(info)) = (words.next(), words.next()) else {
            return Ok(());
        };
        if offset == "Offset" {
            return Ok(());
        }
        let entry = hex(offset)
            .zip(hex(info))
            .ok_or_else(|| format!("bad relocation line: {line}"))?;
        if let Some(table) = self.dynamic_relocations.last_mut() {
            table.entries.push(entry);
        }
        Ok(())
    }
}

/// Return the text between the first `start` and the next `end` in `line`.
fn between<'a>(line: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let (_, rest) = line.split_once(start)?;
    rest.split_once(end).map(|(inner, _)| inner)
}

/// Return the word after `name` in `line`.
fn field_after<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (_, rest) = line.split_once(name)?;
    rest.split_whitespace().next()
}
