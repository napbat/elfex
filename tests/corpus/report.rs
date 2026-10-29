//! The failure categories, the failures of one file and the summary of a run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::defects::KnownDefect;

/// The file cannot be read.
pub const READ: &str = "read";
/// `ElfFile::parse` fails.
pub const PARSE: &str = "parse";
/// `ElfFile::try_build` does not return the input bytes.
pub const ROUND_TRIP: &str = "round-trip";
/// `ElfFile::validate` reports an error.
pub const VALIDATE: &str = "validate";
/// An accessor of `ElfFile` or `ElfImage` returns an error, or `.eh_frame` does not parse.
pub const ACCESSORS: &str = "accessors";
/// `LinkingView` does not give the exports or does not find an exported symbol, or
/// `lookup_dynamic_symbol` gives a different result than the view.
pub const LOOKUP: &str = "lookup";
/// The loader view (`ElfImage`) and its mapped image do not agree with the file.
pub const IMAGE: &str = "image";
/// The reference tool fails or its output does not parse.
pub const REFERENCE: &str = "reference";
/// The file header differs from the reference.
pub const HEADER: &str = "header";
/// A section header differs from the reference.
pub const SECTIONS: &str = "sections";
/// A program header differs from the reference.
pub const SEGMENTS: &str = "segments";
/// A dynamic entry, a needed library, the soname or the run path differs from the reference.
pub const DYNAMIC: &str = "dynamic";
/// A dynamic symbol differs from the reference.
pub const DYNAMIC_SYMBOLS: &str = "dynamic-symbols";
/// A static symbol differs from the reference.
pub const SYMBOLS: &str = "symbols";
/// A relocation section differs from the reference.
pub const RELOCATIONS: &str = "relocations";
/// A relocation table of the dynamic table differs from the reference.
pub const DYNAMIC_RELOCATIONS: &str = "dynamic-relocations";
/// A note differs from the reference.
pub const NOTES: &str = "notes";
/// A version definition or requirement differs from the reference.
pub const VERSIONS: &str = "versions";
/// A section group differs from the reference.
pub const GROUPS: &str = "groups";

/// The categories of the compatibility test, in the order of the summary.
pub const CORPUS_CATEGORIES: [&str; 19] = [
    READ,
    PARSE,
    ROUND_TRIP,
    VALIDATE,
    ACCESSORS,
    LOOKUP,
    IMAGE,
    REFERENCE,
    HEADER,
    SECTIONS,
    SEGMENTS,
    DYNAMIC,
    DYNAMIC_SYMBOLS,
    SYMBOLS,
    RELOCATIONS,
    DYNAMIC_RELOCATIONS,
    NOTES,
    VERSIONS,
    GROUPS,
];

/// The largest number of messages that one file keeps for one category.
const MESSAGES_PER_CATEGORY: usize = 5;

/// The number of files that the summary shows for each category.
const SUMMARY_FILES: usize = 5;

/// The failures of one file.
#[derive(Default)]
pub struct Findings {
    /// The messages of each category.
    messages: BTreeMap<&'static str, Vec<String>>,
    /// The number of messages of each category, also the messages that the file did not keep.
    counts: BTreeMap<&'static str, usize>,
    /// The known defects of the file.
    defects: Vec<&'static KnownDefect>,
    /// The names of the known defects that caused a failure.
    accepted: BTreeSet<&'static str>,
}

impl Findings {
    /// Accept the failures that the known defects of the file cause.
    pub fn accept(&mut self, defects: Vec<&'static KnownDefect>) {
        self.defects = defects;
    }

    /// Record a failure in `category`, if no known defect of the file causes it.
    pub fn fail(&mut self, category: &'static str, message: impl Into<String>) {
        let message = message.into();
        if let Some(defect) = self
            .defects
            .iter()
            .find(|defect| message.contains(defect.pattern))
        {
            self.accepted.insert(defect.name);
            return;
        }
        let count = self.counts.entry(category).or_default();
        *count += 1;
        if *count <= MESSAGES_PER_CATEGORY {
            self.messages.entry(category).or_default().push(message);
        }
    }

    /// Record a failure in `category` if `expected` and `actual` are different.
    ///
    /// The function takes the values, so that the callers can give temporary values.
    pub fn check<T: PartialEq + std::fmt::Debug>(
        &mut self,
        category: &'static str,
        what: impl std::fmt::Display,
        expected: T,
        actual: T,
    ) {
        let values = (expected, actual);
        if values.0 != values.1 {
            let (expected, actual) = values;
            self.fail(
                category,
                format!("{what}: reference {expected:?}, elfex {actual:?}"),
            );
        }
    }

    /// Print each failure of the file at `path`.
    pub fn print(&self, path: &Path) {
        for (category, messages) in &self.messages {
            for message in messages {
                println!("FAIL [{category}] {}: {message}", path.display());
            }
            let count = self.counts.get(category).copied().unwrap_or_default();
            if count > messages.len() {
                println!(
                    "FAIL [{category}] {}: {} more failures",
                    path.display(),
                    count - messages.len()
                );
            }
        }
    }
}

/// The failures of a run.
#[derive(Default)]
pub struct Report {
    /// The number of checked files.
    files: usize,
    /// The files with failures in each category, with the first message.
    failures: BTreeMap<&'static str, Vec<(PathBuf, String)>>,
    /// The number of files with each accepted known defect.
    accepted: BTreeMap<&'static str, usize>,
}

impl Report {
    /// Add the failures of the file at `path`.
    pub fn add(&mut self, path: &Path, findings: Findings) {
        self.files += 1;
        for (category, messages) in findings.messages {
            let first = messages.into_iter().next().unwrap_or_default();
            self.failures
                .entry(category)
                .or_default()
                .push((path.to_path_buf(), first));
        }
        for name in findings.accepted {
            *self.accepted.entry(name).or_default() += 1;
        }
    }

    /// Return `true` if no category has failures.
    pub fn is_clean(&self) -> bool {
        self.failures.is_empty()
    }

    /// Print the number of failed files for each category, with the first few files.
    ///
    /// The summary shows `categories` in their order, and then the other categories with
    /// failures.
    pub fn print_summary(&self, categories: &[&'static str]) {
        println!();
        println!("{} files checked", self.files);
        println!("{:<22} failed files", "category");
        let others = self
            .failures
            .keys()
            .copied()
            .filter(|category| !categories.contains(category));
        for category in categories.iter().copied().chain(others) {
            let failures = self.failures.get(category).map_or(&[][..], Vec::as_slice);
            println!("{category:<22} {}", failures.len());
            let mut sorted: Vec<&(PathBuf, String)> = failures.iter().collect();
            sorted.sort();
            for (path, message) in sorted.into_iter().take(SUMMARY_FILES) {
                println!("    {}: {message}", path.display());
            }
        }
        for (name, files) in &self.accepted {
            println!("accepted known defect {name}: {files} files");
        }
    }
}
