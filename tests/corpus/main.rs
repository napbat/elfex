//! Compatibility tests with a corpus of real ELF files.
//!
//! The tests are ignored by default, because they need files and tools of the host. Run the
//! compatibility test with a list of files and directories:
//!
//! ```sh
//! ELFEX_CORPUS=/usr/bin:/usr/lib cargo test --test corpus -- --ignored --nocapture corpus
//! ```
//!
//! These environment variables control the compatibility test (`corpus`):
//!
//! - `ELFEX_CORPUS`: the files and directories to check, split as the `PATH` variable of the
//!   platform. The test walks each directory recursively. It does not follow a symbolic link
//!   to a directory. It selects the files that start with the ELF magic.
//! - `ELFEX_CORPUS_MAX_BYTES`: the size of the largest file to check. The default is 512 MiB.
//! - `ELFEX_READELF`: the reference tool. The default is `llvm-readelf`. If the tool is not
//!   available, the test does only the self-consistency checks.
//!
//! The edit-and-run test (`edit_and_run`) edits the runnable programs in the directories of
//! `ELFEX_CORPUS` and runs them. It needs a Unix host. See `edit_run.rs`.
//!
//! Each test prints a summary table and fails if a check category has failures.

mod accessors;
mod compare;
mod defects;
#[cfg(unix)]
mod edit_run;
mod reference;
mod report;
mod walk;

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use reference::Reference;
use report::{Findings, Report};

/// The default value of `ELFEX_CORPUS_MAX_BYTES`: 512 MiB.
const DEFAULT_MAX_BYTES: u64 = 512 << 20;

/// The settings of a corpus run, from the environment.
struct Config {
    /// The files and directories of `ELFEX_CORPUS`.
    roots: Vec<PathBuf>,
    /// The size of the largest file to check.
    max_bytes: u64,
    /// The reference tool, or `None` if it is not available.
    readelf: Option<String>,
}

impl Config {
    /// Read the settings from the environment.
    fn from_env() -> Self {
        let corpus = std::env::var_os("ELFEX_CORPUS")
            .expect("set ELFEX_CORPUS to the files and directories to check");
        let roots: Vec<PathBuf> = std::env::split_paths(&corpus)
            .filter(|path| !path.as_os_str().is_empty())
            .collect();
        assert!(!roots.is_empty(), "ELFEX_CORPUS names no path");
        let max_bytes =
            std::env::var("ELFEX_CORPUS_MAX_BYTES").map_or(DEFAULT_MAX_BYTES, |value| {
                value
                    .parse()
                    .expect("ELFEX_CORPUS_MAX_BYTES must be a number of bytes")
            });
        let tool = std::env::var("ELFEX_READELF").unwrap_or_else(|_| "llvm-readelf".to_owned());
        let readelf = reference::tool_available(&tool).then_some(tool);
        Self {
            roots,
            max_bytes,
            readelf,
        }
    }
}

#[test]
#[ignore = "needs ELFEX_CORPUS: see the module documentation"]
fn corpus() {
    let config = Config::from_env();
    match &config.readelf {
        Some(tool) => println!("reference tool: {tool}"),
        None => println!("reference tool not available: self-consistency checks only"),
    }
    let found = walk::collect(&config.roots, config.max_bytes);
    for source in &found.sources {
        println!("{:>7} files  {}", source.files, source.root.display());
    }
    println!(
        "{} files in total ({} too large, {} not readable)",
        found.files.len(),
        found.too_large,
        found.unreadable
    );

    let report = Mutex::new(Report::default());
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                while let Some(path) = found.files.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let findings = check_file(path, config.readelf.as_deref());
                    findings.print(path);
                    report
                        .lock()
                        .expect("a worker panicked")
                        .add(path, findings);
                }
            });
        }
    });
    let report = report.into_inner().expect("a worker panicked");
    report.print_summary(&report::CORPUS_CATEGORIES);
    assert!(
        report.is_clean(),
        "the corpus run has failures: see the summary"
    );
}

#[cfg(unix)]
#[test]
#[ignore = "needs ELFEX_CORPUS with runnable programs: see the module documentation"]
fn edit_and_run() {
    edit_run::run();
}

/// Do all checks of one file.
fn check_file(path: &Path, readelf: Option<&str>) -> Findings {
    let mut findings = Findings::default();
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => {
            findings.fail(report::READ, format!("cannot read the file: {error}"));
            return findings;
        }
    };
    let Some(file) = accessors::check_file(&bytes, &mut findings) else {
        return findings;
    };
    accessors::check_image(&file, &bytes, &mut findings);
    if let Some(tool) = readelf {
        match Reference::load(tool, path) {
            Ok(reference) => compare::compare(&file, &reference, &mut findings),
            Err(message) => findings.fail(report::REFERENCE, message),
        }
    }
    findings
}
