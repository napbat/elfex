//! The edit-and-run test: edit runnable programs with `ElfFile` and run them.
//!
//! The test takes the programs in the directories `gnu/x86_64`, `gnu/aarch64` and
//! `gnu/powerpc64le` below each directory of `ELFEX_CORPUS`. `scripts/build-corpus.sh` makes
//! this layout. The test runs x86-64 programs directly on an x86-64 host. It runs the other
//! programs with `qemu-aarch64 -L /usr/aarch64-linux-gnu` and
//! `qemu-ppc64le -L /usr/powerpc64le-linux-gnu`. It skips a program that does not run without
//! edits, for example a shared object.
//!
//! For each program, the test makes one edited copy for each edit, and one copy with all
//! edits. Each copy must parse, validate, and print the same output as the original program.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use elfex::program::PF_R;
use elfex::{ElfFile, Machine, NewSection, SectionType};

use crate::report::{Findings, Report};
use crate::walk;

/// The edits, in the order of the summary. Each edit is also a failure category.
const EDITS: [&str; 6] = [
    "set_interpreter",
    "add_load_segment",
    "add_section",
    "set_section_data",
    "remove_section",
    "all-edits",
];

/// A directory below the long interpreter path. It makes the path longer than each real
/// interpreter path, so that `set_interpreter` must move the path to a new segment.
const LONG_DIRECTORY: &str = "a-long-directory-name-that-makes-the-interpreter-path-longer";

/// The longest time that one program can run.
const TIMEOUT: Duration = Duration::from_secs(60);

/// How to run the programs of one architecture.
struct Target {
    /// The directory below `gnu/` in the corpus.
    directory: &'static str,
    /// The machine of the programs.
    machine: Machine,
    /// The emulator and the sysroot, or `None` to run the programs directly.
    emulator: Option<(&'static str, &'static str)>,
}

/// The architectures of the test.
const TARGETS: [Target; 3] = [
    Target {
        directory: "x86_64",
        machine: Machine::X86_64,
        emulator: None,
    },
    Target {
        directory: "aarch64",
        machine: Machine::AARCH64,
        emulator: Some(("qemu-aarch64", "/usr/aarch64-linux-gnu")),
    },
    Target {
        directory: "powerpc64le",
        machine: Machine::PPC64,
        emulator: Some(("qemu-ppc64le", "/usr/powerpc64le-linux-gnu")),
    },
];

/// The output of one run.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    /// The exit code, or `None` if a signal stopped the program.
    code: Option<i32>,
    /// The standard output.
    stdout: String,
}

/// Run the edit-and-run test over the corpus directories of `ELFEX_CORPUS`.
pub fn run() {
    let corpus = std::env::var_os("ELFEX_CORPUS")
        .expect("set ELFEX_CORPUS to the corpus directories with runnable programs");
    let work = std::env::temp_dir().join(format!("elfex-edit-and-run-{}", std::process::id()));
    fs::create_dir_all(work.join(LONG_DIRECTORY)).expect("cannot make the work directory");
    let mut report = Report::default();
    let mut programs = 0;
    for root in std::env::split_paths(&corpus) {
        for target in &TARGETS {
            if target.emulator.is_none() && !cfg!(target_arch = "x86_64") {
                println!("skip {}: the host cannot run it", target.directory);
                continue;
            }
            let directory = root.join("gnu").join(target.directory);
            if !directory.is_dir() {
                continue;
            }
            let found = walk::collect(&[directory], u64::MAX);
            for path in found.files {
                let Some(findings) = check_program(&path, target, &work) else {
                    continue;
                };
                programs += 1;
                findings.print(&path);
                report.add(&path, findings);
            }
        }
    }
    let _ = fs::remove_dir_all(&work);
    println!("{programs} programs edited and run");
    report.print_summary(&EDITS);
    assert!(programs > 0, "ELFEX_CORPUS has no runnable programs");
    assert!(
        report.is_clean(),
        "the edit-and-run test has failures: see the summary"
    );
}

/// Edit the program at `path` in each way and run each copy.
///
/// Return `None` if the program is not for `target` or does not run without edits.
fn check_program(path: &Path, target: &Target, work: &Path) -> Option<Findings> {
    let bytes = fs::read(path).ok()?;
    let file = ElfFile::parse(&bytes).ok()?;
    if file.machine() != target.machine {
        return None;
    }
    let expected = run_program(target, path).ok()?;
    if expected.code != Some(0) || expected.stdout.is_empty() {
        return None;
    }
    let name = path.file_name()?.to_string_lossy().into_owned();
    let interpreter = interpreter_link(&file, target, work, &name);
    let mut findings = Findings::default();
    for edit in EDITS {
        let mut edited = file.clone();
        let applied = if edit == "all-edits" {
            EDITS[..EDITS.len() - 1]
                .iter()
                .try_fold(false, |any, edit| {
                    apply(&mut edited, edit, interpreter.as_deref()).map(|applied| any | applied)
                })
        } else {
            apply(&mut edited, edit, interpreter.as_deref())
        };
        match applied {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                findings.fail(edit, format!("the edit fails: {error}"));
                continue;
            }
        }
        let copy = work.join(format!("{}-{name}-{edit}", target.directory));
        if let Err(message) = check_copy(&edited, &copy, target, &expected) {
            findings.fail(edit, message);
        }
        let _ = fs::remove_file(&copy);
    }
    Some(findings)
}

/// Make a symbolic link to the real interpreter of `file` at a longer path, and return the
/// path of the link. Return `None` if the program has no interpreter.
fn interpreter_link(file: &ElfFile, target: &Target, work: &Path, name: &str) -> Option<String> {
    let interpreter = file.interpreter().ok()??;
    let real = match target.emulator {
        Some((_, sysroot)) => {
            let inside = Path::new(sysroot).join(interpreter.trim_start_matches('/'));
            if inside.exists() {
                inside
            } else {
                PathBuf::from(&interpreter)
            }
        }
        None => PathBuf::from(&interpreter),
    };
    let real = fs::canonicalize(real).ok()?;
    let link = work.join(LONG_DIRECTORY).join(format!(
        "{}-{name}-{}",
        target.directory,
        file_name(&interpreter)
    ));
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(real, &link).ok()?;
    let link = link.to_str()?.to_owned();
    assert!(
        link.len() > interpreter.len(),
        "the link path must be longer"
    );
    Some(link)
}

/// Return the last component of `path`.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Apply `edit` to `file`. Return `false` if the edit does not apply to the file.
fn apply(file: &mut ElfFile, edit: &str, interpreter: Option<&str>) -> elfex::Result<bool> {
    match edit {
        "set_interpreter" => {
            let Some(interpreter) = interpreter else {
                return Ok(false);
            };
            file.set_interpreter(interpreter)?;
        }
        "add_load_segment" => {
            file.add_load_segment(PF_R, vec![0x5a; 0x2000], 0)?;
        }
        "add_section" => {
            let data = b"elfex edit-and-run test\0".to_vec();
            file.add_section(NewSection::new(".elfex", SectionType::PROGBITS, data))?;
        }
        "set_section_data" => {
            let Some(comment) = file.section_by_name(".comment") else {
                return Ok(false);
            };
            let index = comment.index;
            let mut data = comment.data.to_vec();
            data.extend_from_slice(b"elfex edit-and-run test, with more bytes than before\0");
            file.set_section_data(index, data)?;
        }
        "remove_section" => {
            let Some(comment) = file.section_by_name(".comment") else {
                return Ok(false);
            };
            file.remove_section(comment.index)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// Write the edited copy to `copy`, check it, run it and compare the output.
fn check_copy(
    edited: &ElfFile,
    copy: &Path,
    target: &Target,
    expected: &Outcome,
) -> Result<(), String> {
    let bytes = edited
        .try_build()
        .map_err(|error| format!("try_build: {error}"))?;
    let parsed =
        ElfFile::parse(&bytes).map_err(|error| format!("the copy does not parse: {error}"))?;
    if let Some(issue) = parsed.validate().errors().next() {
        return Err(format!("the copy does not validate: {issue:?}"));
    }
    let same_headers = parsed.program_headers() == edited.program_headers()
        && parsed.section_headers() == edited.section_headers()
        && parsed.section_names() == edited.section_names();
    if !same_headers {
        return Err("the headers of the copy differ from the edited headers".to_owned());
    }
    if parsed.interpreter().ok() != edited.interpreter().ok() {
        return Err("the interpreter of the copy differs from the edited interpreter".to_owned());
    }
    if parsed.try_build().ok().as_deref() != Some(&bytes[..]) {
        return Err("the round trip of the copy is not lossless".to_owned());
    }
    fs::write(copy, &bytes).map_err(|error| format!("cannot write the copy: {error}"))?;
    fs::set_permissions(copy, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot make the copy executable: {error}"))?;
    let outcome = run_program(target, copy)?;
    if outcome == *expected {
        Ok(())
    } else {
        Err(format!(
            "the copy gives {outcome:?}, the original {expected:?}"
        ))
    }
}

/// Run the program at `path` and return its output.
fn run_program(target: &Target, path: &Path) -> Result<Outcome, String> {
    let mut command = match target.emulator {
        Some((emulator, sysroot)) => {
            let mut command = Command::new(emulator);
            command.arg("-L").arg(sysroot).arg(path);
            command
        }
        None => Command::new(path),
    };
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", path.display()))?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() > TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} does not stop", path.display()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
            Err(error) => return Err(format!("cannot wait for {}: {error}", path.display())),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot read the output: {error}"))?;
    Ok(Outcome {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}
