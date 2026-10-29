//! The Linux implementation: `/proc/<pid>/maps`, `/proc/<pid>/mem` and the summary.

use elfex::{ElfImage, ParseOptions, ReadAt};
use std::fmt::Write;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::process::ExitCode;

const USAGE: &str = "\
usage: dump-process PID [MODULE] [--output PATH]

Parse a module of a running process from /proc/PID/mem and print a summary.

arguments:
  PID                the process ID
  MODULE             the path, the file name or a part of the path of a mapped file
                     (default: the executable of the process)
  -o, --output PATH  write the module as a raw ELF file without sections";

/// The memory of a process, read through `/proc/<pid>/mem`.
struct ProcessMemory {
    mem: File,
}

impl ReadAt for ProcessMemory {
    fn read_at(&self, address: u64, buf: &mut [u8]) -> elfex::Result<usize> {
        // An unmapped or unreadable page gives an I/O error (EIO). The parser fills such pages
        // with zeros because of `allow_missing_segment_data`.
        Ok(self.mem.read_at(buf, address)?)
    }

    fn size(&self) -> Option<u64> {
        // The address space of a process has no size.
        None
    }
}

/// One line of `/proc/<pid>/maps` with a path.
struct Mapping {
    start: u64,
    offset: u64,
    path: String,
}

/// Parse a line `start-end perms offset dev inode path`. Return `None` for an anonymous map.
fn parse_mapping(line: &str) -> Option<Mapping> {
    let mut fields = line.split_whitespace();
    let (start, _) = fields.next()?.split_once('-')?;
    let _permissions = fields.next()?;
    let offset = fields.next()?;
    let _device = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.collect::<Vec<_>>().join(" ");
    if !path.starts_with('/') {
        return None;
    }
    Some(Mapping {
        start: u64::from_str_radix(start, 16).ok()?,
        offset: u64::from_str_radix(offset, 16).ok()?,
        path,
    })
}

/// Return the path and the runtime base of the module. The runtime base is the address of
/// file offset 0: the address of the ELF header.
fn find_module(pid: u32, module: Option<&str>) -> Result<(String, u64), String> {
    let maps_path = format!("/proc/{pid}/maps");
    let maps =
        std::fs::read_to_string(&maps_path).map_err(|error| format!("{maps_path}: {error}"))?;
    let wanted = if let Some(module) = module {
        module.to_owned()
    } else {
        let exe = format!("/proc/{pid}/exe");
        std::fs::read_link(&exe)
            .map_err(|error| format!("{exe}: {error}"))?
            .to_string_lossy()
            .into_owned()
    };
    // The mappings at file offset 0. The first mapping of each file holds the ELF header.
    let headers: Vec<Mapping> = maps
        .lines()
        .filter_map(parse_mapping)
        .filter(|mapping| mapping.offset == 0)
        .collect();
    let exact = |mapping: &&Mapping| {
        mapping.path == wanted || mapping.path.rsplit('/').next() == Some(wanted.as_str())
    };
    let mut candidates: Vec<&Mapping> = headers.iter().filter(exact).collect();
    if candidates.is_empty() {
        candidates = headers
            .iter()
            .filter(|mapping| mapping.path.contains(wanted.as_str()))
            .collect();
    }
    let mut paths: Vec<&str> = candidates
        .iter()
        .map(|mapping| mapping.path.as_str())
        .collect();
    paths.sort_unstable();
    paths.dedup();
    if paths.len() > 1 {
        return Err(format!(
            "'{wanted}' matches more than one file: {}",
            paths.join(", ")
        ));
    }
    let mapping = candidates
        .into_iter()
        .min_by_key(|mapping| mapping.start)
        .ok_or_else(|| format!("no file mapping of process {pid} matches '{wanted}'"))?;
    Ok((mapping.path.clone(), mapping.start))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn print_summary(path: &str, runtime_base: u64, image: &ElfImage<'_>) -> elfex::Result<()> {
    println!("Module:        {path}");
    println!("Runtime base:  {runtime_base:#x}");
    if let Some(bias) = image.load_bias() {
        println!("Load bias:     {bias:#x}");
    }
    println!("Type:          {}", image.file_type());
    println!("Machine:       {}", image.machine());
    println!(
        "Segments:      {} ({} PT_LOAD)",
        image.segments.len(),
        image.load_segments().count()
    );
    println!(
        "Soname:        {}",
        image.soname()?.unwrap_or_else(|| "(none)".to_owned())
    );
    println!(
        "Interpreter:   {}",
        image.interpreter()?.unwrap_or_else(|| "(none)".to_owned())
    );
    println!("Needed:        {}", image.needed_libraries()?.join(", "));
    println!("Exports:       {}", image.exports()?.len());
    println!("Imports:       {}", image.imports()?.len());
    match image.build_id()? {
        Some(build_id) => println!("Build ID:      {}", hex(&build_id)),
        None => println!("Build ID:      (none)"),
    }
    let issues = image.validate().issues;
    println!("Validation:    {} issues", issues.len());
    for issue in &issues {
        println!("  {:?}: {}", issue.level, issue.message);
    }
    Ok(())
}

/// The command line arguments.
struct Arguments {
    pid: u32,
    module: Option<String>,
    output: Option<String>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<Arguments>, String> {
    let mut positional = Vec::new();
    let mut output = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => return Ok(None),
            "-o" | "--output" => output = Some(args.next().ok_or("'--output' needs a value")?),
            _ if arg.starts_with('-') => return Err(format!("unknown option '{arg}'")),
            _ => positional.push(arg),
        }
    }
    let mut positional = positional.into_iter();
    let pid = positional.next().ok_or("give a PID")?;
    let pid = pid
        .parse()
        .map_err(|_| format!("'{pid}' is not a process ID"))?;
    let module = positional.next();
    if positional.next().is_some() {
        return Err("give only a PID and a MODULE".to_owned());
    }
    Ok(Some(Arguments {
        pid,
        module,
        output,
    }))
}

/// Write the image as a raw ELF file without sections. First change the `d_ptr` values that
/// glibc relocated back to virtual addresses of the file, so that other tools can read the
/// dynamic table of the dump.
fn write_dump(mut image: ElfImage<'_>, output: &str) -> elfex::Result<()> {
    let changed = image.restore_dynamic_pointers()?;
    let bytes = image.try_build()?;
    std::fs::write(output, &bytes)?;
    println!(
        "Wrote {} bytes to {output}. Restored {changed} dynamic table pointers.",
        bytes.len()
    );
    Ok(())
}

fn run(arguments: &Arguments) -> Result<(), String> {
    let (path, runtime_base) = find_module(arguments.pid, arguments.module.as_deref())?;
    let mem_path = format!("/proc/{}/mem", arguments.pid);
    let mem = File::open(&mem_path).map_err(|error| {
        let hint = if error.kind() == std::io::ErrorKind::PermissionDenied {
            "\nhint: run as root, or as the parent of the process (kernel.yama.ptrace_scope)"
        } else {
            ""
        };
        format!("{mem_path}: {error}{hint}")
    })?;
    let image = ElfImage::read_from_with_options(
        &ProcessMemory { mem },
        runtime_base,
        ParseOptions::mapped()
            .runtime_base(runtime_base)
            .allow_missing_segment_data(),
    )
    .map_err(|error| format!("{path} at {runtime_base:#x}: {error}"))?;
    print_summary(&path, runtime_base, &image).map_err(|error| format!("{path}: {error}"))?;
    if let Some(output) = &arguments.output {
        write_dump(image, output).map_err(|error| format!("{output}: {error}"))?;
    }
    Ok(())
}

pub fn main() -> ExitCode {
    let arguments = match parse_args(std::env::args().skip(1)) {
        Ok(Some(arguments)) => arguments,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("dump-process: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("dump-process: {message}");
            ExitCode::FAILURE
        }
    }
}
