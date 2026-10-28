//! Read a module of a running Linux process through `/proc/<pid>/mem`.
//!
//! ```text
//! cargo run --example dump-process -- PID [MODULE] [--output PATH]
//! ```
//!
//! The tool finds the module in `/proc/<pid>/maps`. Then it parses the loader-mapped image
//! with `ElfImage::read_from_with_options` and prints a summary. With `--output`, it also
//! writes the image as a raw file without sections (`ElfImage::try_build`). Before the write,
//! it changes the `d_ptr` values that glibc relocated back to virtual addresses of the file.
//!
//! Read access to the memory of a different process needs the same user and a `ptrace`
//! permission (see `/proc/sys/kernel/yama/ptrace_scope`), or root.

#[cfg(target_os = "linux")]
mod linux;

use std::process::ExitCode;

#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> ExitCode {
    eprintln!("dump-process: this tool reads /proc/<pid>/mem and works on Linux only");
    ExitCode::FAILURE
}
