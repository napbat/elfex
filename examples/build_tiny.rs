//! Build a minimal static x86-64 Linux executable with `ElfBuilder`.
//!
//! ```text
//! cargo run --example build-tiny -- [--message TEXT] [OUTPUT]
//! ```
//!
//! The program writes a message to the standard output with the `write` system call. Then it
//! stops with the `exit` system call. It has no interpreter and no libraries.

use elfex::section::{SHF_ALLOC, SHF_EXECINSTR};
use elfex::{BuilderSection, ElfBuilder, ElfFile, ElfImage, Encoding, Machine};
use std::process::ExitCode;

const USAGE: &str = "\
usage: build-tiny [--message TEXT] [OUTPUT]

Build a minimal static x86-64 Linux executable that prints TEXT. The default OUTPUT is 'tiny'.";

/// The offset in the code of the instruction after `lea`. RIP has this value.
const AFTER_LEA: u64 = 17;

/// Return the machine code. `displacement` is the distance from the instruction after `lea`
/// to the message, and `length` is the message length.
fn code(displacement: i32, length: u32) -> Vec<u8> {
    let mut code = vec![
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (SYS_write)
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 (standard output)
        0x48, 0x8d, 0x35, // lea rsi, [rip + disp32]
    ];
    code.extend_from_slice(&displacement.to_le_bytes());
    code.push(0xba); // mov edx, length
    code.extend_from_slice(&length.to_le_bytes());
    code.extend_from_slice(&[
        0x0f, 0x05, // syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (SYS_exit)
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
    ]);
    code
}

/// Build the executable. Plan the layout with placeholder code of the final size to get the
/// address of `.rodata`. Then build the file with the final code.
fn build(message: &str) -> elfex::Result<Vec<u8>> {
    let mut text = message.as_bytes().to_vec();
    text.push(b'\n');
    let length =
        u32::try_from(text.len()).map_err(|_| elfex::Error::generic("the message is too long"))?;

    let builder = |code| {
        ElfBuilder::new(Encoding::ELF64_LE)
            .machine(Machine::X86_64)
            .add_section(BuilderSection::progbits(
                ".text",
                SHF_ALLOC | SHF_EXECINSTR,
                code,
            ))
            .add_section(BuilderSection::progbits(".rodata", SHF_ALLOC, text.clone()))
            .entry_in_section(".text", 0)
    };
    // The layout depends only on the section sizes, so the placeholder code gives the final
    // addresses.
    let layout = builder(code(0, 0)).try_layout()?;
    let address_of = |name: &str| {
        layout
            .section(name)
            .map(|section| section.addr)
            .ok_or_else(|| elfex::Error::generic(format!("the layout has no {name}")))
    };
    let (text_address, rodata_address) = (address_of(".text")?, address_of(".rodata")?);
    let displacement = i64::try_from(rodata_address)
        .ok()
        .zip(i64::try_from(text_address + AFTER_LEA).ok())
        .and_then(|(target, rip)| i32::try_from(target - rip).ok())
        .ok_or_else(|| elfex::Error::generic(".rodata is too far from .text"))?;

    let bytes = builder(code(displacement, length))
        .try_build()?
        .try_build()?;
    let result = ElfFile::parse(&bytes)?.validate();
    if result.has_errors() {
        return Err(elfex::Error::generic(format!(
            "the built file is not valid: {:?}",
            result.issues
        )));
    }
    Ok(bytes)
}

/// Write the file. Make it executable on Unix.
fn write_executable(path: &str, bytes: &[u8]) -> elfex::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Option<(String, String)>, String> {
    let mut message = "Hello from an ELF file that elfex built!".to_owned();
    let mut output = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => return Ok(None),
            "--message" => message = args.next().ok_or("'--message' needs a value")?,
            _ if arg.starts_with('-') => return Err(format!("unknown option '{arg}'")),
            _ if output.is_some() => return Err("give only one OUTPUT".to_owned()),
            _ => output = Some(arg),
        }
    }
    Ok(Some((message, output.unwrap_or_else(|| "tiny".to_owned()))))
}

fn main() -> ExitCode {
    let (message, output) = match parse_args(std::env::args().skip(1)) {
        Ok(Some(arguments)) => arguments,
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Err(message) => {
            eprintln!("build-tiny: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let result = build(&message).and_then(|bytes| {
        write_executable(&output, &bytes)?;
        let image = ElfImage::parse(&bytes)?;
        println!(
            "Wrote {output}: {} bytes, {} PT_LOAD segments, entry point {:#x}.",
            bytes.len(),
            image.load_segments().count(),
            image.entry_point()
        );
        Ok(())
    });
    match result {
        Ok(()) => {
            let command = if output.contains('/') {
                output
            } else {
                format!("./{output}")
            };
            println!("Run it on x86-64 Linux, or with qemu-x86_64 on a different host: {command}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("build-tiny: {error}");
            ExitCode::FAILURE
        }
    }
}
