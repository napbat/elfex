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

/// The offset in the code of the 32-bit displacement of `lea rsi, [rip + disp32]`.
const DISPLACEMENT_OFFSET: usize = 13;
/// The offset in the code of the instruction after `lea`. RIP has this value.
const AFTER_LEA: u64 = 17;
/// The offset in the code of the 32-bit length of `mov edx, imm32`.
const LENGTH_OFFSET: usize = 18;

/// Return the machine code. Patch the displacement and the length after the layout is known.
fn code() -> Vec<u8> {
    vec![
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1 (SYS_write)
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 (standard output)
        0x48, 0x8d, 0x35, 0x00, 0x00, 0x00, 0x00, // lea rsi, [rip + disp32]
        0xba, 0x00, 0x00, 0x00, 0x00, // mov edx, length
        0x0f, 0x05, // syscall
        0xb8, 0x3c, 0x00, 0x00, 0x00, // mov eax, 60 (SYS_exit)
        0x31, 0xff, // xor edi, edi
        0x0f, 0x05, // syscall
    ]
}

/// Build the executable. Then put the address of `.rodata` and the message length in the code.
fn build(message: &str) -> elfex::Result<Vec<u8>> {
    let mut text = message.as_bytes().to_vec();
    text.push(b'\n');
    let length =
        u32::try_from(text.len()).map_err(|_| elfex::Error::generic("the message is too long"))?;

    let mut file = ElfBuilder::new(Encoding::ELF64_LE)
        .machine(Machine::X86_64)
        .add_section(BuilderSection::progbits(
            ".text",
            SHF_ALLOC | SHF_EXECINSTR,
            code(),
        ))
        .add_section(BuilderSection::progbits(".rodata", SHF_ALLOC, text))
        .entry_in_section(".text", 0)
        .try_build()?;

    let address_of = |file: &ElfFile, name: &str| {
        file.section_by_name(name)
            .map(|section| (section.index, section.header.addr))
            .ok_or_else(|| elfex::Error::generic(format!("the builder did not add {name}")))
    };
    let (text_index, text_address) = address_of(&file, ".text")?;
    let (_, rodata_address) = address_of(&file, ".rodata")?;
    let displacement = i64::try_from(rodata_address)
        .ok()
        .zip(i64::try_from(text_address + AFTER_LEA).ok())
        .and_then(|(target, rip)| i32::try_from(target - rip).ok())
        .ok_or_else(|| elfex::Error::generic(".rodata is too far from .text"))?;

    let mut patched = code();
    patched[DISPLACEMENT_OFFSET..DISPLACEMENT_OFFSET + 4]
        .copy_from_slice(&displacement.to_le_bytes());
    patched[LENGTH_OFFSET..LENGTH_OFFSET + 4].copy_from_slice(&length.to_le_bytes());
    // The new data has the same size, so it stays at the same address.
    file.set_section_data(text_index, patched)?;

    let bytes = file.try_build()?;
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
