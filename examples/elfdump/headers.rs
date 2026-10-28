//! Print the file header, the program headers and the section headers.

use elfex::program::{PF_R, PF_W, PF_X};
use elfex::section::{
    SHF_ALLOC, SHF_COMPRESSED, SHF_EXCLUDE, SHF_EXECINSTR, SHF_GROUP, SHF_INFO_LINK,
    SHF_LINK_ORDER, SHF_MERGE, SHF_STRINGS, SHF_TLS, SHF_WRITE,
};
use elfex::{Class, ElfFile, Endian};

/// Return the number of hexadecimal digits of an address in the file.
pub fn address_width(file: &ElfFile) -> usize {
    file.encoding().addr_size() * 2
}

pub fn print_file_header(file: &ElfFile) {
    let header = file.header();
    let ident = &header.ident;
    let class = match ident.class {
        Class::Elf32 => "ELF32",
        Class::Elf64 => "ELF64",
    };
    let endian = match ident.endian {
        Endian::Little => "little-endian",
        Endian::Big => "big-endian",
    };
    println!("File header:");
    println!("  Class:                  {class}");
    println!("  Data:                   {endian}");
    println!(
        "  OS/ABI:                 {} (ABI version {})",
        ident.os_abi, ident.abi_version
    );
    println!("  Type:                   {}", header.file_type);
    println!("  Machine:                {}", header.machine);
    println!("  Version:                {}", header.version);
    println!("  Entry point:            {:#x}", header.entry);
    println!("  Program headers offset: {:#x}", header.phoff);
    println!("  Section headers offset: {:#x}", header.shoff);
    println!("  Flags:                  {:#x}", header.flags);
    println!("  Program headers:        {}", file.program_headers().len());
    println!("  Section headers:        {}", file.section_headers().len());
    println!("  Section name index:     {}", header.shstrndx);
    println!();
}

fn segment_flags(flags: u32) -> String {
    [(PF_R, 'R'), (PF_W, 'W'), (PF_X, 'E')]
        .iter()
        .map(|&(bit, letter)| if flags & bit == 0 { ' ' } else { letter })
        .collect()
}

pub fn print_program_headers(file: &ElfFile) {
    let width = address_width(file);
    println!("Program headers ({}):", file.program_headers().len());
    println!(
        "  {:<16} {:<w$} {:<w$} {:<w$} {:<w$} Flg Align",
        "Type",
        "Offset",
        "VirtAddr",
        "FileSiz",
        "MemSiz",
        w = width + 2
    );
    for header in file.program_headers() {
        println!(
            "  {:<16} {:#0w$x} {:#0w$x} {:#0w$x} {:#0w$x} {} {:#x}",
            header.segment_type.to_string(),
            header.offset,
            header.vaddr,
            header.filesz,
            header.memsz,
            segment_flags(header.flags),
            header.align,
            w = width + 2
        );
    }
    match file.interpreter() {
        Ok(Some(path)) => println!("  Program interpreter: {path}"),
        Ok(None) => {}
        Err(error) => println!("  Program interpreter: <{error}>"),
    }
    println!();
}

fn section_flags(flags: u64) -> String {
    const LETTERS: [(u64, char); 11] = [
        (SHF_WRITE, 'W'),
        (SHF_ALLOC, 'A'),
        (SHF_EXECINSTR, 'X'),
        (SHF_MERGE, 'M'),
        (SHF_STRINGS, 'S'),
        (SHF_INFO_LINK, 'I'),
        (SHF_LINK_ORDER, 'L'),
        (SHF_GROUP, 'G'),
        (SHF_TLS, 'T'),
        (SHF_COMPRESSED, 'C'),
        (SHF_EXCLUDE, 'E'),
    ];
    LETTERS
        .iter()
        .filter(|&&(bit, _)| flags & bit != 0)
        .map(|&(_, letter)| letter)
        .collect()
}

pub fn print_section_headers(file: &ElfFile) {
    let width = address_width(file);
    println!("Section headers ({}):", file.section_headers().len());
    println!(
        "  [Nr] {:<20} {:<16} {:<w$} {:<10} {:<10} {:<5} Lk  Inf Al",
        "Name",
        "Type",
        "Address",
        "Offset",
        "Size",
        "Flg",
        w = width + 2
    );
    for section in file.sections() {
        let header = section.header;
        println!(
            "  [{:>2}] {:<20} {:<16} {:#0w$x} {:#010x} {:#010x} {:<5} {:<3} {:<3} {}",
            section.index,
            section.name,
            header.section_type.to_string(),
            header.addr,
            header.offset,
            header.size,
            section_flags(header.flags),
            header.link,
            header.info,
            header.addralign,
            w = width + 2
        );
    }
    println!("  Flags: W (write), A (alloc), X (execute), M (merge), S (strings), I (info link),");
    println!("  L (link order), G (group), T (TLS), C (compressed), E (exclude)");
    println!();
}
