//! Print the symbol tables and the relocation sections.

use crate::Failure;
use crate::headers::address_width;
use elfex::section::{SHN_ABS, SHN_COMMON, SHN_UNDEF};
use elfex::{ElfFile, NamedSymbol, Relocation, SectionType};
use std::io::Write;

fn section_text(symbol: &NamedSymbol) -> String {
    match symbol.symbol.shndx {
        SHN_UNDEF => "UND".to_owned(),
        SHN_ABS => "ABS".to_owned(),
        SHN_COMMON => "COM".to_owned(),
        _ => symbol
            .section_index
            .map_or_else(|| "?".to_owned(), |index| index.to_string()),
    }
}

fn symbol_name(symbol: &NamedSymbol) -> String {
    match (&symbol.version, &symbol.version_file) {
        (Some(version), Some(file)) => format!("{}@{version} ({file})", symbol.name),
        (Some(version), None) if symbol.hidden => format!("{}@{version}", symbol.name),
        (Some(version), None) => format!("{}@@{version}", symbol.name),
        (None, _) => symbol.name.clone(),
    }
}

fn print_symbol_list(
    file: &ElfFile,
    out: &mut dyn Write,
    title: &str,
    symbols: &[NamedSymbol],
) -> Result<(), Failure> {
    let width = address_width(file);
    writeln!(out, "{title} ({} entries):", symbols.len())?;
    writeln!(
        out,
        "  {:>6} {:<w$} {:>6} {:<12} {:<12} {:<12} {:>5} Name",
        "Num",
        "Value",
        "Size",
        "Type",
        "Bind",
        "Vis",
        "Ndx",
        w = width + 2
    )?;
    for symbol in symbols {
        let entry = &symbol.symbol;
        writeln!(
            out,
            "  {:>6} {:#0w$x} {:>6} {:<12} {:<12} {:<12} {:>5} {}",
            symbol.index,
            entry.value,
            entry.size,
            entry.symbol_type().to_string(),
            entry.binding().to_string(),
            entry.visibility().to_string(),
            section_text(symbol),
            symbol_name(symbol),
            w = width + 2
        )?;
    }
    writeln!(out)?;
    Ok(())
}

pub fn print_symbols(file: &ElfFile, out: &mut dyn Write) -> Result<(), Failure> {
    let dynamic = file.dynamic_symbol_list()?;
    if dynamic.is_empty() {
        writeln!(out, "The file has no dynamic symbols.")?;
        writeln!(out)?;
    } else {
        print_symbol_list(file, out, "Dynamic symbols", &dynamic)?;
    }
    let symbols = file.symbol_list()?;
    if symbols.is_empty() {
        writeln!(out, "The file has no static symbol table.")?;
        writeln!(out)?;
    } else {
        print_symbol_list(file, out, "Static symbols (.symtab)", &symbols)?;
    }
    Ok(())
}

/// Return the symbols of the symbol table section `index`, with names.
fn symbols_of(file: &ElfFile, index: Option<usize>) -> elfex::Result<Vec<NamedSymbol>> {
    let section_type = index
        .and_then(|index| file.section_headers().get(index))
        .map(|header| header.section_type);
    match section_type {
        Some(SectionType::DYNSYM) => file.dynamic_symbol_list(),
        Some(SectionType::SYMTAB) => file.symbol_list(),
        _ => Ok(Vec::new()),
    }
}

fn relocation_line(file: &ElfFile, relocation: &Relocation, symbols: &[NamedSymbol]) -> String {
    let width = address_width(file);
    let kind = relocation
        .type_name(file.machine())
        .map_or_else(|| format!("{:#x}", relocation.r_type), str::to_owned);
    // The symbol lists have no null symbol: the symbol at index `i` is entry `i - 1`.
    let symbol = relocation
        .symbol
        .checked_sub(1)
        .and_then(|position| usize::try_from(position).ok())
        .and_then(|position| symbols.get(position))
        .filter(|symbol| symbol.index == relocation.symbol && !symbol.name.is_empty())
        .map_or_else(String::new, symbol_name);
    let addend = relocation.addend.map_or_else(String::new, |addend| {
        if addend < 0 {
            format!("-{:#x}", addend.unsigned_abs())
        } else {
            format!("+{addend:#x}")
        }
    });
    format!(
        "  {:#0w$x} {kind:<28} {symbol} {addend}",
        relocation.offset,
        w = width + 2
    )
}

pub fn print_relocations(file: &ElfFile, out: &mut dyn Write) -> Result<(), Failure> {
    let sections = file.relocation_sections()?;
    if sections.is_empty() {
        writeln!(out, "The file has no relocation sections.")?;
    }
    for section in &sections {
        let symbols = symbols_of(file, section.symbol_table)?;
        // The type shows the format: for example SHT_RELA, SHT_CREL or SHT_ANDROID_RELA.
        let kind = file
            .section_headers()
            .get(section.index)
            .map_or_else(String::new, |header| format!(" [{}]", header.section_type));
        let target = section
            .target_section
            .and_then(|index| file.section(index))
            .map_or_else(String::new, |target| format!(" for {}", target.name));
        writeln!(
            out,
            "Relocation section {}{kind}{target} ({} entries):",
            section.name,
            section.table.relocations.len()
        )?;
        for relocation in &section.table.relocations {
            writeln!(out, "{}", relocation_line(file, relocation, &symbols))?;
        }
        writeln!(out)?;
    }
    let dynamic = file.dynamic_relocations()?;
    if let Some(relr) = &dynamic.relr {
        writeln!(out, "RELR relative relocations: {} addresses", relr.len())?;
        writeln!(out)?;
    }
    let packed = [
        ("Android packed relocations (APS2)", &dynamic.android),
        ("CREL relocations", &dynamic.crel),
    ];
    for (name, table) in packed {
        if let Some(table) = table {
            writeln!(out, "{name} of the dynamic table: {} entries", table.len())?;
            writeln!(out)?;
        }
    }
    Ok(())
}
