//! Print the symbol tables and the relocation sections.

use crate::headers::address_width;
use elfex::section::{SHN_ABS, SHN_COMMON, SHN_UNDEF};
use elfex::{ElfFile, NamedSymbol, Relocation, SectionType};

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

fn print_symbol_list(file: &ElfFile, title: &str, symbols: &[NamedSymbol]) {
    let width = address_width(file);
    println!("{title} ({} entries):", symbols.len());
    println!(
        "  {:>6} {:<w$} {:>6} {:<12} {:<12} {:<12} {:>5} Name",
        "Num",
        "Value",
        "Size",
        "Type",
        "Bind",
        "Vis",
        "Ndx",
        w = width + 2
    );
    for symbol in symbols {
        let entry = &symbol.symbol;
        println!(
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
        );
    }
    println!();
}

pub fn print_symbols(file: &ElfFile) -> elfex::Result<()> {
    let dynamic = file.dynamic_symbol_list()?;
    if dynamic.is_empty() {
        println!("The file has no dynamic symbols.");
        println!();
    } else {
        print_symbol_list(file, "Dynamic symbols", &dynamic);
    }
    let symbols = file.symbol_list()?;
    if symbols.is_empty() {
        println!("The file has no static symbol table.");
        println!();
    } else {
        print_symbol_list(file, "Static symbols (.symtab)", &symbols);
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
    let symbol = usize::try_from(relocation.symbol)
        .ok()
        .and_then(|index| symbols.get(index))
        .filter(|symbol| relocation.symbol != 0 && !symbol.name.is_empty())
        .map_or_else(String::new, symbol_name);
    let addend = relocation
        .addend
        .map_or_else(String::new, |addend| format!("{addend:+#x}"));
    format!(
        "  {:#0w$x} {kind:<28} {symbol} {addend}",
        relocation.offset,
        w = width + 2
    )
}

pub fn print_relocations(file: &ElfFile) -> elfex::Result<()> {
    let sections = file.relocation_sections()?;
    if sections.is_empty() {
        println!("The file has no relocation sections.");
    }
    for section in &sections {
        let symbols = symbols_of(file, section.symbol_table)?;
        let target = section
            .target_section
            .and_then(|index| file.section(index))
            .map_or_else(String::new, |target| format!(" for {}", target.name));
        println!(
            "Relocation section {}{target} ({} entries):",
            section.name,
            section.table.relocations.len()
        );
        for relocation in &section.table.relocations {
            println!("{}", relocation_line(file, relocation, &symbols));
        }
        println!();
    }
    if let Some(relr) = file.dynamic_relocations()?.relr {
        println!("RELR relative relocations: {} addresses", relr.len());
        println!();
    }
    Ok(())
}
