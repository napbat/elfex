//! Compare the dynamic and the static symbols.

use elfex::{ElfFile, NamedSymbol, SymbolType};
use serde_json::Value;

use super::numbers;
use crate::reference::{array, string};
use crate::report::{DYNAMIC_SYMBOLS, Findings, SYMBOLS};

/// Compare the dynamic symbols (`DynamicSymbols`) and the static symbols (`Symbols`).
pub fn compare(file: &ElfFile, json: &Value, findings: &mut Findings) {
    match file.dynamic_symbol_list() {
        Ok(list) => table(
            file,
            array(json, &["DynamicSymbols"]),
            &list,
            DYNAMIC_SYMBOLS,
            findings,
        ),
        Err(error) => findings.fail(DYNAMIC_SYMBOLS, format!("dynamic_symbol_list: {error}")),
    }
    match file.symbol_list() {
        Ok(list) => table(file, array(json, &["Symbols"]), &list, SYMBOLS, findings),
        Err(error) => findings.fail(SYMBOLS, format!("symbol_list: {error}")),
    }
}

/// Return the name that `llvm-readelf` prints for a symbol.
///
/// - A section symbol without a name has the name of its section.
/// - A dynamic symbol with a version has the suffix `@version`. The suffix is `@@version` for
///   the default version of a defined symbol.
pub fn display_name(file: &ElfFile, symbol: &NamedSymbol, dynamic: bool) -> String {
    if symbol.name.is_empty() && symbol.symbol.symbol_type() == SymbolType::SECTION {
        return symbol
            .section_index
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| file.section_names().get(index))
            .cloned()
            .unwrap_or_default();
    }
    match (&symbol.version, dynamic) {
        (Some(version), true) => {
            let default =
                symbol.version_file.is_none() && symbol.symbol.is_defined() && !symbol.hidden;
            let separator = if default { "@@" } else { "@" };
            format!("{}{separator}{version}", symbol.name)
        }
        _ => symbol.name.clone(),
    }
}

/// Compare one symbol table. The reference lists the null symbol at index 0, and elfex does
/// not.
fn table(
    file: &ElfFile,
    items: &[Value],
    list: &[NamedSymbol],
    category: &'static str,
    findings: &mut Findings,
) {
    let items = items.get(1..).unwrap_or_default();
    findings.check(category, "symbol count", items.len(), list.len());
    let dynamic = category == DYNAMIC_SYMBOLS;
    for (item, symbol) in items.iter().zip(list) {
        let item = &item["Symbol"];
        let what = format!("symbol {}", symbol.index);
        findings.check(
            category,
            format_args!("{what} name"),
            string(item, &["Name", "Name"]).map(str::to_owned),
            Ok(display_name(file, symbol, dynamic)),
        );
        let entry = symbol.symbol;
        numbers(
            findings,
            category,
            &what,
            item,
            &[
                (&["Name", "Value"], u64::from(entry.name)),
                (&["Value"], entry.value),
                (&["Size"], entry.size),
                (&["Binding", "Value"], u64::from(entry.binding().0)),
                (&["Type", "Value"], u64::from(entry.symbol_type().0)),
                (&["Other", "Value"], u64::from(entry.other)),
                (
                    &["Section", "Value"],
                    u64::from(symbol.section_index.unwrap_or(0)),
                ),
            ],
        );
    }
}
