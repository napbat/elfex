//! Read the dynamic symbols, their names and their versions.

use super::{Linker, TableSection, VersionTables};
use crate::dynamic::DynamicTag;
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::header::Machine;
use crate::prelude::*;
use crate::section::SHN_XINDEX;
use crate::strtab::StringTable;
use crate::symbol::{
    NamedSymbol, Symbol, SymbolBinding, SymbolNames, SymbolSectionIndexTable, SymbolTable,
    SymbolVisibility,
};
use crate::version::{VersionDefinitionTable, VersionMap, VersionRequirementTable, VersymTable};
use crate::{Error, Result};

/// Return the name bytes of the symbol at `index`, or `None` if they are not available.
fn name_bytes<'a>(
    symbols: &SymbolTable,
    strings: Option<StringTable<'a>>,
    index: u32,
) -> Option<&'a [u8]> {
    let symbol = symbols.get(usize::try_from(index).ok()?)?;
    strings?.get_bytes(symbol.name).ok()
}

/// Return `true` for a symbol that the object exports: a defined symbol with the binding
/// `STB_GLOBAL`, `STB_WEAK` or `STB_GNU_UNIQUE`, and a visibility other than `STV_HIDDEN`
/// and `STV_INTERNAL`.
pub(crate) fn is_export(symbol: &Symbol) -> bool {
    let binding = symbol.binding();
    let visibility = symbol.visibility();
    symbol.is_defined()
        && [
            SymbolBinding::GLOBAL,
            SymbolBinding::WEAK,
            SymbolBinding::GNU_UNIQUE,
        ]
        .contains(&binding)
        && visibility != SymbolVisibility::HIDDEN
        && visibility != SymbolVisibility::INTERNAL
}

/// Return `true` for an undefined symbol: a symbol that the object imports.
pub(crate) fn is_import(symbol: &Symbol) -> bool {
    symbol.is_undefined()
}

/// Return `true` for all symbols.
pub(crate) const fn is_any(_symbol: &Symbol) -> bool {
    true
}

/// The parsed tables that describe the dynamic symbols.
pub(crate) struct DynamicSymbols<'a, 't> {
    /// The dynamic string table.
    pub(crate) strings: Option<StringTable<'a>>,
    /// The dynamic symbol table.
    pub(crate) symbols: &'t SymbolTable,
    /// The extended section indices, if a symbol needs them.
    pub(crate) indices: Option<&'t SymbolSectionIndexTable>,
    /// The version tables.
    pub(crate) versions: &'t VersionTables,
    /// The map from the version indexes to the version names.
    pub(crate) map: &'t VersionMap,
}

impl<'a> DynamicSymbols<'a, '_> {
    /// Return the tables that describe a dynamic symbol.
    fn names(&self) -> SymbolNames<'a, '_> {
        SymbolNames {
            strings: self.strings,
            structure: "DT_STRTAB",
            indices: self.indices,
            versym: self.versions.versym.as_ref(),
            map: Some(self.map),
        }
    }

    /// Return the dynamic symbols after index 0 that `keep` accepts.
    pub(crate) fn list(&self, keep: impl Fn(&Symbol) -> bool) -> Result<Vec<NamedSymbol<'a>>> {
        self.names().describe_all(&self.symbols.symbols, keep)
    }

    /// Make the [`NamedSymbol`] of the symbol at `index`.
    pub(crate) fn describe(&self, index: usize, symbol: Symbol) -> Result<NamedSymbol<'a>> {
        self.names().describe(index, symbol)
    }
}

/// The tables that a dynamic symbol lookup uses.
pub(crate) struct SymbolSearch<'a, 't> {
    /// The dynamic symbol table.
    pub(crate) symbols: &'t SymbolTable,
    /// The dynamic string table.
    pub(crate) strings: Option<StringTable<'a>>,
    /// The GNU hash table.
    pub(crate) gnu_hash: Option<&'t GnuHashTable>,
    /// The System V hash table.
    pub(crate) sysv_hash: Option<&'t SysvHashTable>,
    /// The output of [`sorted_names`], or `None` for a linear search.
    pub(crate) sorted: Option<&'t [u32]>,
}

impl SymbolSearch<'_, '_> {
    /// Find the symbol with the name `name`: with the GNU hash table, else with the System V
    /// hash table, else with a binary search of the sorted names, else with a linear search.
    /// If more than one symbol has the name, the searches without a hash table find the one
    /// with the lowest index.
    pub(crate) fn find(&self, name: &str) -> Option<(usize, Symbol)> {
        let name = name.as_bytes();
        let symbol_name = |index: u32| name_bytes(self.symbols, self.strings, index);
        let found = if let Some(table) = self.gnu_hash {
            table.lookup(name, symbol_name)
        } else if let Some(table) = self.sysv_hash {
            table.lookup(name, symbol_name)
        } else if let Some(sorted) = self.sorted {
            let first = sorted.partition_point(|index| symbol_name(*index) < Some(name));
            sorted
                .get(first)
                .copied()
                .filter(|index| symbol_name(*index) == Some(name))
        } else {
            (1..self.symbols.len())
                .filter_map(|index| u32::try_from(index).ok())
                .find(|index| symbol_name(*index) == Some(name))
        };
        let index = usize::try_from(found?).ok()?;
        Some((index, *self.symbols.get(index)?))
    }
}

/// Return the indices of the dynamic symbols with a name, except index 0, sorted by name
/// and then by index.
pub(crate) fn sorted_names(symbols: &SymbolTable, strings: Option<StringTable<'_>>) -> Vec<u32> {
    let name = |index: &u32| name_bytes(symbols, strings, *index);
    let mut sorted: Vec<u32> = (1..symbols.len())
        .filter_map(|index| u32::try_from(index).ok())
        .filter(|index| name(index).is_some())
        .collect();
    // The sort is stable, so equal names stay in index order.
    sorted.sort_by(|a, b| name(a).cmp(&name(b)));
    sorted
}

impl<'a> Linker<'a> {
    /// Parse the dynamic symbol table.
    ///
    /// `ElfFile` prefers the `SHT_DYNSYM` section. Else the table is at `DT_SYMTAB`. The
    /// count comes from the first source that is available:
    ///
    /// 1. `DT_MIPS_SYMTABNO`, for a MIPS object.
    /// 2. `nchain` of the `DT_HASH` table.
    /// 3. The symbol count of the `DT_GNU_HASH` table, or a larger symbol index that a
    ///    dynamic relocation refers to.
    /// 4. The distance from `DT_SYMTAB` to `DT_STRTAB`, if the string table follows.
    pub(crate) fn symbols(&self) -> Result<Option<SymbolTable>> {
        let encoding = self.encoding();
        if let Some(section) = self.space.table_section(TableSection::DynamicSymbols)? {
            return SymbolTable::parse_with_entsize(section.data, encoding, section.entsize)
                .map(Some)
                .map_err(|error| error.in_structure("SHT_DYNSYM"));
        }
        let Some(address) = self.pointer(DynamicTag::SYMTAB) else {
            return Ok(None);
        };
        let standard = u64::try_from(Symbol::size(encoding.class)).unwrap_or(u64::MAX);
        let entsize = self.value(DynamicTag::SYMENT).unwrap_or(standard);
        if entsize < standard {
            return Err(Error::invalid_table(format!(
                "DT_SYMENT {entsize} is smaller than the symbol size {standard}"
            ))
            .in_structure("DT_SYMTAB"));
        }
        let Some(count) = self.symbol_count(address, entsize)? else {
            return Ok(None);
        };
        let size = count.checked_mul(entsize).ok_or_else(|| {
            Error::invalid_table(format!("the symbol count {count} is too large"))
                .in_structure("DT_SYMTAB")
        })?;
        let bytes = self.bytes(address, size, "DT_SYMTAB")?;
        SymbolTable::parse_with_entsize(bytes, encoding, entsize)
            .map(Some)
            .map_err(|error| error.in_structure("DT_SYMTAB").at_address(address))
    }

    /// Return the number of dynamic symbols at `symtab`, or `None` if no source gives it.
    fn symbol_count(&self, symtab: u64, entsize: u64) -> Result<Option<u64>> {
        if self.space.machine() == Machine::MIPS
            && let Some(count) = self.value(DynamicTag::MIPS_SYMTABNO)
        {
            return Ok(Some(count));
        }
        if let Some(table) = self.sysv_hash()? {
            return Ok(Some(u64::from(table.symbol_count())));
        }
        if let Some(table) = self.gnu_hash()? {
            let hashed = u64::from(table.symbol_count());
            // A relocation table that does not parse gives no count.
            let referenced = self
                .max_relocation_symbol()
                .ok()
                .flatten()
                .map(|symbol| u64::from(symbol) + 1);
            return Ok(Some(
                referenced.map_or(hashed, |referenced| hashed.max(referenced)),
            ));
        }
        Ok(self
            .pointer(DynamicTag::STRTAB)
            .filter(|strtab| *strtab > symtab)
            .map(|strtab| (strtab - symtab) / entsize))
    }

    /// Parse the extended section indices of the dynamic symbols, for a table with `count`
    /// symbols.
    ///
    /// `ElfFile` prefers the `SHT_SYMTAB_SHNDX` section that links to the `SHT_DYNSYM`
    /// section. Else the table is at `DT_SYMTAB_SHNDX`, with one entry for each symbol.
    pub(crate) fn symbol_indices(&self, count: usize) -> Result<Option<SymbolSectionIndexTable>> {
        let encoding = self.encoding();
        if let Some(section) = self
            .space
            .table_section(TableSection::DynamicSymbolIndices)?
        {
            return SymbolSectionIndexTable::parse(section.data, encoding)
                .map(Some)
                .map_err(|error| error.in_structure("SHT_SYMTAB_SHNDX"));
        }
        let Some(address) = self.pointer(DynamicTag::SYMTAB_SHNDX) else {
            return Ok(None);
        };
        // A table in memory has fewer than `u64::MAX / 4` entries. `bytes` rejects a size
        // that the segment does not hold.
        let size = u64::try_from(count).unwrap_or(u64::MAX).saturating_mul(4);
        let bytes = self.bytes(address, size, "DT_SYMTAB_SHNDX")?;
        // `size` is a multiple of 4, so the parse cannot fail.
        SymbolSectionIndexTable::parse(bytes, encoding).map(Some)
    }

    /// Parse the extended section indices of `symbols`, if a symbol needs them.
    pub(crate) fn indices_for(
        &self,
        symbols: &SymbolTable,
    ) -> Result<Option<SymbolSectionIndexTable>> {
        if symbols.iter().any(|symbol| symbol.shndx == SHN_XINDEX) {
            self.symbol_indices(symbols.len())
        } else {
            Ok(None)
        }
    }

    /// Parse the version tables.
    ///
    /// `symbol_count` gives the number of dynamic symbols. Only the `DT_VERSYM` table needs
    /// it, so the function calls it only for that table.
    pub(crate) fn versions(
        &self,
        symbol_count: &dyn Fn() -> Result<Option<usize>>,
    ) -> Result<VersionTables> {
        Ok(VersionTables {
            versym: self.versym(symbol_count)?,
            definitions: self.version_definitions()?,
            requirements: self.version_requirements()?,
        })
    }

    /// Return the `Elf_Versym` values. The `DT_VERSYM` table has one value for each dynamic
    /// symbol.
    fn versym(
        &self,
        symbol_count: &dyn Fn() -> Result<Option<usize>>,
    ) -> Result<Option<VersymTable>> {
        let encoding = self.encoding();
        if let Some(section) = self.space.table_section(TableSection::Versym)? {
            return VersymTable::parse(section.data, encoding)
                .map(Some)
                .map_err(|error| error.in_structure("SHT_GNU_versym"));
        }
        let Some(address) = self.pointer(DynamicTag::VERSYM) else {
            return Ok(None);
        };
        let Some(count) = symbol_count()? else {
            return Ok(None);
        };
        // A table in memory has fewer than `u64::MAX / 2` entries. `bytes` rejects a size
        // that the segment does not hold.
        let size = u64::try_from(count).unwrap_or(u64::MAX).saturating_mul(2);
        let bytes = self.bytes(address, size, "DT_VERSYM")?;
        // `size` is a multiple of 2, so the parse cannot fail.
        VersymTable::parse(bytes, encoding).map(Some)
    }

    /// Return the version definitions.
    fn version_definitions(&self) -> Result<Option<VersionDefinitionTable>> {
        let encoding = self.encoding();
        if let Some(section) = self.space.table_section(TableSection::Verdef)? {
            let count = (section.info != 0).then_some(u64::from(section.info));
            return VersionDefinitionTable::parse(section.data, encoding, count)
                .map(Some)
                .map_err(|error| error.in_structure("SHT_GNU_verdef"));
        }
        let Some(address) = self.pointer(DynamicTag::VERDEF) else {
            return Ok(None);
        };
        let bytes = self.slice(address, "DT_VERDEF")?;
        VersionDefinitionTable::parse(bytes, encoding, self.value(DynamicTag::VERDEFNUM))
            .map(Some)
            .map_err(|error| error.in_structure("DT_VERDEF").at_address(address))
    }

    /// Return the version requirements.
    fn version_requirements(&self) -> Result<Option<VersionRequirementTable>> {
        let encoding = self.encoding();
        if let Some(section) = self.space.table_section(TableSection::Verneed)? {
            let count = (section.info != 0).then_some(u64::from(section.info));
            return VersionRequirementTable::parse(section.data, encoding, count)
                .map(Some)
                .map_err(|error| error.in_structure("SHT_GNU_verneed"));
        }
        let Some(address) = self.pointer(DynamicTag::VERNEED) else {
            return Ok(None);
        };
        let bytes = self.slice(address, "DT_VERNEED")?;
        VersionRequirementTable::parse(bytes, encoding, self.value(DynamicTag::VERNEEDNUM))
            .map(Some)
            .map_err(|error| error.in_structure("DT_VERNEED").at_address(address))
    }

    /// Return the dynamic symbols after index 0 that `keep` accepts.
    pub(crate) fn symbol_list(
        &self,
        keep: impl Fn(&Symbol) -> bool,
    ) -> Result<Vec<NamedSymbol<'a>>> {
        let Some(symbols) = self.symbols()? else {
            return Ok(Vec::new());
        };
        let strings = self.strings()?;
        let versions = self.versions(&|| Ok(Some(symbols.len())))?;
        let indices = self.indices_for(&symbols)?;
        let map = versions.map();
        DynamicSymbols {
            strings,
            symbols: &symbols,
            indices: indices.as_ref(),
            versions: &versions,
            map: &map,
        }
        .list(keep)
    }

    /// Find the dynamic symbol with the name `name` (see [`SymbolSearch::find`]).
    pub(crate) fn lookup(&self, name: &str) -> Result<Option<NamedSymbol<'a>>> {
        let Some(symbols) = self.symbols()? else {
            return Ok(None);
        };
        let strings = self.strings()?;
        let gnu_hash = self.gnu_hash()?;
        let sysv_hash = match gnu_hash {
            Some(_) => None,
            None => self.sysv_hash()?,
        };
        let search = SymbolSearch {
            symbols: &symbols,
            strings,
            gnu_hash: gnu_hash.as_ref(),
            sysv_hash: sysv_hash.as_ref(),
            sorted: None,
        };
        let Some((index, symbol)) = search.find(name) else {
            return Ok(None);
        };
        let versions = self.versions(&|| Ok(Some(symbols.len())))?;
        let indices = if symbol.shndx == SHN_XINDEX {
            self.symbol_indices(symbols.len())?
        } else {
            None
        };
        let map = versions.map();
        DynamicSymbols {
            strings,
            symbols: &symbols,
            indices: indices.as_ref(),
            versions: &versions,
            map: &map,
        }
        .describe(index, symbol)
        .map(Some)
    }
}
