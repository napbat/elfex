//! Read the dynamic symbols, their names and their versions.

use super::{Linker, TableSection, VersionTables, cached};
use crate::dynamic::DynamicTag;
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
fn name_bytes<'t>(
    symbols: &'t SymbolTable,
    strings: Option<&'t StringTable>,
    index: u32,
) -> Option<&'t [u8]> {
    let symbol = symbols.get(usize::try_from(index).ok()?)?;
    strings?.get_bytes(symbol.name).ok()
}

/// Return `true` for a symbol that the object exports: a defined symbol with the binding
/// `STB_GLOBAL`, `STB_WEAK` or `STB_GNU_UNIQUE`, and a visibility other than `STV_HIDDEN`
/// and `STV_INTERNAL`.
fn is_export(symbol: &Symbol) -> bool {
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

impl Linker<'_> {
    /// Return the dynamic symbol table.
    ///
    /// `ElfFile` prefers the `SHT_DYNSYM` section. Else the table is at `DT_SYMTAB`. The
    /// count comes from the first source that is available:
    ///
    /// 1. `DT_MIPS_SYMTABNO`, for a MIPS object.
    /// 2. `nchain` of the `DT_HASH` table.
    /// 3. The symbol count of the `DT_GNU_HASH` table, or a larger symbol index that a
    ///    dynamic relocation refers to.
    /// 4. The distance from `DT_SYMTAB` to `DT_STRTAB`, if the string table follows.
    pub(crate) fn symbols(&self) -> Result<Option<&SymbolTable>> {
        cached(&self.cache.symbols, || self.load_symbols()).map(Option::as_ref)
    }

    /// Return the dynamic symbol table and drop the other tables.
    pub(crate) fn into_symbols(self) -> Result<Option<SymbolTable>> {
        self.symbols()?;
        Ok(self.cache.symbols.into_inner().flatten())
    }

    /// Parse the dynamic symbol table (see [`Self::symbols`]).
    fn load_symbols(&self) -> Result<Option<SymbolTable>> {
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
            let referenced = self.relocations().ok().and_then(|relocations| {
                relocations
                    .iter()
                    .map(|relocation| u64::from(relocation.symbol) + 1)
                    .max()
            });
            return Ok(Some(
                referenced.map_or(hashed, |referenced| hashed.max(referenced)),
            ));
        }
        Ok(self
            .pointer(DynamicTag::STRTAB)
            .filter(|strtab| *strtab > symtab)
            .map(|strtab| (strtab - symtab) / entsize))
    }

    /// Return the extended section indices of the dynamic symbols, for a table with `count`
    /// symbols.
    ///
    /// `ElfFile` prefers the `SHT_SYMTAB_SHNDX` section that links to the `SHT_DYNSYM`
    /// section. Else the table is at `DT_SYMTAB_SHNDX`, with one entry for each symbol.
    fn symbol_indices(&self, count: usize) -> Result<Option<&SymbolSectionIndexTable>> {
        cached(&self.cache.indices, || {
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
        })
        .map(Option::as_ref)
    }

    /// Return the extended section indices of `symbols`, if a symbol needs them.
    fn indices_for(&self, symbols: &SymbolTable) -> Result<Option<&SymbolSectionIndexTable>> {
        if symbols.iter().any(|symbol| symbol.shndx == SHN_XINDEX) {
            self.symbol_indices(symbols.len())
        } else {
            Ok(None)
        }
    }

    /// Return the version tables and the map from the version indexes to the version names.
    pub(crate) fn versions(&self) -> Result<&(VersionTables, VersionMap)> {
        cached(&self.cache.versions, || {
            let tables = VersionTables {
                versym: self.versym()?,
                definitions: self.version_definitions()?,
                requirements: self.version_requirements()?,
            };
            let map = tables.map();
            Ok((tables, map))
        })
    }

    /// Return the version tables and drop the other tables.
    pub(crate) fn into_versions(self) -> Result<VersionTables> {
        self.versions()?;
        Ok(self
            .cache
            .versions
            .into_inner()
            .map(|(tables, _)| tables)
            .unwrap_or_default())
    }

    /// Return the `Elf_Versym` values. The `DT_VERSYM` table has one value for each dynamic
    /// symbol.
    fn versym(&self) -> Result<Option<VersymTable>> {
        let encoding = self.encoding();
        if let Some(section) = self.space.table_section(TableSection::Versym)? {
            return VersymTable::parse(section.data, encoding)
                .map(Some)
                .map_err(|error| error.in_structure("SHT_GNU_versym"));
        }
        let Some(address) = self.pointer(DynamicTag::VERSYM) else {
            return Ok(None);
        };
        let Some(symbols) = self.symbols()? else {
            return Ok(None);
        };
        // A table in memory has fewer than `u64::MAX / 2` entries. `bytes` rejects a size
        // that the segment does not hold.
        let size = u64::try_from(symbols.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(2);
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

    /// Return the tables that describe a dynamic symbol. `indices` are the extended section
    /// indices, if the caller needs them.
    fn names<'t>(
        &'t self,
        strings: Option<&'t StringTable>,
        indices: Option<&'t SymbolSectionIndexTable>,
    ) -> Result<SymbolNames<'t>> {
        let (versions, map) = self.versions()?;
        Ok(SymbolNames {
            strings,
            structure: "DT_STRTAB",
            indices,
            versym: versions.versym.as_ref(),
            map: Some(map),
        })
    }

    /// Return all dynamic symbols except the null symbol at index 0.
    pub(crate) fn symbol_list(&self) -> Result<Vec<NamedSymbol>> {
        let Some(symbols) = self.symbols()? else {
            return Ok(Vec::new());
        };
        let strings = self.strings()?;
        self.versions()?;
        let indices = self.indices_for(symbols)?;
        let names = self.names(strings, indices)?;
        symbols
            .iter()
            .enumerate()
            .skip(1)
            .map(|(index, symbol)| names.describe(index, *symbol))
            .collect()
    }

    /// Return the dynamic symbols that the object exports.
    pub(crate) fn exports(&self) -> Result<Vec<NamedSymbol>> {
        let mut list = self.symbol_list()?;
        list.retain(|symbol| is_export(&symbol.symbol));
        Ok(list)
    }

    /// Return the undefined dynamic symbols: the symbols that the object imports.
    pub(crate) fn imports(&self) -> Result<Vec<NamedSymbol>> {
        let mut list = self.symbol_list()?;
        list.retain(|symbol| symbol.symbol.is_undefined());
        Ok(list)
    }

    /// Find the dynamic symbol with the name `name`: with the GNU hash table, else with the
    /// System V hash table, else with a binary search of the names. If more than one symbol
    /// has the name, the binary search finds the first one.
    pub(crate) fn lookup(&self, name: &str) -> Result<Option<NamedSymbol>> {
        let Some(symbols) = self.symbols()? else {
            return Ok(None);
        };
        let strings = self.strings()?;
        let name = name.as_bytes();
        let symbol_name = |index: u32| name_bytes(symbols, strings, index);
        let found = if let Some(table) = self.gnu_hash()? {
            table.lookup(name, symbol_name)
        } else if let Some(table) = self.sysv_hash()? {
            table.lookup(name, symbol_name)
        } else {
            let sorted = self.sorted_names(symbols, strings);
            let first = sorted.partition_point(|index| symbol_name(*index) < Some(name));
            sorted
                .get(first)
                .copied()
                .filter(|index| symbol_name(*index) == Some(name))
        };
        let Some((index, symbol)) = found.and_then(|index| {
            let index = usize::try_from(index).ok()?;
            Some((index, *symbols.get(index)?))
        }) else {
            return Ok(None);
        };
        self.versions()?;
        let indices = if symbol.shndx == SHN_XINDEX {
            self.symbol_indices(symbols.len())?
        } else {
            None
        };
        self.names(strings, indices)?
            .describe(index, symbol)
            .map(Some)
    }

    /// Return the indices of the dynamic symbols with a name, except index 0, sorted by name
    /// and then by index.
    fn sorted_names(&self, symbols: &SymbolTable, strings: Option<&StringTable>) -> &[u32] {
        self.cache.sorted_names.get_or_init(|| {
            let name = |index: &u32| name_bytes(symbols, strings, *index);
            let mut sorted: Vec<u32> = (1..symbols.len())
                .filter_map(|index| u32::try_from(index).ok())
                .filter(|index| name(index).is_some())
                .collect();
            // The sort is stable, so equal names stay in index order.
            sorted.sort_by(|a, b| name(a).cmp(&name(b)));
            sorted
        })
    }
}
