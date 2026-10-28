//! Read the dynamic symbols, their names and their versions.

use super::{AddressSpace, Linker, TableSection, VersionTables};
use crate::dynamic::DynamicTag;
use crate::header::Machine;
use crate::prelude::*;
use crate::section::SHN_XINDEX;
use crate::strtab::StringTable;
use crate::symbol::{
    NamedSymbol, Symbol, SymbolBinding, SymbolNames, SymbolSectionIndexTable, SymbolTable,
    SymbolVisibility,
};
use crate::version::{VersionDefinitionTable, VersionRequirementTable, VersymTable};
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

impl<S: AddressSpace> Linker<'_, S> {
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
    fn symbol_indices(&self, count: usize) -> Result<Option<SymbolSectionIndexTable>> {
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

    /// Return the extended section indices of `symbols`, if a symbol needs them.
    fn indices_for(&self, symbols: &SymbolTable) -> Result<Option<SymbolSectionIndexTable>> {
        if symbols.iter().any(|symbol| symbol.shndx == SHN_XINDEX) {
            self.symbol_indices(symbols.len())
        } else {
            Ok(None)
        }
    }

    /// Return the version tables. `symbol_count` is the number of dynamic symbols, if the
    /// caller knows it. The `DT_VERSYM` table has one value for each dynamic symbol.
    pub(crate) fn versions(&self, symbol_count: Option<usize>) -> Result<VersionTables> {
        Ok(VersionTables {
            versym: self.versym(symbol_count)?,
            definitions: self.version_definitions()?,
            requirements: self.version_requirements()?,
        })
    }

    /// Return the `Elf_Versym` values.
    fn versym(&self, symbol_count: Option<usize>) -> Result<Option<VersymTable>> {
        let encoding = self.encoding();
        if let Some(section) = self.space.table_section(TableSection::Versym)? {
            return VersymTable::parse(section.data, encoding)
                .map(Some)
                .map_err(|error| error.in_structure("SHT_GNU_versym"));
        }
        let Some(address) = self.pointer(DynamicTag::VERSYM) else {
            return Ok(None);
        };
        let count = match symbol_count {
            Some(count) => count,
            None => match self.symbols()? {
                Some(symbols) => symbols.len(),
                None => return Ok(None),
            },
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

    /// Return all dynamic symbols except the null symbol at index 0.
    pub(crate) fn symbol_list(&self) -> Result<Vec<NamedSymbol>> {
        let Some(symbols) = self.symbols()? else {
            return Ok(Vec::new());
        };
        let strings = self.strings()?;
        let versions = self.versions(Some(symbols.len()))?;
        let map = versions.map();
        let indices = self.indices_for(&symbols)?;
        let names = SymbolNames {
            strings: strings.as_ref(),
            structure: "DT_STRTAB",
            indices: indices.as_ref(),
            versym: versions.versym.as_ref(),
            map: Some(&map),
        };
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
    /// System V hash table, else with a linear search.
    pub(crate) fn lookup(&self, name: &str) -> Result<Option<NamedSymbol>> {
        let Some(symbols) = self.symbols()? else {
            return Ok(None);
        };
        let strings = self.strings()?;
        let name = name.as_bytes();
        let symbol_name = |index: u32| name_bytes(&symbols, strings.as_ref(), index);
        let found = if let Some(table) = self.gnu_hash()? {
            table.lookup(name, symbol_name)
        } else if let Some(table) = self.sysv_hash()? {
            table.lookup(name, symbol_name)
        } else {
            (1..symbols.len())
                .filter_map(|index| u32::try_from(index).ok())
                .find(|index| symbol_name(*index) == Some(name))
        };
        let Some((index, symbol)) = found.and_then(|index| {
            let index = usize::try_from(index).ok()?;
            Some((index, *symbols.get(index)?))
        }) else {
            return Ok(None);
        };
        let versions = self.versions(Some(symbols.len()))?;
        let map = versions.map();
        let indices = if symbol.shndx == SHN_XINDEX {
            self.symbol_indices(symbols.len())?
        } else {
            None
        };
        let names = SymbolNames {
            strings: strings.as_ref(),
            structure: "DT_STRTAB",
            indices: indices.as_ref(),
            versym: versions.versym.as_ref(),
            map: Some(&map),
        };
        names.describe(index, symbol).map(Some)
    }
}
