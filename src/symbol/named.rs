//! A symbol with its name, its section and its version: [`NamedSymbol`].

use super::{Symbol, SymbolSectionIndexTable};
use crate::prelude::*;
use crate::section::SHN_UNDEF;
use crate::strtab::StringTable;
use crate::version::{VersionMap, VersymTable, is_hidden};
use crate::{Error, Result};

/// A symbol of a static or a dynamic symbol table, with its name, its section and its
/// version.
///
/// These accessors return this type:
///
/// - `ElfFile::symbol_list` and `ElfFile::lookup_symbol` for the static symbol table
///   (`SHT_SYMTAB`).
/// - `dynamic_symbol_list`, `exports`, `imports` and `lookup_dynamic_symbol` of `ElfFile` and
///   `ElfImage` for the dynamic symbol table.
///
/// The strings borrow the string table of the file or the image for the lifetime `'a`. A
/// string is a copy only if it is not valid UTF-8. Use [`Self::into_owned`] to keep a symbol
/// after the file or the image goes out of scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct NamedSymbol<'a> {
    /// The index of the symbol in its symbol table.
    pub index: u32,
    /// The symbol name from the linked string table, as lossy UTF-8. The name is empty if
    /// `st_name` is 0.
    pub name: Cow<'a, str>,
    /// The symbol table entry (`Elf32_Sym` or `Elf64_Sym`).
    pub symbol: Symbol,
    /// The section index of the symbol.
    ///
    /// - If `st_shndx` is `SHN_XINDEX`, the index comes from the extended section index
    ///   table: the `SHT_SYMTAB_SHNDX` section of the symbol table, or `DT_SYMTAB_SHNDX`.
    /// - A reserved value (for example `SHN_ABS` or `SHN_COMMON`) stays as it is. Compare
    ///   the value with these values before you use it as a section index.
    /// - The value is `None` for `SHN_UNDEF`. It is also `None` for `SHN_XINDEX` if no
    ///   extended section index table gives the index.
    pub section_index: Option<u32>,
    /// The version name from the `Elf_Versym` value and the version definitions or
    /// requirements, as lossy UTF-8. `None` if the symbol has no version or the base version
    /// (`VER_NDX_LOCAL` or `VER_NDX_GLOBAL`). Static symbols have no version.
    pub version: Option<Cow<'a, str>>,
    /// The file name (`vn_file`) of the version requirement, as lossy UTF-8: the library that
    /// defines the symbol. `None` for a version that the file itself defines.
    pub version_file: Option<Cow<'a, str>>,
    /// `true` if the `Elf_Versym` value has the `VERSYM_HIDDEN` bit: the version is not the
    /// default version of the symbol.
    pub hidden: bool,
}

impl NamedSymbol<'_> {
    /// Return a symbol that owns copies of its strings.
    #[must_use]
    pub fn into_owned(self) -> NamedSymbol<'static> {
        NamedSymbol {
            index: self.index,
            name: Cow::Owned(self.name.into_owned()),
            symbol: self.symbol,
            section_index: self.section_index,
            version: self.version.map(|version| Cow::Owned(version.into_owned())),
            version_file: self.version_file.map(|file| Cow::Owned(file.into_owned())),
            hidden: self.hidden,
        }
    }
}

/// Read the string at `offset` in `strings`, as lossy UTF-8.
///
/// `structure` names the string table in the error context.
pub(crate) fn table_string<'a>(
    strings: Option<StringTable<'a>>,
    offset: u32,
    structure: &str,
) -> Result<Cow<'a, str>> {
    let strings = strings.ok_or_else(|| {
        Error::invalid_table(format!("the string table {structure} is missing"))
            .in_structure(structure)
    })?;
    strings
        .get_lossy(offset)
        .map_err(|error| error.in_structure(structure))
}

/// The tables that give the name, the section and the version of a symbol.
pub(crate) struct SymbolNames<'a, 't> {
    /// The string table that `st_name` refers to.
    pub(crate) strings: Option<StringTable<'a>>,
    /// The name of the string table for the error context, for example `DT_STRTAB`.
    pub(crate) structure: &'static str,
    /// The extended section indices of the symbol table.
    pub(crate) indices: Option<&'t SymbolSectionIndexTable>,
    /// The `Elf_Versym` values, for a dynamic symbol table.
    pub(crate) versym: Option<&'t VersymTable>,
    /// The map from the version indexes to the version names, for a dynamic symbol table.
    pub(crate) map: Option<&'t VersionMap>,
}

impl<'a> SymbolNames<'a, '_> {
    /// Make the [`NamedSymbol`] of the symbol at `index`.
    pub(crate) fn describe(&self, index: usize, symbol: Symbol) -> Result<NamedSymbol<'a>> {
        let index_u32 = u32::try_from(index).map_err(|_| {
            Error::invalid_table(format!("the symbol index {index} does not fit in 32 bits"))
        })?;
        let name = if symbol.name == 0 {
            Cow::Borrowed("")
        } else {
            table_string(self.strings, symbol.name, self.structure)?
        };
        let raw = self.versym.and_then(|versym| versym.get(index));
        let version = raw
            .zip(self.map)
            .and_then(|(raw, map)| map.symbol_version(raw));
        let (version, version_file) = match version {
            Some(version) => (
                Some(table_string(self.strings, version.name, self.structure)?),
                version
                    .file
                    .map(|file| table_string(self.strings, file, self.structure))
                    .transpose()?,
            ),
            None => (None, None),
        };
        let section_index = if symbol.shndx == SHN_UNDEF {
            None
        } else {
            symbol
                .section_index(index, self.indices)
                .filter(|section| *section != u32::from(SHN_UNDEF))
        };
        Ok(NamedSymbol {
            index: index_u32,
            name,
            symbol,
            section_index,
            version,
            version_file,
            hidden: raw.is_some_and(is_hidden),
        })
    }

    /// Make the [`NamedSymbol`] of each symbol of `symbols` after index 0 that `keep`
    /// accepts, in table order.
    pub(crate) fn describe_all(
        &self,
        symbols: &[Symbol],
        keep: impl Fn(&Symbol) -> bool,
    ) -> Result<Vec<NamedSymbol<'a>>> {
        let kept = || {
            symbols
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(_, symbol)| keep(symbol))
        };
        // Count the symbols first, so that the list does not grow and copy its items.
        let mut list = Vec::with_capacity(kept().count());
        for (index, symbol) in kept() {
            list.push(self.describe(index, *symbol)?);
        }
        Ok(list)
    }
}
