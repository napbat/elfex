//! The reusable view of the dynamic linking tables: [`LinkingView`].

use super::symbols::{DynamicSymbols, SymbolSearch, is_any, is_export, is_import, sorted_names};
use super::{DynamicRelocations, Linker, VersionTables};
use crate::dynamic::{DynamicTable, DynamicTag};
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::prelude::*;
use crate::section::SHN_XINDEX;
use crate::strtab::StringTable;
use crate::symbol::{NamedSymbol, Symbol, SymbolSectionIndexTable, SymbolTable};
use crate::version::VersionMap;
use crate::{Error, Result};

/// A view of the dynamic linking tables of an [`ElfFile`](crate::ElfFile) or an
/// [`ElfImage`](crate::ElfImage) that parses the symbol tables only once.
///
/// [`ElfFile::linking`](crate::ElfFile::linking) and
/// [`ElfImage::linking`](crate::ElfImage::linking) return this type. The linking accessors
/// of `ElfFile` and `ElfImage` (for example `exports` and `lookup_dynamic_symbol`) parse the
/// tables again on each call. Use one view to call more than one accessor, or to look up many
/// symbols.
///
/// When you make the view, it parses these tables and keeps them:
///
/// - The dynamic table.
/// - The dynamic symbol table and its extended section indices.
/// - The symbol version tables.
/// - The GNU and System V hash tables. Without a hash table, the view sorts the symbol names
///   for the lookups.
///
/// If a table does not parse, each call that needs the table returns the error. The other
/// tables (for example the relocations) are parsed at each call. The string tables are not
/// parsed, so they cost nothing. Each method gives the same result as the accessor of the
/// same function.
///
/// The view is `Send` and `Sync`, so threads can share it.
///
/// # Examples
///
/// ```
/// use elfex::{ElfFile, Result};
///
/// /// Return the address of each name, or `None` if the file does not define the name.
/// fn addresses(file: &ElfFile<&[u8]>, names: &[&str]) -> Result<Vec<Option<u64>>> {
///     let view = file.linking()?;
///     names
///         .iter()
///         .map(|name| Ok(view.lookup(name)?.map(|symbol| symbol.symbol.value)))
///         .collect()
/// }
///
/// let bytes = elfex::ElfBuilder::new(elfex::Encoding::ELF64_LE).build().build();
/// let file = ElfFile::parse(&bytes)?;
/// assert_eq!(addresses(&file, &["main", "exit"])?, [None, None]);
/// # Ok::<(), elfex::Error>(())
/// ```
pub struct LinkingView<'a> {
    /// The reader of the tables.
    linker: Linker<'a>,
    /// The dynamic symbol table.
    symbols: Result<Option<SymbolTable>>,
    /// The extended section indices of the dynamic symbols, if a symbol needs them.
    indices: Result<Option<SymbolSectionIndexTable>>,
    /// The version tables and their map.
    versions: Result<(VersionTables, VersionMap)>,
    /// The System V hash table.
    sysv_hash: Result<Option<SysvHashTable>>,
    /// The GNU hash table.
    gnu_hash: Result<Option<GnuHashTable>>,
    /// The indices of the named dynamic symbols, sorted by name and then by index, for a
    /// lookup without a hash table. The list is empty if a hash table is present.
    sorted_names: Vec<u32>,
}

/// Return a copy of the value or the error in `result`.
fn shared<T>(result: &Result<T>) -> Result<&T> {
    result.as_ref().map_err(Error::duplicate)
}

impl<'a> LinkingView<'a> {
    /// Make a view of `linker` and parse the tables that it keeps.
    pub(crate) fn new(linker: Linker<'a>) -> Self {
        let symbols = linker.symbols();
        let symbol_count = || shared(&symbols).map(|table| table.as_ref().map(SymbolTable::len));
        let versions = linker.versions(&symbol_count).map(|tables| {
            let map = tables.map();
            (tables, map)
        });
        let indices = match &symbols {
            Ok(Some(table)) => linker.indices_for(table),
            _ => Ok(None),
        };
        let gnu_hash = linker.gnu_hash();
        let sysv_hash = linker.sysv_hash();
        let sorted_names = match (&symbols, &gnu_hash, &sysv_hash) {
            (Ok(Some(table)), Ok(None), Ok(None)) => {
                sorted_names(table, linker.strings().ok().flatten())
            }
            _ => Vec::new(),
        };
        Self {
            linker,
            symbols,
            indices,
            versions,
            sysv_hash,
            gnu_hash,
            sorted_names,
        }
    }

    /// Return the dynamic table, or `None` if there is no dynamic table.
    #[must_use]
    pub fn dynamic(&self) -> Option<&DynamicTable> {
        self.linker.dynamic()
    }

    /// Return the dynamic string table. The table borrows the bytes of the file or the image.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_strings` of `ElfFile` and
    /// `ElfImage`.
    pub fn string_table(&self) -> Result<Option<StringTable<'a>>> {
        self.linker.strings()
    }

    /// Return the dynamic symbol table.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_symbols` of `ElfFile` and
    /// `ElfImage`.
    pub fn symbol_table(&self) -> Result<Option<&SymbolTable>> {
        shared(&self.symbols).map(Option::as_ref)
    }

    /// Return the names of the needed libraries (`DT_NEEDED`), in table order, as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `needed_libraries` of `ElfFile` and
    /// `ElfImage`.
    pub fn needed_libraries(&self) -> Result<Vec<String>> {
        self.linker.needed_libraries()
    }

    /// Return the shared object name (`DT_SONAME`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn soname(&self) -> Result<Option<String>> {
        self.linker.string_entry(DynamicTag::SONAME)
    }

    /// Return the deprecated library search path (`DT_RPATH`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn rpath(&self) -> Result<Option<String>> {
        self.linker.string_entry(DynamicTag::RPATH)
    }

    /// Return the library search path (`DT_RUNPATH`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn runpath(&self) -> Result<Option<String>> {
        self.linker.string_entry(DynamicTag::RUNPATH)
    }

    /// Parse the relocation tables that the dynamic table names.
    ///
    /// The view does not keep the relocations, so each call parses them again.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_relocations` of `ElfFile` and
    /// `ElfImage`.
    pub fn relocations(&self) -> Result<DynamicRelocations> {
        self.linker.relocations()
    }

    /// Return the System V hash table at `DT_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the hash table does not parse.
    pub fn sysv_hash_table(&self) -> Result<Option<&SysvHashTable>> {
        shared(&self.sysv_hash).map(Option::as_ref)
    }

    /// Return the GNU hash table at `DT_GNU_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the hash table does not parse.
    pub fn gnu_hash_table(&self) -> Result<Option<&GnuHashTable>> {
        shared(&self.gnu_hash).map(Option::as_ref)
    }

    /// Return the symbol version tables.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `version_tables` of `ElfFile` and
    /// `ElfImage`.
    pub fn version_tables(&self) -> Result<&VersionTables> {
        shared(&self.versions).map(|(tables, _)| tables)
    }

    /// Return the map from the version indexes to the version names of
    /// [`Self::version_tables`].
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::version_tables`].
    pub fn version_map(&self) -> Result<&VersionMap> {
        shared(&self.versions).map(|(_, map)| map)
    }

    /// Return all dynamic symbols except the null symbol, with their names, sections and
    /// versions. The names borrow the bytes of the file or the image.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_symbol_list` of `ElfFile` and
    /// `ElfImage`.
    pub fn symbols(&self) -> Result<Vec<NamedSymbol<'a>>> {
        self.symbol_list(is_any)
    }

    /// Return the exported dynamic symbols: the defined symbols with the binding
    /// `STB_GLOBAL`, `STB_WEAK` or `STB_GNU_UNIQUE` and a visibility other than `STV_HIDDEN`
    /// and `STV_INTERNAL`.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::symbols`].
    pub fn exports(&self) -> Result<Vec<NamedSymbol<'a>>> {
        self.symbol_list(is_export)
    }

    /// Return the imported dynamic symbols: the symbols with `st_shndx` `SHN_UNDEF`, except
    /// the null symbol.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::symbols`].
    pub fn imports(&self) -> Result<Vec<NamedSymbol<'a>>> {
        self.symbol_list(is_import)
    }

    /// Find the dynamic symbol with the name `name`.
    ///
    /// The search uses the GNU hash table, or else the System V hash table. Without a hash
    /// table, it does a binary search of the names that the view sorted. If more than one
    /// symbol has the name, the result is the first one.
    ///
    /// # Errors
    ///
    /// Return an error if a hash table does not parse, or for the same conditions as
    /// [`Self::symbols`].
    pub fn lookup(&self, name: &str) -> Result<Option<NamedSymbol<'a>>> {
        let Some(symbols) = shared(&self.symbols)? else {
            return Ok(None);
        };
        let strings = self.linker.strings()?;
        let gnu_hash = shared(&self.gnu_hash)?.as_ref();
        let sysv_hash = match gnu_hash {
            Some(_) => None,
            None => shared(&self.sysv_hash)?.as_ref(),
        };
        let search = SymbolSearch {
            symbols,
            strings,
            gnu_hash,
            sysv_hash,
            sorted: Some(&self.sorted_names),
        };
        let Some((index, symbol)) = search.find(name) else {
            return Ok(None);
        };
        let (versions, map) = shared(&self.versions)?;
        let indices = if symbol.shndx == SHN_XINDEX {
            shared(&self.indices)?.as_ref()
        } else {
            None
        };
        DynamicSymbols {
            strings,
            symbols,
            indices,
            versions,
            map,
        }
        .describe(index, symbol)
        .map(Some)
    }

    /// Return the words of the `DT_INIT_ARRAY` array, as they are in the source.
    ///
    /// # Errors
    ///
    /// Return an error if `DT_INIT_ARRAYSZ` is missing or is not a multiple of the word size,
    /// or if the array is outside the segments.
    pub fn init_array(&self) -> Result<Vec<u64>> {
        self.linker
            .array(DynamicTag::INIT_ARRAY, DynamicTag::INIT_ARRAYSZ)
    }

    /// Return the words of the `DT_FINI_ARRAY` array, as they are in the source.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::init_array`], for
    /// `DT_FINI_ARRAYSZ`.
    pub fn fini_array(&self) -> Result<Vec<u64>> {
        self.linker
            .array(DynamicTag::FINI_ARRAY, DynamicTag::FINI_ARRAYSZ)
    }

    /// Return the words of the `DT_PREINIT_ARRAY` array, as they are in the source.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::init_array`], for
    /// `DT_PREINIT_ARRAYSZ`.
    pub fn preinit_array(&self) -> Result<Vec<u64>> {
        self.linker
            .array(DynamicTag::PREINIT_ARRAY, DynamicTag::PREINIT_ARRAYSZ)
    }

    /// Return the dynamic symbols after index 0 that `keep` accepts.
    fn symbol_list(&self, keep: fn(&Symbol) -> bool) -> Result<Vec<NamedSymbol<'a>>> {
        let Some(symbols) = shared(&self.symbols)? else {
            return Ok(Vec::new());
        };
        let strings = self.linker.strings()?;
        let (versions, map) = shared(&self.versions)?;
        let indices = shared(&self.indices)?.as_ref();
        DynamicSymbols {
            strings,
            symbols,
            indices,
            versions,
            map,
        }
        .list(keep)
    }
}

impl core::fmt::Debug for LinkingView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinkingView")
            .field("dynamic", &self.linker.dynamic())
            .finish_non_exhaustive()
    }
}
