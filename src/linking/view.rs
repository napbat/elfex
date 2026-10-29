//! The reusable view of the dynamic linking tables: [`LinkingView`].

use super::{DynamicRelocations, Linker, VersionTables};
use crate::Result;
use crate::dynamic::{DynamicTable, DynamicTag};
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::prelude::*;
use crate::strtab::StringTable;
use crate::symbol::{NamedSymbol, SymbolTable};
use crate::version::VersionMap;

/// A view of the dynamic linking tables of an [`ElfFile`](crate::ElfFile) or an
/// [`ElfImage`](crate::ElfImage) that parses each table only once.
///
/// [`ElfFile::linking`](crate::ElfFile::linking) and
/// [`ElfImage::linking`](crate::ElfImage::linking) return this type. The linking accessors
/// of `ElfFile` and `ElfImage` (for example `exports` and `lookup_dynamic_symbol`) make a new
/// view for each call, so they parse the tables again each time. Use one view to call more
/// than one accessor, or to look up many symbols.
///
/// The view parses the dynamic table when you make it. It parses each other table at the
/// first call that needs it, and keeps the table. If a table does not parse, the call returns
/// the error, and the next call parses the table again. Each method gives the same result as
/// the accessor of the same function.
///
/// The view is not `Sync`, because it keeps the tables in `OnceCell` values.
///
/// # Examples
///
/// ```
/// use elfex::{ElfFile, Result};
///
/// /// Return the address of each name, or `None` if the file does not define the name.
/// fn addresses(file: &ElfFile, names: &[&str]) -> Result<Vec<Option<u64>>> {
///     let view = file.linking()?;
///     names
///         .iter()
///         .map(|name| Ok(view.lookup(name)?.map(|symbol| symbol.symbol.value)))
///         .collect()
/// }
///
/// let file = elfex::ElfBuilder::new(elfex::Encoding::ELF64_LE).build();
/// assert_eq!(addresses(&file, &["main", "exit"])?, [None, None]);
/// # Ok::<(), elfex::Error>(())
/// ```
pub struct LinkingView<'a> {
    /// The reader with the parsed tables.
    linker: Linker<'a>,
}

impl<'a> LinkingView<'a> {
    /// Make a view of `linker`.
    pub(crate) const fn new(linker: Linker<'a>) -> Self {
        Self { linker }
    }

    /// Return the dynamic table, or `None` if there is no dynamic table.
    #[must_use]
    pub fn dynamic(&self) -> Option<&DynamicTable> {
        self.linker.dynamic()
    }

    /// Return the dynamic string table.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_strings` of `ElfFile` and
    /// `ElfImage`.
    pub fn string_table(&self) -> Result<Option<&StringTable>> {
        self.linker.strings()
    }

    /// Return the dynamic symbol table.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_symbols` of `ElfFile` and
    /// `ElfImage`.
    pub fn symbol_table(&self) -> Result<Option<&SymbolTable>> {
        self.linker.symbols()
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

    /// Return the relocation tables that the dynamic table names.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_relocations` of `ElfFile` and
    /// `ElfImage`.
    pub fn relocations(&self) -> Result<&DynamicRelocations> {
        self.linker.relocations()
    }

    /// Return the System V hash table at `DT_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the hash table does not parse.
    pub fn sysv_hash_table(&self) -> Result<Option<&SysvHashTable>> {
        self.linker.sysv_hash()
    }

    /// Return the GNU hash table at `DT_GNU_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the hash table does not parse.
    pub fn gnu_hash_table(&self) -> Result<Option<&GnuHashTable>> {
        self.linker.gnu_hash()
    }

    /// Return the symbol version tables.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `version_tables` of `ElfFile` and
    /// `ElfImage`.
    pub fn version_tables(&self) -> Result<&VersionTables> {
        self.linker.versions().map(|(tables, _)| tables)
    }

    /// Return the map from the version indexes to the version names of
    /// [`Self::version_tables`].
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::version_tables`].
    pub fn version_map(&self) -> Result<&VersionMap> {
        self.linker.versions().map(|(_, map)| map)
    }

    /// Return all dynamic symbols except the null symbol, with their names, sections and
    /// versions.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as `dynamic_symbol_list` of `ElfFile` and
    /// `ElfImage`.
    pub fn symbols(&self) -> Result<Vec<NamedSymbol>> {
        self.linker.symbol_list()
    }

    /// Return the exported dynamic symbols: the defined symbols with the binding
    /// `STB_GLOBAL`, `STB_WEAK` or `STB_GNU_UNIQUE` and a visibility other than `STV_HIDDEN`
    /// and `STV_INTERNAL`.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::symbols`].
    pub fn exports(&self) -> Result<Vec<NamedSymbol>> {
        self.linker.exports()
    }

    /// Return the imported dynamic symbols: the symbols with `st_shndx` `SHN_UNDEF`, except
    /// the null symbol.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::symbols`].
    pub fn imports(&self) -> Result<Vec<NamedSymbol>> {
        self.linker.imports()
    }

    /// Find the dynamic symbol with the name `name`.
    ///
    /// The search uses the GNU hash table, or else the System V hash table. Without a hash
    /// table, the view sorts the symbol names at the first lookup, and then does a binary
    /// search. If more than one symbol has the name, the result is the first one.
    ///
    /// # Errors
    ///
    /// Return an error if a hash table does not parse, or for the same conditions as
    /// [`Self::symbols`].
    pub fn lookup(&self, name: &str) -> Result<Option<NamedSymbol>> {
        self.linker.lookup(name)
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

    /// Return the dynamic string table and drop the view.
    pub(crate) fn into_string_table(self) -> Result<Option<StringTable>> {
        self.linker.into_strings()
    }

    /// Return the dynamic symbol table and drop the view.
    pub(crate) fn into_symbol_table(self) -> Result<Option<SymbolTable>> {
        self.linker.into_symbols()
    }

    /// Return the relocation tables and drop the view.
    pub(crate) fn into_relocations(self) -> Result<DynamicRelocations> {
        self.linker.into_relocations()
    }

    /// Return the System V hash table and drop the view.
    pub(crate) fn into_sysv_hash_table(self) -> Result<Option<SysvHashTable>> {
        self.linker.into_sysv_hash()
    }

    /// Return the GNU hash table and drop the view.
    pub(crate) fn into_gnu_hash_table(self) -> Result<Option<GnuHashTable>> {
        self.linker.into_gnu_hash()
    }

    /// Return the symbol version tables and drop the view.
    pub(crate) fn into_version_tables(self) -> Result<VersionTables> {
        self.linker.into_versions()
    }
}

impl core::fmt::Debug for LinkingView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinkingView")
            .field("dynamic", &self.linker.dynamic())
            .finish_non_exhaustive()
    }
}
