//! The dynamic linking accessors of an [`ElfFile`].
//!
//! The accessors prefer the sections (for example `.dynsym`, `.gnu.version` and the
//! `SHT_NOTE` sections). If a section is absent, they read the table through the dynamic
//! table, as `ElfImage` does.

use super::{ElfFile, FileSpace};
use crate::Result;
use crate::dynamic::{DynamicTable, DynamicTag};
use crate::eh_frame::EhFrameHdr;
use crate::endian::Encoding;
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::header::Machine;
use crate::liblist::LibraryListEntry;
use crate::linking::symbols::{is_any, is_export, is_import};
use crate::linking::{
    self, AddressSpace, DynamicRelocations, Linker, LinkingView, NoteSource, SectionTable,
    SegmentBytes, TableSection, VersionTables,
};
use crate::note::{AuxvEntry, FileMapping, Note};
use crate::prelude::*;
use crate::program::SegmentType;
use crate::section::SectionType;
use crate::strtab::StringTable;
use crate::symbol::{NamedSymbol, SymbolTable};

impl<'a> AddressSpace<'a> for FileSpace<'a> {
    fn encoding(&self) -> Encoding {
        self.headers().encoding()
    }

    fn machine(&self) -> Machine {
        self.headers().machine()
    }

    fn slice_from_vaddr(&self, vaddr: u64) -> Result<&'a [u8]> {
        FileSpace::slice_from_vaddr(self, vaddr)
    }

    fn resolve_pointer(&self, value: u64) -> u64 {
        value
    }

    fn dynamic_bytes(&self) -> Result<Option<&'a [u8]>> {
        if let Some(index) = self.file_section_index(SectionType::DYNAMIC) {
            return self.section_data(index).map(Some);
        }
        Ok(AddressSpace::segments(self, SegmentType::DYNAMIC)?
            .into_iter()
            .next()
            .map(|segment| segment.data))
    }

    fn segments(&self, segment_type: SegmentType) -> Result<Vec<SegmentBytes<'a>>> {
        self.headers()
            .program_headers
            .iter()
            .enumerate()
            .filter(|(_, header)| header.segment_type == segment_type)
            .map(|(index, header)| {
                let data = self
                    .segment_data(index)
                    .map_err(|error| error.in_structure(format!("{segment_type}")))?;
                Ok(SegmentBytes {
                    header: *header,
                    data,
                })
            })
            .collect()
    }

    fn note_sources(&self) -> Result<Vec<NoteSource<'a>>> {
        let mut sources = Vec::new();
        for (index, header) in self.headers().section_headers.iter().enumerate() {
            if header.section_type == SectionType::NOTE && header.has_file_data() {
                sources.push(NoteSource {
                    data: self.section_data(index)?,
                    align: header.addralign,
                    address: header.addr,
                });
            }
        }
        if !sources.is_empty() {
            return Ok(sources);
        }
        Ok(AddressSpace::segments(self, SegmentType::NOTE)?
            .into_iter()
            .map(|segment| NoteSource {
                data: segment.data,
                align: segment.header.align,
                address: segment.header.vaddr,
            })
            .collect())
    }

    fn table_section(&self, table: TableSection) -> Result<Option<SectionTable<'a>>> {
        let index = match table {
            TableSection::DynamicStrings => self.dynamic_strings_index(),
            TableSection::DynamicSymbols => self.file_section_index(SectionType::DYNSYM),
            TableSection::Versym => self.file_section_index(SectionType::GNU_VERSYM),
            TableSection::Verdef => self.file_section_index(SectionType::GNU_VERDEF),
            TableSection::Verneed => self.file_section_index(SectionType::GNU_VERNEED),
            TableSection::DynamicSymbolIndices => self
                .file_section_index(SectionType::DYNSYM)
                .and_then(|dynsym| self.symbol_index_section(dynsym)),
        };
        let Some(index) = index else {
            return Ok(None);
        };
        let data = self.section_data(index)?;
        // `section_data` checks the index.
        let Some(header) = self.headers().section_headers.get(index) else {
            return Ok(None);
        };
        Ok(Some(SectionTable {
            data,
            entsize: header.entsize,
            info: header.info,
        }))
    }
}

impl<'a> FileSpace<'a> {
    /// Return the index of the first section of `section_type` with file bytes.
    pub(crate) fn file_section_index(&self, section_type: SectionType) -> Option<usize> {
        self.headers()
            .section_headers
            .iter()
            .position(|header| header.section_type == section_type && header.has_file_data())
    }

    /// Return the index of the `SHT_STRTAB` section that `sh_link` of the `SHT_DYNAMIC`
    /// section gives, if it has file bytes.
    fn dynamic_strings_index(&self) -> Option<usize> {
        let headers = &self.headers().section_headers;
        let dynamic = self.file_section_index(SectionType::DYNAMIC)?;
        let link = usize::try_from(headers.get(dynamic)?.link).ok()?;
        let strings = headers.get(link)?;
        (link != 0 && strings.section_type == SectionType::STRTAB && strings.has_file_data())
            .then_some(link)
    }

    /// Return the index of the `SHT_SYMTAB_SHNDX` section that links to the symbol table at
    /// `symtab`, if it has file bytes.
    pub(crate) fn symbol_index_section(&self, symtab: usize) -> Option<usize> {
        self.headers().section_headers.iter().position(|header| {
            header.section_type == SectionType::SYMTAB_SHNDX
                && header.has_file_data()
                && usize::try_from(header.link).is_ok_and(|link| link == symtab)
        })
    }

    /// Return the reader of the dynamic linking tables.
    fn linker(self) -> Result<Linker<'a>> {
        Linker::load(self)
    }
}

impl<D: AsRef<[u8]>> ElfFile<D> {
    /// Return the index of the first section of `section_type` with file bytes.
    pub(super) fn file_section_index(&self, section_type: SectionType) -> Option<usize> {
        self.space().file_section_index(section_type)
    }

    /// Return the reader of the dynamic linking tables.
    fn linker(&self) -> Result<Linker<'_>> {
        self.space().linker()
    }

    /// Return the dynamic table: the `SHT_DYNAMIC` section, or else the file bytes of the
    /// `PT_DYNAMIC` segment.
    ///
    /// Return `None` if the file has neither.
    ///
    /// # Errors
    ///
    /// Return an error if the bytes of the section or the segment are outside the file.
    pub fn dynamic(&self) -> Result<Option<DynamicTable>> {
        linking::dynamic_table(&self.space())
    }

    /// Return a view of the dynamic linking tables that parses the symbol tables only once.
    ///
    /// The linking accessors of `ElfFile` (for example [`Self::exports`] and
    /// [`Self::lookup_dynamic_symbol`]) parse the tables again on each call. Use the view to
    /// call more than one of them, or to look up many symbols. The view gives the same
    /// results.
    ///
    /// The view parses the dynamic symbol table, the version tables and the hash tables
    /// when you make it. It does not depend on the storage type of the file, and threads can
    /// share it.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::dynamic`].
    pub fn linking(&self) -> Result<LinkingView<'_>> {
        self.linker().map(LinkingView::new)
    }

    /// Return the dynamic string table: the `sh_link` section of the `SHT_DYNAMIC` section,
    /// or else the bytes at `DT_STRTAB` with the size `DT_STRSZ`. The table borrows the file
    /// bytes.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table does not parse, or if the string table is outside
    /// the file bytes of the `PT_LOAD` segments.
    pub fn dynamic_strings(&self) -> Result<Option<StringTable<'_>>> {
        self.linker()?.strings()
    }

    /// Return the dynamic symbol table: the `SHT_DYNSYM` section, or else the table at
    /// `DT_SYMTAB`.
    ///
    /// Without a section, the symbol count comes from `DT_MIPS_SYMTABNO` (MIPS only), else
    /// from `DT_HASH`, else from `DT_GNU_HASH` and the dynamic relocations, else from the
    /// distance between `DT_SYMTAB` and `DT_STRTAB`. Return `None` if no source gives the
    /// count.
    ///
    /// # Errors
    ///
    /// Return an error if a table does not parse, if `DT_SYMENT` is smaller than the symbol
    /// size, or if the table is outside the file bytes of the `PT_LOAD` segments.
    pub fn dynamic_symbols(&self) -> Result<Option<SymbolTable>> {
        self.linker()?.symbols()
    }

    /// Return the names of the needed libraries (`DT_NEEDED`), in table order, as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table or the dynamic string table does not parse, or if
    /// a name offset is outside the string table.
    pub fn needed_libraries(&self) -> Result<Vec<String>> {
        self.linker()?.needed_libraries()
    }

    /// Return the shared object name (`DT_SONAME`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn soname(&self) -> Result<Option<String>> {
        self.linker()?.string_entry(DynamicTag::SONAME)
    }

    /// Return the deprecated library search path (`DT_RPATH`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn rpath(&self) -> Result<Option<String>> {
        self.linker()?.string_entry(DynamicTag::RPATH)
    }

    /// Return the library search path (`DT_RUNPATH`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn runpath(&self) -> Result<Option<String>> {
        self.linker()?.string_entry(DynamicTag::RUNPATH)
    }

    /// Return the path of the program interpreter from the `PT_INTERP` segment.
    ///
    /// The path is the file bytes of the segment up to the first null byte. Return `None` if
    /// the file has no `PT_INTERP` segment.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::OffsetOutOfBounds`](crate::ErrorKind::OffsetOutOfBounds) if the
    ///   segment is outside the file.
    /// - Return [`ErrorKind::InvalidUtf8`](crate::ErrorKind::InvalidUtf8) if the path is not
    ///   UTF-8.
    pub fn interpreter(&self) -> Result<Option<String>> {
        AddressSpace::segments(&self.space(), SegmentType::INTERP)?
            .first()
            .map(|segment| linking::interpreter_path(segment.data))
            .transpose()
    }

    /// Return the notes of all `SHT_NOTE` sections, or else of all `PT_NOTE` segments.
    ///
    /// # Errors
    ///
    /// Return an error if a note table is outside the file or does not parse.
    pub fn notes(&self) -> Result<Vec<Note>> {
        linking::notes(&self.space())
    }

    /// Return the descriptor of the first GNU `NT_GNU_BUILD_ID` note.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::notes`].
    pub fn build_id(&self) -> Result<Option<Vec<u8>>> {
        linking::build_id(&self.space())
    }

    /// Return the page size and the mapped files of the first `NT_FILE` note (owner `CORE`)
    /// of a core file.
    ///
    /// The notes come from the `SHT_NOTE` sections, or else from the `PT_NOTE` segments.
    /// Return `None` if the file has no such note.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::notes`], or if the descriptor
    /// does not parse (see [`parse_nt_file`](crate::note::parse_nt_file)).
    pub fn core_file_mappings(&self) -> Result<Option<(u64, Vec<FileMapping>)>> {
        linking::core_file_mappings(&self.space())
    }

    /// Return the auxiliary vector of the first `NT_AUXV` note (owner `CORE`) of a core
    /// file, without the `AT_NULL` entry.
    ///
    /// Return `None` if the file has no such note.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::notes`], or if the descriptor
    /// does not parse (see [`parse_auxv`](crate::note::parse_auxv)).
    pub fn auxv(&self) -> Result<Option<Vec<AuxvEntry>>> {
        linking::auxv(&self.space())
    }

    /// Return the relocation tables that the dynamic table names: `DT_RELA`, `DT_REL`,
    /// `DT_JMPREL`, `DT_RELR` (or `DT_ANDROID_RELR`), `DT_ANDROID_RELA` (or
    /// `DT_ANDROID_REL`) and `DT_CREL`.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table does not parse, if a size tag is missing, if
    /// `DT_PLTREL` is not `DT_REL` or `DT_RELA`, or if a table is outside the file bytes of
    /// the `PT_LOAD` segments or does not parse.
    pub fn dynamic_relocations(&self) -> Result<DynamicRelocations> {
        self.linker()?.relocations()
    }

    /// Return the System V hash table at `DT_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table or the hash table does not parse.
    pub fn sysv_hash_table(&self) -> Result<Option<SysvHashTable>> {
        self.linker()?.sysv_hash()
    }

    /// Return the GNU hash table at `DT_GNU_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table or the hash table does not parse.
    pub fn gnu_hash_table(&self) -> Result<Option<GnuHashTable>> {
        self.linker()?.gnu_hash()
    }

    /// Return the symbol version tables: the `SHT_GNU_versym`, `SHT_GNU_verdef` and
    /// `SHT_GNU_verneed` sections, or else the tables at `DT_VERSYM`, `DT_VERDEF` and
    /// `DT_VERNEED`.
    ///
    /// # Errors
    ///
    /// Return an error if a table does not parse or is outside the file.
    pub fn version_tables(&self) -> Result<VersionTables> {
        let linker = self.linker()?;
        linker.versions(&|| Ok(linker.symbols()?.map(|symbols| symbols.len())))
    }

    /// Return all dynamic symbols except the null symbol, with their names, sections and
    /// versions. The names borrow the file bytes.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic symbol table, the dynamic string table or a version
    /// table does not parse, or if a name offset is outside the string table.
    pub fn dynamic_symbol_list(&self) -> Result<Vec<NamedSymbol<'_>>> {
        self.linker()?.symbol_list(is_any)
    }

    /// Return the exported dynamic symbols: the defined symbols with the binding
    /// `STB_GLOBAL`, `STB_WEAK` or `STB_GNU_UNIQUE` and a visibility other than `STV_HIDDEN`
    /// and `STV_INTERNAL`.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::dynamic_symbol_list`].
    pub fn exports(&self) -> Result<Vec<NamedSymbol<'_>>> {
        self.linker()?.symbol_list(is_export)
    }

    /// Return the imported dynamic symbols: the symbols with `st_shndx` `SHN_UNDEF`, except
    /// the null symbol.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::dynamic_symbol_list`].
    pub fn imports(&self) -> Result<Vec<NamedSymbol<'_>>> {
        self.linker()?.symbol_list(is_import)
    }

    /// Find the dynamic symbol with the name `name`.
    ///
    /// The search uses the GNU hash table, or else the System V hash table, or else a search
    /// of the dynamic symbol table. Each call parses the tables again: use
    /// [`Self::linking`] to look up many names.
    ///
    /// # Errors
    ///
    /// Return an error if a hash table does not parse, or for the same conditions as
    /// [`Self::dynamic_symbol_list`].
    pub fn lookup_dynamic_symbol(&self, name: &str) -> Result<Option<NamedSymbol<'_>>> {
        self.linker()?.lookup(name)
    }

    /// Return the virtual addresses in the `DT_INIT_ARRAY` array, as they are in the file.
    ///
    /// # Errors
    ///
    /// Return an error if `DT_INIT_ARRAYSZ` is missing or is not a multiple of the word size,
    /// or if the array is outside the file bytes of the `PT_LOAD` segments.
    pub fn init_array(&self) -> Result<Vec<u64>> {
        self.linker()?
            .array(DynamicTag::INIT_ARRAY, DynamicTag::INIT_ARRAYSZ)
    }

    /// Return the virtual addresses in the `DT_FINI_ARRAY` array, as they are in the file.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::init_array`], for
    /// `DT_FINI_ARRAYSZ`.
    pub fn fini_array(&self) -> Result<Vec<u64>> {
        self.linker()?
            .array(DynamicTag::FINI_ARRAY, DynamicTag::FINI_ARRAYSZ)
    }

    /// Return the virtual addresses in the `DT_PREINIT_ARRAY` array, as they are in the
    /// file.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::init_array`], for
    /// `DT_PREINIT_ARRAYSZ`.
    pub fn preinit_array(&self) -> Result<Vec<u64>> {
        self.linker()?
            .array(DynamicTag::PREINIT_ARRAY, DynamicTag::PREINIT_ARRAYSZ)
    }

    /// Return the prelink library list (`DT_GNU_LIBLIST`, `DT_GNU_LIBLISTSZ`), with the
    /// names from the dynamic string table. Return `None` if the dynamic table has no
    /// `DT_GNU_LIBLIST`.
    ///
    /// The list comes from the dynamic table, also if the file has a `SHT_GNU_LIBLIST`
    /// section.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`LinkingView::library_list`].
    pub fn library_list(&self) -> Result<Option<Vec<LibraryListEntry>>> {
        self.linker()?.library_list()
    }

    /// Return the `.eh_frame_hdr` table of the first `PT_GNU_EH_FRAME` segment.
    ///
    /// # Errors
    ///
    /// Return an error if the segment is outside the file or the table does not parse.
    pub fn eh_frame_hdr(&self) -> Result<Option<EhFrameHdr>> {
        linking::eh_frame_hdr(&self.space())
    }
}
