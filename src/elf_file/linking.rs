//! The dynamic linking accessors of an [`ElfFile`].
//!
//! The accessors prefer the sections (for example `.dynsym`, `.gnu.version` and the
//! `SHT_NOTE` sections). If a section is absent, they read the table through the dynamic
//! table, as `ElfImage` does.

use super::ElfFile;
use crate::dynamic::{DynamicTable, DynamicTag};
use crate::eh_frame::EhFrameHdr;
use crate::endian::Encoding;
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::header::Machine;
use crate::linking::{
    self, AddressSpace, DynamicRelocations, DynamicSymbol, Linker, NoteSource, SectionTable,
    SegmentBytes, TableSection, VersionTables,
};
use crate::note::Note;
use crate::prelude::*;
use crate::program::SegmentType;
use crate::reloc::RelocationTable;
use crate::section::{SectionHeader, SectionType};
use crate::strtab::StringTable;
use crate::symbol::SymbolTable;
use crate::{Error, Result};

impl AddressSpace for ElfFile {
    fn encoding(&self) -> Encoding {
        ElfFile::encoding(self)
    }

    fn machine(&self) -> Machine {
        ElfFile::machine(self)
    }

    fn slice_from_vaddr(&self, vaddr: u64) -> Result<&[u8]> {
        ElfFile::slice_from_vaddr(self, vaddr)
    }

    fn resolve_pointer(&self, value: u64) -> u64 {
        value
    }

    fn dynamic_bytes(&self) -> Result<Option<&[u8]>> {
        if let Some(index) = self.file_section_index(SectionType::DYNAMIC) {
            return self.section_data(index).map(Some);
        }
        Ok(AddressSpace::segments(self, SegmentType::DYNAMIC)?
            .into_iter()
            .next()
            .map(|segment| segment.data))
    }

    fn segments(&self, segment_type: SegmentType) -> Result<Vec<SegmentBytes<'_>>> {
        self.program_headers()
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

    fn note_sources(&self) -> Result<Vec<NoteSource<'_>>> {
        let mut sources = Vec::new();
        for (index, header) in self.section_headers().iter().enumerate() {
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

    fn table_section(&self, table: TableSection) -> Result<Option<SectionTable<'_>>> {
        let index = match table {
            TableSection::DynamicStrings => self.dynamic_strings_index(),
            TableSection::DynamicSymbols => self.file_section_index(SectionType::DYNSYM),
            TableSection::Versym => self.file_section_index(SectionType::GNU_VERSYM),
            TableSection::Verdef => self.file_section_index(SectionType::GNU_VERDEF),
            TableSection::Verneed => self.file_section_index(SectionType::GNU_VERNEED),
        };
        let Some(index) = index else {
            return Ok(None);
        };
        let header = self.section_header(index)?;
        Ok(Some(SectionTable {
            data: self.section_data(index)?,
            entsize: header.entsize,
            info: header.info,
        }))
    }
}

impl ElfFile {
    /// Return the index of the first section of `section_type` with file bytes.
    fn file_section_index(&self, section_type: SectionType) -> Option<usize> {
        self.section_headers()
            .iter()
            .position(|header| header.section_type == section_type && header.has_file_data())
    }

    /// Return the index of the `SHT_STRTAB` section that `sh_link` of the `SHT_DYNAMIC`
    /// section gives, if it has file bytes.
    fn dynamic_strings_index(&self) -> Option<usize> {
        let dynamic = self.file_section_index(SectionType::DYNAMIC)?;
        let link = usize::try_from(self.section_headers().get(dynamic)?.link).ok()?;
        let strings = self.section_headers().get(link)?;
        (link != 0 && strings.section_type == SectionType::STRTAB && strings.has_file_data())
            .then_some(link)
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
        linking::dynamic_table(self)
    }

    /// Return the dynamic string table: the `sh_link` section of the `SHT_DYNAMIC` section,
    /// or else the bytes at `DT_STRTAB` with the size `DT_STRSZ`.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table does not parse, or if the string table is outside
    /// the file bytes of the `PT_LOAD` segments.
    pub fn dynamic_strings(&self) -> Result<Option<StringTable>> {
        Linker::load(self)?.strings()
    }

    /// Return the dynamic symbol table: the `SHT_DYNSYM` section, or else the table at
    /// `DT_SYMTAB`.
    ///
    /// Without a section, the symbol count comes from `DT_HASH`, else from `DT_GNU_HASH` and
    /// the dynamic relocations, else from the distance between `DT_SYMTAB` and `DT_STRTAB`.
    /// Return `None` if no source gives the count.
    ///
    /// # Errors
    ///
    /// Return an error if a table does not parse, if `DT_SYMENT` is smaller than the symbol
    /// size, or if the table is outside the file bytes of the `PT_LOAD` segments.
    pub fn dynamic_symbols(&self) -> Result<Option<SymbolTable>> {
        Linker::load(self)?.symbols()
    }

    /// Return the names of the needed libraries (`DT_NEEDED`), in table order, as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table or the dynamic string table does not parse, or if
    /// a name offset is outside the string table.
    pub fn needed_libraries(&self) -> Result<Vec<String>> {
        Linker::load(self)?.needed_libraries()
    }

    /// Return the shared object name (`DT_SONAME`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn soname(&self) -> Result<Option<String>> {
        Linker::load(self)?.string_entry(DynamicTag::SONAME)
    }

    /// Return the deprecated library search path (`DT_RPATH`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn rpath(&self) -> Result<Option<String>> {
        Linker::load(self)?.string_entry(DynamicTag::RPATH)
    }

    /// Return the library search path (`DT_RUNPATH`), as lossy UTF-8.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::needed_libraries`].
    pub fn runpath(&self) -> Result<Option<String>> {
        Linker::load(self)?.string_entry(DynamicTag::RUNPATH)
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
        AddressSpace::segments(self, SegmentType::INTERP)?
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
        linking::notes(self)
    }

    /// Return the descriptor of the first GNU `NT_GNU_BUILD_ID` note.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::notes`].
    pub fn build_id(&self) -> Result<Option<Vec<u8>>> {
        linking::build_id(self)
    }

    /// Return the relocation tables that the dynamic table names: `DT_RELA`, `DT_REL`,
    /// `DT_JMPREL` and `DT_RELR`.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table does not parse, if a size tag is missing, if
    /// `DT_PLTREL` is not `DT_REL` or `DT_RELA`, or if a table is outside the file bytes of
    /// the `PT_LOAD` segments or does not parse.
    pub fn dynamic_relocations(&self) -> Result<DynamicRelocations> {
        Linker::load(self)?.relocations()
    }

    /// Return the System V hash table at `DT_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table or the hash table does not parse.
    pub fn sysv_hash_table(&self) -> Result<Option<SysvHashTable>> {
        Linker::load(self)?.sysv_hash()
    }

    /// Return the GNU hash table at `DT_GNU_HASH`.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table or the hash table does not parse.
    pub fn gnu_hash_table(&self) -> Result<Option<GnuHashTable>> {
        Linker::load(self)?.gnu_hash()
    }

    /// Return the symbol version tables: the `SHT_GNU_versym`, `SHT_GNU_verdef` and
    /// `SHT_GNU_verneed` sections, or else the tables at `DT_VERSYM`, `DT_VERDEF` and
    /// `DT_VERNEED`.
    ///
    /// # Errors
    ///
    /// Return an error if a table does not parse or is outside the file.
    pub fn version_tables(&self) -> Result<VersionTables> {
        Linker::load(self)?.versions(None)
    }

    /// Return all dynamic symbols except the null symbol, with their names and versions.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic symbol table, the dynamic string table or a version
    /// table does not parse, or if a name offset is outside the string table.
    pub fn dynamic_symbol_list(&self) -> Result<Vec<DynamicSymbol>> {
        Linker::load(self)?.symbol_list()
    }

    /// Return the exported dynamic symbols: the defined symbols with the binding
    /// `STB_GLOBAL`, `STB_WEAK` or `STB_GNU_UNIQUE` and a visibility other than `STV_HIDDEN`
    /// and `STV_INTERNAL`.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::dynamic_symbol_list`].
    pub fn exports(&self) -> Result<Vec<DynamicSymbol>> {
        Linker::load(self)?.exports()
    }

    /// Return the imported dynamic symbols: the symbols with `st_shndx` `SHN_UNDEF`, except
    /// the null symbol.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::dynamic_symbol_list`].
    pub fn imports(&self) -> Result<Vec<DynamicSymbol>> {
        Linker::load(self)?.imports()
    }

    /// Find the dynamic symbol with the name `name`.
    ///
    /// The search uses the GNU hash table, or else the System V hash table, or else a linear
    /// search of the dynamic symbol table.
    ///
    /// # Errors
    ///
    /// Return an error if a hash table does not parse, or for the same conditions as
    /// [`Self::dynamic_symbol_list`].
    pub fn lookup_dynamic_symbol(&self, name: &str) -> Result<Option<DynamicSymbol>> {
        Linker::load(self)?.lookup(name)
    }

    /// Return the virtual addresses in the `DT_INIT_ARRAY` array, as they are in the file.
    ///
    /// # Errors
    ///
    /// Return an error if `DT_INIT_ARRAYSZ` is missing or is not a multiple of the word size,
    /// or if the array is outside the file bytes of the `PT_LOAD` segments.
    pub fn init_array(&self) -> Result<Vec<u64>> {
        Linker::load(self)?.array(DynamicTag::INIT_ARRAY, DynamicTag::INIT_ARRAYSZ)
    }

    /// Return the virtual addresses in the `DT_FINI_ARRAY` array, as they are in the file.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::init_array`], for
    /// `DT_FINI_ARRAYSZ`.
    pub fn fini_array(&self) -> Result<Vec<u64>> {
        Linker::load(self)?.array(DynamicTag::FINI_ARRAY, DynamicTag::FINI_ARRAYSZ)
    }

    /// Return the virtual addresses in the `DT_PREINIT_ARRAY` array, as they are in the
    /// file.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::init_array`], for
    /// `DT_PREINIT_ARRAYSZ`.
    pub fn preinit_array(&self) -> Result<Vec<u64>> {
        Linker::load(self)?.array(DynamicTag::PREINIT_ARRAY, DynamicTag::PREINIT_ARRAYSZ)
    }

    /// Return the `.eh_frame_hdr` table of the first `PT_GNU_EH_FRAME` segment.
    ///
    /// # Errors
    ///
    /// Return an error if the segment is outside the file or the table does not parse.
    pub fn eh_frame_hdr(&self) -> Result<Option<EhFrameHdr>> {
        linking::eh_frame_hdr(self)
    }

    /// Return the first `SHT_SYMTAB` section as a symbol table.
    ///
    /// # Errors
    ///
    /// Return an error if the section is outside the file or does not parse.
    pub fn symbols(&self) -> Result<Option<SymbolTable>> {
        let Some(index) = self.file_section_index(SectionType::SYMTAB) else {
            return Ok(None);
        };
        let header = self.section_header(index)?;
        SymbolTable::parse_with_entsize(self.section_data(index)?, self.encoding(), header.entsize)
            .map(Some)
            .map_err(|error| error.in_structure("SHT_SYMTAB"))
    }

    /// Return the string table that `sh_link` of the first `SHT_SYMTAB` section gives.
    ///
    /// # Errors
    ///
    /// Return an error if `sh_link` is not a section index, or if the section is outside the
    /// file.
    pub fn symbol_strings(&self) -> Result<Option<StringTable>> {
        let Some(index) = self.file_section_index(SectionType::SYMTAB) else {
            return Ok(None);
        };
        let link = self.section_header(index)?.link;
        let link = usize::try_from(link)
            .map_err(|_| Error::invalid_section(format!("sh_link {link} is out of range")))?;
        self.section_data(link)
            .map(|data| Some(StringTable::parse(data)))
            .map_err(|error| error.in_structure("SHT_SYMTAB sh_link"))
    }

    /// Parse the `SHT_REL` or `SHT_RELA` section at `index`.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) if `index` is
    ///   out of range, or if the section is not `SHT_REL` or `SHT_RELA`.
    /// - Return an error if the section is outside the file or does not parse.
    pub fn section_relocations(&self, index: usize) -> Result<RelocationTable> {
        let header: SectionHeader = *self.section_header(index)?;
        let with_addend = match header.section_type {
            SectionType::RELA => true,
            SectionType::REL => false,
            other => {
                return Err(Error::invalid_section(format!(
                    "section {index} has the type {other}, not SHT_REL or SHT_RELA"
                )));
            }
        };
        let encoding = self.encoding();
        let entsize = if header.entsize == 0 {
            crate::reloc::Relocation::size(encoding.class, with_addend)
        } else {
            usize::try_from(header.entsize).map_err(|_| {
                Error::invalid_section(format!("sh_entsize {} is too large", header.entsize))
            })?
        };
        RelocationTable::parse_with_entsize(
            self.section_data(index)?,
            encoding,
            self.machine(),
            with_addend,
            entsize,
        )
    }
}
