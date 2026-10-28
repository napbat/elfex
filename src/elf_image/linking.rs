//! The dynamic linking accessors of an [`ElfImage`].
//!
//! The accessors read each table at the virtual address that the dynamic table gives. They
//! translate the `d_ptr` values with [`ElfImage::resolve_pointer`], so they also work for a
//! loader-mapped image in which glibc changed the `d_ptr` values to runtime addresses.

use super::ElfImage;
use crate::dynamic::{DynamicEntry, DynamicTable, DynamicTag};
use crate::eh_frame::EhFrameHdr;
use crate::endian::Encoding;
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::header::Machine;
use crate::linking::{
    self, AddressSpace, DynamicRelocations, Linker, NoteSource, SegmentBytes, VersionTables,
};
use crate::note::{AuxvEntry, FileMapping, Note};
use crate::prelude::*;
use crate::program::SegmentType;
use crate::strtab::StringTable;
use crate::symbol::{NamedSymbol, SymbolTable};
use crate::{Error, Result};

impl AddressSpace for ElfImage {
    fn encoding(&self) -> Encoding {
        ElfImage::encoding(self)
    }

    fn machine(&self) -> Machine {
        ElfImage::machine(self)
    }

    fn slice_from_vaddr(&self, vaddr: u64) -> Result<&[u8]> {
        ElfImage::slice_from_vaddr(self, vaddr)
    }

    fn resolve_pointer(&self, value: u64) -> u64 {
        ElfImage::resolve_pointer(self, value)
    }

    fn dynamic_bytes(&self) -> Result<Option<&[u8]>> {
        Ok(AddressSpace::segments(self, SegmentType::DYNAMIC)?
            .into_iter()
            .next()
            .map(|segment| segment.data))
    }

    fn segments(&self, segment_type: SegmentType) -> Result<Vec<SegmentBytes<'_>>> {
        self.segments
            .iter()
            .filter(|segment| segment.header.segment_type == segment_type)
            .map(|segment| {
                let header = segment.header;
                let data = if !segment.data.is_empty() || header.memsz == 0 {
                    segment.data.as_slice()
                } else {
                    let memory = ElfImage::slice_from_vaddr(self, header.vaddr)
                        .map_err(|error| error.in_structure(format!("{segment_type}")))?;
                    let limit = usize::try_from(header.memsz)
                        .map_or(memory.len(), |size| size.min(memory.len()));
                    memory.get(..limit).unwrap_or(memory)
                };
                Ok(SegmentBytes { header, data })
            })
            .collect()
    }

    fn note_sources(&self) -> Result<Vec<NoteSource<'_>>> {
        Ok(AddressSpace::segments(self, SegmentType::NOTE)?
            .into_iter()
            .map(|segment| NoteSource {
                data: segment.data,
                align: segment.header.align,
                address: segment.header.vaddr,
            })
            .collect())
    }
}

impl ElfImage {
    /// Translate a `d_ptr` value of the dynamic table to a virtual address of the file.
    ///
    /// In a loaded process, glibc changes many `d_ptr` values in `.dynamic` to runtime
    /// addresses (but not on MIPS and RISC-V). If the image has a load bias, and no `PT_LOAD`
    /// memory range contains `value` but one contains `value` minus the load bias, return
    /// `value` minus the load bias. Else return `value`.
    ///
    /// The linking accessors (for example [`Self::dynamic_symbols`]) apply this function to
    /// the values of the pointer tags (`DynamicTag::is_pointer`).
    #[must_use]
    pub fn resolve_pointer(&self, value: u64) -> u64 {
        let Some(bias) = self.load_bias() else {
            return value;
        };
        let mapped = |address: u64| {
            self.load_segments()
                .any(|segment| segment.header.contains_vaddr(address))
        };
        let file_address = value.wrapping_sub(bias);
        if bias != 0 && !mapped(value) && mapped(file_address) {
            file_address
        } else {
            value
        }
    }

    /// Return the dynamic table of the `PT_DYNAMIC` segment, as it is in the image.
    ///
    /// The table bytes are the own data of the segment, or else at most `p_memsz` bytes of
    /// memory at `p_vaddr`. The function does not change the `d_ptr` values: in a
    /// loader-mapped image they can be runtime addresses (see [`Self::resolve_pointer`]).
    /// Return `None` if the image has no `PT_DYNAMIC` segment.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no `PT_LOAD`
    /// segment contains the `PT_DYNAMIC` address.
    pub fn dynamic(&self) -> Result<Option<DynamicTable>> {
        linking::dynamic_table(self)
    }

    /// Write the `d_ptr` values of the dynamic table back as virtual addresses of the file.
    /// Return the number of changed entries.
    ///
    /// The function changes each entry with a pointer tag (`DynamicTag::is_pointer`) for which
    /// [`Self::resolve_pointer`] gives a different value. Thus it undoes the change that glibc
    /// makes in a loaded process. The function writes only these `d_un` fields, in place:
    ///
    /// - In the own data of the `PT_DYNAMIC` segment, if it has data.
    /// - In the `PT_LOAD` memory at the `PT_DYNAMIC` address, if a `PT_LOAD` segment contains
    ///   the entry.
    ///
    /// Return 0 if the image has no `PT_DYNAMIC` segment or no load bias. A second call
    /// returns 0.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if no
    ///   `PT_LOAD` segment contains the `PT_DYNAMIC` address, and the segment has no data.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if an ELF32
    ///   value does not fit in 32 bits.
    pub fn restore_dynamic_pointers(&mut self) -> Result<usize> {
        let Some(table) = self.dynamic()? else {
            return Ok(0);
        };
        let machine = self.machine();
        let changes: Vec<(usize, u64)> = table
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| entry.tag.is_pointer(machine))
            .filter_map(|(position, entry)| {
                let value = self.resolve_pointer(entry.value);
                (value != entry.value).then_some((position, value))
            })
            .collect();
        let Some(dynamic) = self
            .segments
            .iter()
            .position(|segment| segment.header.segment_type == SegmentType::DYNAMIC)
        else {
            return Ok(0);
        };
        let encoding = self.encoding();
        let size = DynamicEntry::size(encoding.class);
        let vaddr = self.segments[dynamic].header.vaddr;
        for &(position, value) in &changes {
            // The parser stops at the first `DT_NULL` entry. Thus entry `position` is at byte
            // `position * size`, and its `d_un` field follows the `d_tag` field.
            let offset = position
                .checked_mul(size)
                .and_then(|offset| offset.checked_add(encoding.addr_size()))
                .ok_or_else(|| Error::value_out_of_range("the dynamic table is too large"))?;
            let mut bytes = Vec::with_capacity(encoding.addr_size());
            encoding.write_addr(&mut bytes, value)?;
            let address = u64::try_from(offset)
                .ok()
                .and_then(|offset| vaddr.checked_add(offset))
                .ok_or_else(|| Error::invalid_address(vaddr))?;
            let own = &mut self.segments[dynamic].data;
            if own.is_empty() {
                self.write_vaddr(address, &bytes)?;
                continue;
            }
            encoding.put_addr(own, offset, value)?;
            if self
                .load_segment_for(address, u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .is_some()
            {
                self.write_vaddr(address, &bytes)?;
            }
        }
        Ok(changes.len())
    }

    /// Return the dynamic string table at `DT_STRTAB` with the size `DT_STRSZ`.
    ///
    /// The function translates `DT_STRTAB` with [`Self::resolve_pointer`]. Without
    /// `DT_STRSZ`, the table goes to the end of the segment data.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table does not parse, or if no `PT_LOAD` segment holds
    /// the string table.
    pub fn dynamic_strings(&self) -> Result<Option<StringTable>> {
        Linker::load(self)?.strings()
    }

    /// Return the dynamic symbol table at `DT_SYMTAB`.
    ///
    /// The symbol count comes from `DT_MIPS_SYMTABNO` (MIPS only), else from `DT_HASH`, else
    /// from `DT_GNU_HASH` and the dynamic relocations, else from the distance between
    /// `DT_SYMTAB` and `DT_STRTAB`. Return `None` if no source gives the count. The function
    /// translates the `d_ptr` values with [`Self::resolve_pointer`].
    ///
    /// # Errors
    ///
    /// Return an error if a table does not parse, if `DT_SYMENT` is smaller than the symbol
    /// size, or if no `PT_LOAD` segment holds the table.
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

    /// Return the notes of all `PT_NOTE` segments.
    ///
    /// The bytes of each segment are its own data, or else at most `p_memsz` bytes of memory
    /// at `p_vaddr`.
    ///
    /// # Errors
    ///
    /// Return an error if no `PT_LOAD` segment holds a `PT_NOTE` segment, or if a note table
    /// does not parse.
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

    /// Return the page size and the mapped files of the first `NT_FILE` note (owner `CORE`)
    /// of a core file.
    ///
    /// Return `None` if the image has no such note.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::notes`], or if the descriptor
    /// does not parse (see [`parse_nt_file`](crate::note::parse_nt_file)).
    pub fn core_file_mappings(&self) -> Result<Option<(u64, Vec<FileMapping>)>> {
        linking::core_file_mappings(self)
    }

    /// Return the auxiliary vector of the first `NT_AUXV` note (owner `CORE`) of a core
    /// file, without the `AT_NULL` entry.
    ///
    /// Return `None` if the image has no such note.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::notes`], or if the descriptor
    /// does not parse (see [`parse_auxv`](crate::note::parse_auxv)).
    pub fn auxv(&self) -> Result<Option<Vec<AuxvEntry>>> {
        linking::auxv(self)
    }

    /// Return the relocation tables that the dynamic table names: `DT_RELA`, `DT_REL`,
    /// `DT_JMPREL` and `DT_RELR`.
    ///
    /// The function translates the `d_ptr` values with [`Self::resolve_pointer`]. The
    /// relocation offsets are virtual addresses of the file.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic table does not parse, if a size tag is missing, if
    /// `DT_PLTREL` is not `DT_REL` or `DT_RELA`, or if a table is not in a `PT_LOAD` segment
    /// or does not parse.
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

    /// Return the symbol version tables at `DT_VERSYM`, `DT_VERDEF` and `DT_VERNEED`.
    ///
    /// `DT_VERSYM` has one value for each dynamic symbol. Thus the function reads it only if
    /// [`Self::dynamic_symbols`] finds the symbol count.
    ///
    /// # Errors
    ///
    /// Return an error if a table does not parse or is not in a `PT_LOAD` segment.
    pub fn version_tables(&self) -> Result<VersionTables> {
        Linker::load(self)?.versions(None)
    }

    /// Return all dynamic symbols except the null symbol, with their names, sections and
    /// versions.
    ///
    /// # Errors
    ///
    /// Return an error if the dynamic symbol table, the dynamic string table or a version
    /// table does not parse, or if a name offset is outside the string table.
    pub fn dynamic_symbol_list(&self) -> Result<Vec<NamedSymbol>> {
        Linker::load(self)?.symbol_list()
    }

    /// Return the exported dynamic symbols: the defined symbols with the binding
    /// `STB_GLOBAL`, `STB_WEAK` or `STB_GNU_UNIQUE` and a visibility other than `STV_HIDDEN`
    /// and `STV_INTERNAL`.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::dynamic_symbol_list`].
    pub fn exports(&self) -> Result<Vec<NamedSymbol>> {
        Linker::load(self)?.exports()
    }

    /// Return the imported dynamic symbols: the symbols with `st_shndx` `SHN_UNDEF`, except
    /// the null symbol.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::dynamic_symbol_list`].
    pub fn imports(&self) -> Result<Vec<NamedSymbol>> {
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
    pub fn lookup_dynamic_symbol(&self, name: &str) -> Result<Option<NamedSymbol>> {
        Linker::load(self)?.lookup(name)
    }

    /// Return the words of the `DT_INIT_ARRAY` array, as they are in the image.
    ///
    /// In a loader-mapped image, the dynamic linker relocated the words: they are runtime
    /// addresses.
    ///
    /// # Errors
    ///
    /// Return an error if `DT_INIT_ARRAYSZ` is missing or is not a multiple of the word size,
    /// or if no `PT_LOAD` segment holds the array.
    pub fn init_array(&self) -> Result<Vec<u64>> {
        Linker::load(self)?.array(DynamicTag::INIT_ARRAY, DynamicTag::INIT_ARRAYSZ)
    }

    /// Return the words of the `DT_FINI_ARRAY` array, as they are in the image.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::init_array`], for
    /// `DT_FINI_ARRAYSZ`.
    pub fn fini_array(&self) -> Result<Vec<u64>> {
        Linker::load(self)?.array(DynamicTag::FINI_ARRAY, DynamicTag::FINI_ARRAYSZ)
    }

    /// Return the words of the `DT_PREINIT_ARRAY` array, as they are in the image.
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
    /// The section address of the table is `p_vaddr`. Thus the addresses in the table are
    /// virtual addresses of the file.
    ///
    /// # Errors
    ///
    /// Return an error if no `PT_LOAD` segment holds the segment, or if the table does not
    /// parse.
    pub fn eh_frame_hdr(&self) -> Result<Option<EhFrameHdr>> {
        linking::eh_frame_hdr(self)
    }
}
