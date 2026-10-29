//! Dynamic linking data of an [`ElfFile`](crate::ElfFile) or an [`ElfImage`](crate::ElfImage).
//!
//! The dynamic table (`.dynamic`, `PT_DYNAMIC`) names the tables that the dynamic linker uses:
//! the dynamic string and symbol tables, the hash tables, the version tables, the relocations
//! and the initialization arrays. `ElfFile` and `ElfImage` have the same accessors for these
//! tables, for example `dynamic_symbols()`, `needed_libraries()` and `dynamic_relocations()`.
//!
//! This module holds the result types of these accessors: [`DynamicRelocations`] and
//! [`VersionTables`]. The symbol accessors return [`NamedSymbol`](crate::NamedSymbol).
//!
//! The two types also read the notes of a core file: `core_file_mappings()` (`NT_FILE`) and
//! `auxv()` (`NT_AUXV`).
//!
//! # Reuse of the parsed tables
//!
//! Each accessor parses the tables that it needs again. `ElfFile::linking()` and
//! `ElfImage::linking()` return a [`LinkingView`] that parses each table only once. Use it to
//! call more than one accessor, or to look up many symbols: each lookup then uses the hash
//! table directly.
//!
//! # Table sources
//!
//! - `ElfImage` reads each table at the virtual address that the dynamic table gives, with
//!   the size that the dynamic table gives.
//! - `ElfFile` prefers the sections (for example `.dynsym` and `.gnu.version`). If the file
//!   has no such section, it reads the table through the dynamic table, as `ElfImage` does.
//!
//! # Loader-mapped images
//!
//! In a loaded process, glibc changes many `d_ptr` values of `.dynamic` to runtime addresses
//! (but not on MIPS and RISC-V). `ElfImage` translates such a value back to a virtual address
//! of the file if it knows the load bias. See
//! [`ElfImage::resolve_pointer`](crate::ElfImage::resolve_pointer).

mod relocations;
mod symbols;
#[cfg(test)]
mod tests;
mod view;

pub use view::LinkingView;

use core::cell::OnceCell;

use crate::dynamic::{DynamicTable, DynamicTag};
use crate::eh_frame::EhFrameHdr;
use crate::endian::Encoding;
use crate::hash::{GnuHashTable, SysvHashTable};
use crate::header::Machine;
use crate::note::{
    AuxvEntry, ELF_NOTE_CORE, ELF_NOTE_GNU, FileMapping, NT_AUXV, NT_FILE, NT_GNU_BUILD_ID, Note,
    NoteTable, parse_auxv, parse_nt_file,
};
use crate::prelude::*;
use crate::program::{ProgramHeader, SegmentType};
use crate::reloc::{Relocation, RelocationTable, RelrTable};
use crate::strtab::StringTable;
use crate::symbol::{SymbolSectionIndexTable, SymbolTable};
use crate::version::{VersionDefinitionTable, VersionMap, VersionRequirementTable, VersymTable};
use crate::{Error, Result};

/// The relocation tables that the dynamic table names.
///
/// Each field is `None` if the dynamic table does not have its address tag. The relocation
/// offsets (`r_offset`) are virtual addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DynamicRelocations {
    /// The `Elf32_Rela` or `Elf64_Rela` entries at `DT_RELA` (`DT_RELASZ`, `DT_RELAENT`).
    pub rela: Option<RelocationTable>,
    /// The `Elf32_Rel` or `Elf64_Rel` entries at `DT_REL` (`DT_RELSZ`, `DT_RELENT`).
    pub rel: Option<RelocationTable>,
    /// The PLT relocations at `DT_JMPREL` (`DT_PLTRELSZ`). `DT_PLTREL` selects `Rel` or
    /// `Rela` entries.
    pub plt: Option<RelocationTable>,
    /// The relative relocations at `DT_RELR` (`DT_RELRSZ`), or at `DT_ANDROID_RELR`.
    pub relr: Option<RelrTable>,
    /// The Android packed relocations (`APS2`) at `DT_ANDROID_RELA` (`DT_ANDROID_RELASZ`), or
    /// else at `DT_ANDROID_REL` (`DT_ANDROID_RELSZ`).
    pub android: Option<RelocationTable>,
    /// The CREL relocations at `DT_CREL`. The CREL header gives the entry count.
    pub crel: Option<RelocationTable>,
}

impl DynamicRelocations {
    /// Iterate over the `Rel` and `Rela` entries of [`Self::rela`], [`Self::rel`],
    /// [`Self::android`], [`Self::crel`] and [`Self::plt`], in this order. The iterator does
    /// not include the `RELR` addresses.
    pub fn iter(&self) -> impl Iterator<Item = &Relocation> {
        [&self.rela, &self.rel, &self.android, &self.crel, &self.plt]
            .into_iter()
            .flatten()
            .flat_map(RelocationTable::iter)
    }
}

/// The GNU symbol version tables of the dynamic symbols.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct VersionTables {
    /// The `Elf_Versym` values (`.gnu.version`, `DT_VERSYM`).
    pub versym: Option<VersymTable>,
    /// The version definitions (`.gnu.version_d`, `DT_VERDEF`).
    pub definitions: Option<VersionDefinitionTable>,
    /// The version requirements (`.gnu.version_r`, `DT_VERNEED`).
    pub requirements: Option<VersionRequirementTable>,
}

impl VersionTables {
    /// Return the map from the version indexes to the version names.
    #[must_use]
    pub fn map(&self) -> VersionMap {
        VersionMap::new(self.definitions.as_ref(), self.requirements.as_ref())
    }
}

/// The bytes of a segment of an address space.
pub(crate) struct SegmentBytes<'a> {
    /// The program header.
    pub(crate) header: ProgramHeader,
    /// The segment bytes. They start at the virtual address `p_vaddr`.
    pub(crate) data: &'a [u8],
}

/// The bytes of a note table and its alignment.
pub(crate) struct NoteSource<'a> {
    /// The note entries.
    pub(crate) data: &'a [u8],
    /// The alignment: `sh_addralign` or `p_align`.
    pub(crate) align: u64,
    /// The virtual address of the bytes, for the error context.
    pub(crate) address: u64,
}

/// A table section of an `ElfFile` that replaces a table of the dynamic table.
pub(crate) struct SectionTable<'a> {
    /// The section bytes.
    pub(crate) data: &'a [u8],
    /// The entry size (`sh_entsize`).
    pub(crate) entsize: u64,
    /// The extra information (`sh_info`). For a version definition or requirement section,
    /// this is the number of entries.
    pub(crate) info: u32,
}

/// The tables that an `ElfFile` can read from a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TableSection {
    /// The string table that `sh_link` of the `SHT_DYNAMIC` section gives.
    DynamicStrings,
    /// The `SHT_DYNSYM` section.
    DynamicSymbols,
    /// The `SHT_GNU_versym` section.
    Versym,
    /// The `SHT_GNU_verdef` section.
    Verdef,
    /// The `SHT_GNU_verneed` section.
    Verneed,
    /// The `SHT_SYMTAB_SHNDX` section that links to the `SHT_DYNSYM` section.
    DynamicSymbolIndices,
}

/// The view of an `ElfFile` or an `ElfImage` that the linking accessors use.
pub(crate) trait AddressSpace {
    /// Return the class and the byte order.
    fn encoding(&self) -> Encoding;

    /// Return the target architecture (`e_machine`).
    fn machine(&self) -> Machine;

    /// Return the bytes from the virtual address `vaddr` to the end of the data of its
    /// segment.
    fn slice_from_vaddr(&self, vaddr: u64) -> Result<&[u8]>;

    /// Translate a `d_ptr` value of the dynamic table to a virtual address of the file.
    fn resolve_pointer(&self, value: u64) -> u64;

    /// Return the bytes of the dynamic table, or `None` if there is no dynamic table.
    fn dynamic_bytes(&self) -> Result<Option<&[u8]>>;

    /// Return the bytes of each segment of `segment_type`, in program header order.
    fn segments(&self, segment_type: SegmentType) -> Result<Vec<SegmentBytes<'_>>>;

    /// Return the bytes of each note table.
    fn note_sources(&self) -> Result<Vec<NoteSource<'_>>>;

    /// Return the section that holds a table, or `None` to read the table through the
    /// dynamic table. The default implementation returns `None`.
    fn table_section(&self, _table: TableSection) -> Result<Option<SectionTable<'_>>> {
        Ok(None)
    }
}

/// Parse the dynamic table of `space`, as it is in the source.
pub(crate) fn dynamic_table<S: AddressSpace + ?Sized>(space: &S) -> Result<Option<DynamicTable>> {
    let Some(bytes) = space.dynamic_bytes()? else {
        return Ok(None);
    };
    // The parser reads only complete entries, so it cannot fail.
    DynamicTable::parse(bytes, space.encoding()).map(Some)
}

/// Parse all notes of `space`, in source order.
pub(crate) fn notes<S: AddressSpace>(space: &S) -> Result<Vec<Note>> {
    let mut notes = Vec::new();
    for source in space.note_sources()? {
        let table = NoteTable::parse(source.data, space.encoding(), source.align)
            .map_err(|error| error.at_address(source.address))?;
        notes.extend(table.notes);
    }
    Ok(notes)
}

/// Return the descriptor of the first GNU `NT_GNU_BUILD_ID` note of `space`.
pub(crate) fn build_id<S: AddressSpace>(space: &S) -> Result<Option<Vec<u8>>> {
    Ok(notes(space)?
        .into_iter()
        .find(|note| note.is(ELF_NOTE_GNU, NT_GNU_BUILD_ID))
        .map(|note| note.desc))
}

/// Return the page size and the mapped files of the first `NT_FILE` note (owner `CORE`) of
/// `space`.
pub(crate) fn core_file_mappings<S: AddressSpace>(
    space: &S,
) -> Result<Option<(u64, Vec<FileMapping>)>> {
    notes(space)?
        .iter()
        .find(|note| note.is(ELF_NOTE_CORE, NT_FILE))
        .map(|note| parse_nt_file(&note.desc, space.encoding()))
        .transpose()
}

/// Return the entries of the first `NT_AUXV` note (owner `CORE`) of `space`.
pub(crate) fn auxv<S: AddressSpace>(space: &S) -> Result<Option<Vec<AuxvEntry>>> {
    notes(space)?
        .iter()
        .find(|note| note.is(ELF_NOTE_CORE, NT_AUXV))
        .map(|note| parse_auxv(&note.desc, space.encoding()))
        .transpose()
}

/// Parse the `.eh_frame_hdr` data of the first `PT_GNU_EH_FRAME` segment of `space`.
pub(crate) fn eh_frame_hdr<S: AddressSpace>(space: &S) -> Result<Option<EhFrameHdr>> {
    let Some(segment) = space
        .segments(SegmentType::GNU_EH_FRAME)?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };
    let address = segment.header.vaddr;
    EhFrameHdr::parse(segment.data, space.encoding(), address)
        .map(Some)
        .map_err(|error| error.in_structure("PT_GNU_EH_FRAME").at_address(address))
}

/// Return the interpreter path in the `PT_INTERP` bytes: the bytes up to the first null
/// byte, as UTF-8.
pub(crate) fn interpreter_path(bytes: &[u8]) -> Result<String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    bytes
        .get(..end)
        .and_then(|path| core::str::from_utf8(path).ok())
        .map(ToString::to_string)
        .ok_or_else(|| Error::invalid_utf8().in_structure("PT_INTERP"))
}

/// Read the string at `offset` in the dynamic string table, as lossy UTF-8.
fn dynamic_string(strings: Option<&StringTable>, offset: u64) -> Result<String> {
    let strings = strings.ok_or_else(|| {
        Error::invalid_table("the dynamic string table (DT_STRTAB) is missing")
            .in_structure("dynamic table")
    })?;
    let offset = u32::try_from(offset).map_err(|_| {
        Error::invalid_table(format!(
            "the string offset {offset:#x} does not fit in 32 bits"
        ))
        .in_structure("DT_STRTAB")
    })?;
    strings
        .get_lossy(offset)
        .map(Cow::into_owned)
        .map_err(|error| error.in_structure("DT_STRTAB"))
}

/// The tables that a [`Linker`] parsed. Each cell holds a table after its first successful
/// parse. An error is not kept: the next call parses the table again and returns the error
/// again.
#[derive(Default)]
struct Cache {
    /// The dynamic string table.
    strings: OnceCell<Option<StringTable>>,
    /// The dynamic symbol table.
    symbols: OnceCell<Option<SymbolTable>>,
    /// The extended section indices of the dynamic symbols.
    indices: OnceCell<Option<SymbolSectionIndexTable>>,
    /// The version tables and their map.
    versions: OnceCell<(VersionTables, VersionMap)>,
    /// The System V hash table.
    sysv_hash: OnceCell<Option<SysvHashTable>>,
    /// The GNU hash table.
    gnu_hash: OnceCell<Option<GnuHashTable>>,
    /// The relocation tables of the dynamic table.
    relocations: OnceCell<DynamicRelocations>,
    /// The indices of the named dynamic symbols, sorted by name and then by index, for a
    /// lookup without a hash table.
    sorted_names: OnceCell<Vec<u32>>,
}

/// Return the value in `cell`. If `cell` is empty, fill it with the result of `load`, or
/// return the error of `load`.
fn cached<T>(cell: &OnceCell<T>, load: impl FnOnce() -> Result<T>) -> Result<&T> {
    if let Some(value) = cell.get() {
        return Ok(value);
    }
    let value = load()?;
    Ok(cell.get_or_init(|| value))
}

/// The dynamic table of an address space and the readers of the tables that it names.
///
/// The linker keeps each table that it parsed, so a second call does not parse it again.
pub(crate) struct Linker<'a> {
    /// The address space.
    space: &'a (dyn AddressSpace + Sync),
    /// The dynamic table as it is in the source, or `None` if there is no dynamic table.
    dynamic: Option<DynamicTable>,
    /// The parsed tables.
    cache: Cache,
}

impl<'a> Linker<'a> {
    /// Parse the dynamic table of `space`.
    pub(crate) fn load(space: &'a (dyn AddressSpace + Sync)) -> Result<Self> {
        Ok(Self {
            space,
            dynamic: dynamic_table(space)?,
            cache: Cache::default(),
        })
    }

    /// Return the dynamic table, or `None` if there is no dynamic table.
    pub(crate) fn dynamic(&self) -> Option<&DynamicTable> {
        self.dynamic.as_ref()
    }

    /// Return the class and the byte order of the address space.
    fn encoding(&self) -> Encoding {
        self.space.encoding()
    }

    /// Return the value of the first dynamic entry with `tag`.
    fn value(&self, tag: DynamicTag) -> Option<u64> {
        self.dynamic.as_ref()?.get(tag)
    }

    /// Return the value of the first dynamic entry with `tag`. If the tag is a pointer tag,
    /// translate the value with [`AddressSpace::resolve_pointer`].
    fn pointer(&self, tag: DynamicTag) -> Option<u64> {
        let value = self.value(tag)?;
        if tag.is_pointer(self.space.machine()) {
            Some(self.space.resolve_pointer(value))
        } else {
            Some(value)
        }
    }

    /// Return the bytes from `address` to the end of the data of its segment.
    fn slice(&self, address: u64, structure: &str) -> Result<&'a [u8]> {
        self.space
            .slice_from_vaddr(address)
            .map_err(|error| error.in_structure(structure))
    }

    /// Return `size` bytes at `address`.
    fn bytes(&self, address: u64, size: u64, structure: &str) -> Result<&'a [u8]> {
        if size == 0 {
            return Ok(&[]);
        }
        let slice = self.slice(address, structure)?;
        usize::try_from(size)
            .ok()
            .and_then(|size| slice.get(..size))
            .ok_or_else(|| {
                Error::invalid_table(format!(
                    "the table needs {size} bytes, but its segment has {} bytes at the address",
                    slice.len()
                ))
                .in_structure(structure)
                .at_address(address)
            })
    }

    /// Return the size value of `tag`, or an error if the tag is absent.
    fn required_size(&self, tag: DynamicTag, structure: &str) -> Result<u64> {
        self.value(tag).ok_or_else(|| {
            Error::invalid_table(format!("{tag} is missing")).in_structure(structure)
        })
    }

    /// Return the dynamic string table.
    ///
    /// `ElfFile` prefers the `sh_link` string table of the `SHT_DYNAMIC` section. Else the
    /// table is at `DT_STRTAB` with the size `DT_STRSZ`. Without `DT_STRSZ`, the table goes
    /// to the end of its segment.
    pub(crate) fn strings(&self) -> Result<Option<&StringTable>> {
        cached(&self.cache.strings, || self.load_strings()).map(Option::as_ref)
    }

    /// Parse the dynamic string table (see [`Self::strings`]).
    fn load_strings(&self) -> Result<Option<StringTable>> {
        if let Some(section) = self.space.table_section(TableSection::DynamicStrings)? {
            return Ok(Some(StringTable::parse(section.data)));
        }
        let Some(address) = self.pointer(DynamicTag::STRTAB) else {
            return Ok(None);
        };
        let bytes = match self.value(DynamicTag::STRSZ) {
            Some(size) => self.bytes(address, size, "DT_STRTAB")?,
            None => self.slice(address, "DT_STRTAB")?,
        };
        Ok(Some(StringTable::parse(bytes)))
    }

    /// Return the dynamic string table and drop the other tables.
    pub(crate) fn into_strings(self) -> Result<Option<StringTable>> {
        self.strings()?;
        Ok(self.cache.strings.into_inner().flatten())
    }

    /// Return the names of the `DT_NEEDED` entries, in table order.
    pub(crate) fn needed_libraries(&self) -> Result<Vec<String>> {
        let Some(dynamic) = &self.dynamic else {
            return Ok(Vec::new());
        };
        let offsets: Vec<u64> = dynamic.get_all(DynamicTag::NEEDED).collect();
        if offsets.is_empty() {
            return Ok(Vec::new());
        }
        let strings = self.strings()?;
        offsets
            .into_iter()
            .map(|offset| dynamic_string(strings, offset))
            .collect()
    }

    /// Return the string of the first entry with the string tag `tag`.
    pub(crate) fn string_entry(&self, tag: DynamicTag) -> Result<Option<String>> {
        let Some(offset) = self.value(tag) else {
            return Ok(None);
        };
        dynamic_string(self.strings()?, offset).map(Some)
    }

    /// Return the class-sized words of the array at the pointer tag `address_tag` with the
    /// size tag `size_tag`, for example `DT_INIT_ARRAY` and `DT_INIT_ARRAYSZ`.
    pub(crate) fn array(&self, address_tag: DynamicTag, size_tag: DynamicTag) -> Result<Vec<u64>> {
        let Some(address) = self.pointer(address_tag) else {
            return Ok(Vec::new());
        };
        let structure = format!("{address_tag}");
        let size = self.required_size(size_tag, &structure)?;
        let encoding = self.encoding();
        let word = encoding.addr_size();
        let bytes = self.bytes(address, size, &structure)?;
        if !bytes.len().is_multiple_of(word) {
            return Err(Error::invalid_table(format!(
                "the array size {size} is not a multiple of {word}"
            ))
            .in_structure(structure)
            .at_address(address));
        }
        bytes
            .chunks_exact(word)
            .map(|chunk| encoding.read_addr(chunk, 0))
            .collect()
    }
}
