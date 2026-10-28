//! The dynamic table (`.dynamic`, `PT_DYNAMIC`): `Elf32_Dyn` and `Elf64_Dyn` entries.

mod tags;
#[cfg(test)]
mod tests;

pub use tags::*;

use crate::endian::{Class, Encoding};
use crate::prelude::*;
use crate::strtab::StringTable;
use crate::{Error, Result};

/// One dynamic table entry: `Elf32_Dyn` or `Elf64_Dyn`.
///
/// `d_tag` is a class-sized signed value (`Elf32_Sword` or `Elf64_Sxword`). An ELF32 tag
/// sign-extends to `i64`. `d_un` is a class-sized unsigned value: a virtual address
/// (`d_ptr`) or a value (`d_val`), as the tag tells.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct DynamicEntry {
    /// The `d_tag` field: the entry type.
    pub tag: DynamicTag,
    /// The `d_un` field: a virtual address or a value.
    pub value: u64,
}

impl DynamicEntry {
    /// Make an entry from a tag and a value.
    #[must_use]
    pub const fn new(tag: DynamicTag, value: u64) -> Self {
        Self { tag, value }
    }

    /// Return the size in bytes of one entry: 8 for ELF32, 16 for ELF64.
    #[must_use]
    pub const fn size(class: Class) -> usize {
        match class {
            Class::Elf32 => 8,
            Class::Elf64 => 16,
        }
    }

    /// Parse one entry from the start of `bytes`.
    ///
    /// # Errors
    ///
    /// Return `BufferTooSmall` if `bytes` is shorter than one entry.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        let tag = encoding
            .read_signed_addr(bytes, 0)
            .map_err(|e| e.in_structure(dyn_name(encoding)))?;
        let value = encoding
            .read_addr(bytes, encoding.addr_size())
            .map_err(|e| e.in_structure(dyn_name(encoding)))?;
        Ok(Self {
            tag: DynamicTag(tag),
            value,
        })
    }

    /// Append the entry to `out`.
    ///
    /// # Errors
    ///
    /// Return `ValueOutOfRange` if the class is ELF32 and the tag or the value does not fit
    /// in 32 bits.
    pub fn write(&self, out: &mut Vec<u8>, encoding: Encoding) -> Result<()> {
        encoding
            .write_signed_addr(out, self.tag.0)
            .map_err(|e| e.in_structure(dyn_name(encoding)))?;
        encoding
            .write_addr(out, self.value)
            .map_err(|e| e.in_structure(dyn_name(encoding)))
    }
}

/// Return the spec structure name for the class.
const fn dyn_name(encoding: Encoding) -> &'static str {
    if encoding.is_64bit() {
        "Elf64_Dyn"
    } else {
        "Elf32_Dyn"
    }
}

/// The dynamic table: the entries of `.dynamic` or `PT_DYNAMIC`.
///
/// `entries` does not contain the terminating `DT_NULL` entry. [`DynamicTable::write`] adds it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DynamicTable {
    /// The entries before the first `DT_NULL`.
    pub entries: Vec<DynamicEntry>,
}

impl DynamicTable {
    /// Make an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Parse a dynamic table from `bytes`.
    ///
    /// Parsing stops at the first `DT_NULL` entry and ignores the bytes after it. If no
    /// `DT_NULL` entry is present, the table holds all complete entries in `bytes`.
    ///
    /// # Errors
    ///
    /// Return an error only if an entry cannot be read (this does not occur for complete entries).
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        Self::parse_with_count(bytes, encoding).map(|(table, _)| table)
    }

    /// Parse a dynamic table from `bytes` and return the number of entries read.
    ///
    /// The count includes the terminating `DT_NULL` entry if one is present. Lossless callers
    /// use it to know the size of the table in `bytes` (`count * DynamicEntry::size(class)`).
    ///
    /// # Errors
    ///
    /// Return an error only if an entry cannot be read (this does not occur for complete entries).
    pub fn parse_with_count(bytes: &[u8], encoding: Encoding) -> Result<(Self, usize)> {
        let size = DynamicEntry::size(encoding.class);
        let mut entries = Vec::new();
        let mut count = 0;
        for chunk in bytes.chunks_exact(size) {
            let entry = DynamicEntry::parse(chunk, encoding)
                .map_err(|e| e.at_offset(u64::try_from(count * size).unwrap_or(u64::MAX)))?;
            count += 1;
            if entry.tag == DynamicTag::NULL {
                break;
            }
            entries.push(entry);
        }
        Ok((Self { entries }, count))
    }

    /// Serialize the entries and one terminating `DT_NULL` entry.
    ///
    /// # Errors
    ///
    /// Return `ValueOutOfRange` if the class is ELF32 and a tag or value does not fit in 32 bits.
    pub fn write(&self, encoding: Encoding) -> Result<Vec<u8>> {
        let size = DynamicEntry::size(encoding.class);
        let mut out = Vec::with_capacity((self.entries.len() + 1).saturating_mul(size));
        for entry in &self.entries {
            entry.write(&mut out, encoding)?;
        }
        DynamicEntry::default().write(&mut out, encoding)?;
        Ok(out)
    }

    /// Serialize the table and fill it to `size_in_bytes` with `DT_NULL` entries.
    ///
    /// Use it to rewrite a table in place. Bytes after the last complete entry are zero.
    ///
    /// # Errors
    ///
    /// Return `BufferTooSmall` if the entries and one `DT_NULL` entry do not fit in
    /// `size_in_bytes`, and `ValueOutOfRange` as [`DynamicTable::write`] does.
    pub fn write_padded(&self, encoding: Encoding, size_in_bytes: usize) -> Result<Vec<u8>> {
        let mut out = self.write(encoding)?;
        if out.len() > size_in_bytes {
            return Err(
                Error::buffer_too_small(out.len(), size_in_bytes).in_structure(dyn_name(encoding))
            );
        }
        out.resize(size_in_bytes, 0);
        Ok(out)
    }

    /// Return the value of the first entry with `tag`.
    #[must_use]
    pub fn get(&self, tag: DynamicTag) -> Option<u64> {
        self.entries.iter().find(|e| e.tag == tag).map(|e| e.value)
    }

    /// Return the values of all entries with `tag`, in table order.
    pub fn get_all(&self, tag: DynamicTag) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .filter(move |e| e.tag == tag)
            .map(|e| e.value)
    }

    /// Return `true` if an entry with `tag` is present.
    #[must_use]
    pub fn contains(&self, tag: DynamicTag) -> bool {
        self.entries.iter().any(|e| e.tag == tag)
    }

    /// Set the value of the first entry with `tag`, or append a new entry.
    pub fn set(&mut self, tag: DynamicTag, value: u64) {
        match self.entries.iter_mut().find(|e| e.tag == tag) {
            Some(entry) => entry.value = value,
            None => self.entries.push(DynamicEntry::new(tag, value)),
        }
    }

    /// Remove all entries with `tag` and return the number of removed entries.
    pub fn remove(&mut self, tag: DynamicTag) -> usize {
        let before = self.entries.len();
        self.entries.retain(|e| e.tag != tag);
        before - self.entries.len()
    }

    /// Append an entry.
    pub fn push(&mut self, entry: DynamicEntry) {
        self.entries.push(entry);
    }

    /// Insert an entry at `index`, or append it if `index` is after the end.
    pub fn insert(&mut self, index: usize, entry: DynamicEntry) {
        let index = index.min(self.entries.len());
        self.entries.insert(index, entry);
    }

    /// Return the string table offsets of all `DT_NEEDED` entries.
    #[must_use]
    pub fn needed_offsets(&self) -> Vec<u64> {
        self.get_all(DynamicTag::NEEDED).collect()
    }

    /// Return the string table offset of `DT_SONAME`.
    #[must_use]
    pub fn soname_offset(&self) -> Option<u64> {
        self.get(DynamicTag::SONAME)
    }

    /// Return the string table offset of `DT_RPATH`.
    #[must_use]
    pub fn rpath_offset(&self) -> Option<u64> {
        self.get(DynamicTag::RPATH)
    }

    /// Return the string table offset of `DT_RUNPATH`.
    #[must_use]
    pub fn runpath_offset(&self) -> Option<u64> {
        self.get(DynamicTag::RUNPATH)
    }

    /// Return the `DT_FLAGS` value, or 0 if it is absent.
    #[must_use]
    pub fn flags(&self) -> u64 {
        self.get(DynamicTag::FLAGS).unwrap_or(0)
    }

    /// Return the `DT_FLAGS_1` value, or 0 if it is absent.
    #[must_use]
    pub fn flags_1(&self) -> u64 {
        self.get(DynamicTag::FLAGS_1).unwrap_or(0)
    }

    /// Return `true` if `DT_BIND_NOW`, `DF_BIND_NOW` or `DF_1_NOW` is present.
    #[must_use]
    pub fn is_bind_now(&self) -> bool {
        self.contains(DynamicTag::BIND_NOW)
            || self.flags() & DF_BIND_NOW != 0
            || self.flags_1() & DF_1_NOW != 0
    }

    /// Return `true` if `DF_1_PIE` is set.
    #[must_use]
    pub fn is_pie(&self) -> bool {
        self.flags_1() & DF_1_PIE != 0
    }

    /// Return the names of the needed libraries (`DT_NEEDED`) from `strings`.
    ///
    /// # Errors
    ///
    /// Return an error if an offset is not in `strings` or a name is not valid UTF-8.
    pub fn needed<'a>(&self, strings: &'a StringTable) -> Result<Vec<&'a str>> {
        self.get_all(DynamicTag::NEEDED)
            .map(|offset| string_at(strings, offset))
            .collect()
    }

    /// Return the shared object name (`DT_SONAME`) from `strings`.
    ///
    /// # Errors
    ///
    /// Return an error if the offset is not in `strings` or the name is not valid UTF-8.
    pub fn soname<'a>(&self, strings: &'a StringTable) -> Result<Option<&'a str>> {
        self.soname_offset()
            .map(|o| string_at(strings, o))
            .transpose()
    }

    /// Return the library search path (`DT_RPATH`) from `strings`.
    ///
    /// # Errors
    ///
    /// Return an error if the offset is not in `strings` or the path is not valid UTF-8.
    pub fn rpath<'a>(&self, strings: &'a StringTable) -> Result<Option<&'a str>> {
        self.rpath_offset()
            .map(|o| string_at(strings, o))
            .transpose()
    }

    /// Return the library search path (`DT_RUNPATH`) from `strings`.
    ///
    /// # Errors
    ///
    /// Return an error if the offset is not in `strings` or the path is not valid UTF-8.
    pub fn runpath<'a>(&self, strings: &'a StringTable) -> Result<Option<&'a str>> {
        self.runpath_offset()
            .map(|o| string_at(strings, o))
            .transpose()
    }

    /// Collect the common values of the table in a [`DynamicInfo`].
    #[must_use]
    pub fn info(&self) -> DynamicInfo {
        let flags = self.flags();
        DynamicInfo {
            strtab: self.get(DynamicTag::STRTAB),
            strsz: self.get(DynamicTag::STRSZ),
            symtab: self.get(DynamicTag::SYMTAB),
            syment: self.get(DynamicTag::SYMENT),
            hash: self.get(DynamicTag::HASH),
            gnu_hash: self.get(DynamicTag::GNU_HASH),
            rela: self.get(DynamicTag::RELA),
            relasz: self.get(DynamicTag::RELASZ),
            relaent: self.get(DynamicTag::RELAENT),
            rel: self.get(DynamicTag::REL),
            relsz: self.get(DynamicTag::RELSZ),
            relent: self.get(DynamicTag::RELENT),
            relr: self.get(DynamicTag::RELR),
            relrsz: self.get(DynamicTag::RELRSZ),
            relrent: self.get(DynamicTag::RELRENT),
            jmprel: self.get(DynamicTag::JMPREL),
            pltrelsz: self.get(DynamicTag::PLTRELSZ),
            pltrel: self
                .get(DynamicTag::PLTREL)
                .map(|v| DynamicTag(i64::try_from(v).unwrap_or(-1))),
            pltgot: self.get(DynamicTag::PLTGOT),
            init: self.get(DynamicTag::INIT),
            fini: self.get(DynamicTag::FINI),
            init_array: self.get(DynamicTag::INIT_ARRAY),
            init_arraysz: self.get(DynamicTag::INIT_ARRAYSZ),
            fini_array: self.get(DynamicTag::FINI_ARRAY),
            fini_arraysz: self.get(DynamicTag::FINI_ARRAYSZ),
            preinit_array: self.get(DynamicTag::PREINIT_ARRAY),
            preinit_arraysz: self.get(DynamicTag::PREINIT_ARRAYSZ),
            versym: self.get(DynamicTag::VERSYM),
            verdef: self.get(DynamicTag::VERDEF),
            verdefnum: self.get(DynamicTag::VERDEFNUM),
            verneed: self.get(DynamicTag::VERNEED),
            verneednum: self.get(DynamicTag::VERNEEDNUM),
            symtab_shndx: self.get(DynamicTag::SYMTAB_SHNDX),
            android_rel: self.get(DynamicTag::ANDROID_REL),
            android_relsz: self.get(DynamicTag::ANDROID_RELSZ),
            android_rela: self.get(DynamicTag::ANDROID_RELA),
            android_relasz: self.get(DynamicTag::ANDROID_RELASZ),
            flags,
            flags_1: self.flags_1(),
            textrel: self.contains(DynamicTag::TEXTREL) || flags & DF_TEXTREL != 0,
            bind_now: self.is_bind_now(),
        }
    }
}

/// Get the string at a 64-bit offset in `strings`.
fn string_at(strings: &StringTable, offset: u64) -> Result<&str> {
    let offset = u32::try_from(offset)
        .map_err(|_| Error::invalid_table("dynamic string offset does not fit in 32 bits"))?;
    strings.get(offset)
}

/// The common values of a dynamic table, from [`DynamicTable::info`].
///
/// Each `Option` field is the value of the first entry with the tag, or `None` if the tag is
/// absent. Address fields are virtual addresses; size fields are in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DynamicInfo {
    /// `DT_STRTAB`: virtual address of the dynamic string table.
    pub strtab: Option<u64>,
    /// `DT_STRSZ`: size of the dynamic string table.
    pub strsz: Option<u64>,
    /// `DT_SYMTAB`: virtual address of the dynamic symbol table.
    pub symtab: Option<u64>,
    /// `DT_SYMENT`: size of one dynamic symbol.
    pub syment: Option<u64>,
    /// `DT_HASH`: virtual address of the SysV hash table.
    pub hash: Option<u64>,
    /// `DT_GNU_HASH`: virtual address of the GNU hash table.
    pub gnu_hash: Option<u64>,
    /// `DT_RELA`: virtual address of the `RELA` relocations.
    pub rela: Option<u64>,
    /// `DT_RELASZ`: size of the `RELA` relocations.
    pub relasz: Option<u64>,
    /// `DT_RELAENT`: size of one `RELA` relocation.
    pub relaent: Option<u64>,
    /// `DT_REL`: virtual address of the `REL` relocations.
    pub rel: Option<u64>,
    /// `DT_RELSZ`: size of the `REL` relocations.
    pub relsz: Option<u64>,
    /// `DT_RELENT`: size of one `REL` relocation.
    pub relent: Option<u64>,
    /// `DT_RELR`: virtual address of the `RELR` relocations.
    pub relr: Option<u64>,
    /// `DT_RELRSZ`: size of the `RELR` relocations.
    pub relrsz: Option<u64>,
    /// `DT_RELRENT`: size of one `RELR` entry.
    pub relrent: Option<u64>,
    /// `DT_JMPREL`: virtual address of the PLT relocations.
    pub jmprel: Option<u64>,
    /// `DT_PLTRELSZ`: size of the PLT relocations.
    pub pltrelsz: Option<u64>,
    /// `DT_PLTREL`: type of the PLT relocations (`DT_REL` or `DT_RELA`).
    pub pltrel: Option<DynamicTag>,
    /// `DT_PLTGOT`: virtual address of the PLT or GOT.
    pub pltgot: Option<u64>,
    /// `DT_INIT`: virtual address of the initialization function.
    pub init: Option<u64>,
    /// `DT_FINI`: virtual address of the termination function.
    pub fini: Option<u64>,
    /// `DT_INIT_ARRAY`: virtual address of the initialization array.
    pub init_array: Option<u64>,
    /// `DT_INIT_ARRAYSZ`: size of the initialization array.
    pub init_arraysz: Option<u64>,
    /// `DT_FINI_ARRAY`: virtual address of the termination array.
    pub fini_array: Option<u64>,
    /// `DT_FINI_ARRAYSZ`: size of the termination array.
    pub fini_arraysz: Option<u64>,
    /// `DT_PREINIT_ARRAY`: virtual address of the pre-initialization array.
    pub preinit_array: Option<u64>,
    /// `DT_PREINIT_ARRAYSZ`: size of the pre-initialization array.
    pub preinit_arraysz: Option<u64>,
    /// `DT_VERSYM`: virtual address of the symbol version table.
    pub versym: Option<u64>,
    /// `DT_VERDEF`: virtual address of the version definitions.
    pub verdef: Option<u64>,
    /// `DT_VERDEFNUM`: number of version definitions.
    pub verdefnum: Option<u64>,
    /// `DT_VERNEED`: virtual address of the version requirements.
    pub verneed: Option<u64>,
    /// `DT_VERNEEDNUM`: number of version requirements.
    pub verneednum: Option<u64>,
    /// `DT_SYMTAB_SHNDX`: virtual address of the extended section index table.
    pub symtab_shndx: Option<u64>,
    /// `DT_ANDROID_REL`: virtual address of the Android packed `REL` relocations.
    pub android_rel: Option<u64>,
    /// `DT_ANDROID_RELSZ`: size of the Android packed `REL` relocations.
    pub android_relsz: Option<u64>,
    /// `DT_ANDROID_RELA`: virtual address of the Android packed `RELA` relocations.
    pub android_rela: Option<u64>,
    /// `DT_ANDROID_RELASZ`: size of the Android packed `RELA` relocations.
    pub android_relasz: Option<u64>,
    /// `DT_FLAGS`: `DF_*` flags, 0 if absent.
    pub flags: u64,
    /// `DT_FLAGS_1`: `DF_1_*` flags, 0 if absent.
    pub flags_1: u64,
    /// `true` if `DT_TEXTREL` or `DF_TEXTREL` is present.
    pub textrel: bool,
    /// `true` if `DT_BIND_NOW`, `DF_BIND_NOW` or `DF_1_NOW` is present.
    pub bind_now: bool,
}
