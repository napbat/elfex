//! The section table accessors of an [`ElfFile`]: the static symbol table, the relocation
//! sections and the section groups.

use super::ElfFile;
use crate::header::FileType;
use crate::prelude::*;
use crate::reloc::{Relocation, RelocationTable};
use crate::section::{SHF_INFO_LINK, SectionHeader, SectionType};
use crate::strtab::StringTable;
use crate::symbol::{
    NamedSymbol, SymbolNames, SymbolSectionIndexTable, SymbolTable, SymbolType, table_string,
};
use crate::{Error, Result};
use alloc::collections::btree_map::Entry;

#[cfg(test)]
mod tests;

/// The structure name of the static string table in an error context.
const SYMTAB_STRINGS: &str = "SHT_SYMTAB sh_link";

/// A relocation section (`SHT_REL` or `SHT_RELA`) of an [`ElfFile`] and its entries.
///
/// [`ElfFile::relocation_sections`] returns this type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RelocationSection {
    /// The index of the relocation section in the section header table.
    pub index: usize,
    /// The name of the relocation section, for example `.rela.text`.
    pub name: String,
    /// The index of the section that the relocations change (`sh_info`).
    ///
    /// The value is `Some` if `sh_info` is not 0, and the section has `SHF_INFO_LINK` or the
    /// file is a relocatable file (`ET_REL`). A malformed file can give an index that is out
    /// of range.
    pub target_section: Option<usize>,
    /// The index of the symbol table that the entries refer to (`sh_link`), or `None` if
    /// `sh_link` is 0. A malformed file can give an index that is out of range.
    pub symbol_table: Option<usize>,
    /// The relocation entries.
    pub table: RelocationTable,
}

/// A section group (`SHT_GROUP`) of an [`ElfFile`].
///
/// [`ElfFile::section_groups`] returns this type. The crate has no section group writer: write
/// the flags and the member indices as 32-bit words.
///
/// # Examples
///
/// ```
/// use elfex::section::{GRP_COMDAT, SHF_EXECINSTR, SHF_GROUP, SectionType};
/// use elfex::symbol::{NewSymbol, SymbolBinding, SymbolTableBuilder, SymbolType};
/// use elfex::{BuilderSection, ElfBuilder, Encoding, FileType};
///
/// let encoding = Encoding::ELF64_LE;
/// // The signature symbol "foo" is in section 1, the member of the group.
/// let mut builder = SymbolTableBuilder::new(encoding);
/// builder.add(NewSymbol::new("foo", SymbolBinding::GLOBAL, SymbolType::FUNC).with_shndx(1));
/// let symbols = builder.try_build()?;
/// let mut words = Vec::new();
/// encoding.write_u32(&mut words, GRP_COMDAT);
/// encoding.write_u32(&mut words, 1);
///
/// let table = |name: &str, section_type, data, link: &str, info| BuilderSection {
///     section_type,
///     link_name: Some(link.into()),
///     info,
///     ..BuilderSection::progbits(name, 0, data)
/// };
/// let (signature, locals) = (symbols.indices[0], symbols.first_non_local);
/// let file = ElfBuilder::new(encoding)
///     .file_type(FileType::REL)
///     .add_section(BuilderSection::progbits(".text.foo", SHF_EXECINSTR | SHF_GROUP, vec![0xc3]))
///     .add_section(table(".group", SectionType::GROUP, words, ".symtab", signature))
///     .add_section(table(".symtab", SectionType::SYMTAB, symbols.symbols, ".strtab", locals))
///     .add_section(BuilderSection {
///         section_type: SectionType::STRTAB,
///         ..BuilderSection::progbits(".strtab", 0, symbols.strings)
///     })
///     .try_build()?;
///
/// let groups = file.section_groups()?;
/// assert_eq!(groups.len(), 1);
/// assert_eq!(groups[0].flags, GRP_COMDAT);
/// assert_eq!(groups[0].signature.as_deref(), Some("foo"));
/// assert_eq!(groups[0].members, [1]);
/// # Ok::<(), elfex::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SectionGroup {
    /// The index of the `SHT_GROUP` section in the section header table.
    pub index: usize,
    /// The group flags: the first word of the section, for example
    /// [`GRP_COMDAT`](crate::section::GRP_COMDAT).
    pub flags: u32,
    /// The signature of the group: the name of the symbol `sh_info` in the symbol table
    /// `sh_link`. For an unnamed `STT_SECTION` symbol, this is the name of its section.
    ///
    /// The value is `None` if `sh_link` is not a symbol table, or if the table has no symbol
    /// `sh_info`.
    pub signature: Option<String>,
    /// The section indices of the members, in section order.
    pub members: Vec<u32>,
}

/// A symbol table section with its string table and its extended section indices.
struct LinkedSymbols {
    /// The symbols.
    symbols: SymbolTable,
    /// The string table that `sh_link` gives.
    strings: StringTable,
    /// The `SHT_SYMTAB_SHNDX` section that links to the symbol table.
    indices: Option<SymbolSectionIndexTable>,
}

impl LinkedSymbols {
    /// Return the tables that make a [`NamedSymbol`].
    fn names(&self) -> SymbolNames<'_> {
        SymbolNames {
            strings: Some(&self.strings),
            structure: SYMTAB_STRINGS,
            indices: self.indices.as_ref(),
            versym: None,
            map: None,
        }
    }
}

impl ElfFile {
    /// Return the first `SHT_SYMTAB` section as a symbol table.
    ///
    /// # Errors
    ///
    /// Return an error if the section is outside the file or does not parse.
    pub fn symbols(&self) -> Result<Option<SymbolTable>> {
        let Some(index) = self.file_section_index(SectionType::SYMTAB) else {
            return Ok(None);
        };
        self.symbol_table_at(index).map(Some)
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
        self.linked_strings(index).map(Some)
    }

    /// Return all symbols of the first `SHT_SYMTAB` section except the null symbol, with
    /// their names and sections.
    ///
    /// The `SHT_SYMTAB_SHNDX` section that links to the symbol table gives the section index
    /// of a symbol with `st_shndx` `SHN_XINDEX`. Static symbols have no version. Return an
    /// empty list if the file has no `SHT_SYMTAB` section.
    ///
    /// # Errors
    ///
    /// Return an error if the symbol table, its string table or its extended section index
    /// table is outside the file or does not parse, or if a name offset is outside the
    /// string table.
    pub fn symbol_list(&self) -> Result<Vec<NamedSymbol>> {
        let Some(index) = self.file_section_index(SectionType::SYMTAB) else {
            return Ok(Vec::new());
        };
        let linked = self.linked_symbols(index)?;
        let names = linked.names();
        linked
            .symbols
            .iter()
            .enumerate()
            .skip(1)
            .map(|(index, symbol)| names.describe(index, *symbol))
            .collect()
    }

    /// Find the symbol with the name `name`.
    ///
    /// The search looks at the first `SHT_SYMTAB` section first, in table order. If no
    /// static symbol has the name, the result is the result of
    /// [`Self::lookup_dynamic_symbol`].
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::symbol_list`] and
    /// [`Self::lookup_dynamic_symbol`].
    pub fn lookup_symbol(&self, name: &str) -> Result<Option<NamedSymbol>> {
        if let Some(index) = self.file_section_index(SectionType::SYMTAB) {
            let linked = self.linked_symbols(index)?;
            let found = linked
                .symbols
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, symbol)| {
                    symbol.name != 0
                        && linked
                            .strings
                            .get_bytes(symbol.name)
                            .is_ok_and(|bytes| bytes == name.as_bytes())
                });
            if let Some((index, symbol)) = found {
                return linked.names().describe(index, *symbol).map(Some);
            }
        }
        self.lookup_dynamic_symbol(name)
    }

    /// Return the file bytes of the first section named `name`, or `None` if the file has no
    /// such section.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::section_data`].
    pub fn section_data_by_name(&self, name: &str) -> Result<Option<&[u8]>> {
        match self.headers.section_by_name(name) {
            Some((index, _)) => self.section_data(index).map(Some),
            None => Ok(None),
        }
    }

    /// Parse the `SHT_REL` or `SHT_RELA` section at `index`.
    ///
    /// The entry size is `sh_entsize`, or the standard size if `sh_entsize` is 0.
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
            Relocation::size(encoding.class, with_addend)
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

    /// Return all `SHT_REL` and `SHT_RELA` sections with their entries, in section order.
    ///
    /// # Errors
    ///
    /// Return an error for the same conditions as [`Self::section_relocations`].
    pub fn relocation_sections(&self) -> Result<Vec<RelocationSection>> {
        let relocatable = self.file_type() == FileType::REL;
        self.section_headers()
            .iter()
            .enumerate()
            .filter(|(_, header)| {
                header.section_type == SectionType::REL || header.section_type == SectionType::RELA
            })
            .map(|(index, header)| {
                let info_is_section = relocatable || header.flags & SHF_INFO_LINK != 0;
                Ok(RelocationSection {
                    index,
                    name: self.section_name(index),
                    target_section: (info_is_section && header.info != 0)
                        .then(|| usize::try_from(header.info).ok())
                        .flatten(),
                    symbol_table: (header.link != 0)
                        .then(|| usize::try_from(header.link).ok())
                        .flatten(),
                    table: self.section_relocations(index)?,
                })
            })
            .collect()
    }

    /// Return all section groups (`SHT_GROUP` sections), in section order.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) if the size
    ///   of a group section is 0 or not a multiple of 4.
    /// - Return an error if a section is outside the file, if the signature symbol table or
    ///   its string table does not parse, or if the name offset of the signature is outside
    ///   the string table.
    pub fn section_groups(&self) -> Result<Vec<SectionGroup>> {
        let encoding = self.encoding();
        let mut tables: BTreeMap<usize, Option<LinkedSymbols>> = BTreeMap::new();
        let mut groups = Vec::new();
        for (index, header) in self.section_headers().iter().enumerate() {
            if header.section_type != SectionType::GROUP {
                continue;
            }
            let data = self.section_data(index)?;
            if data.is_empty() || !data.len().is_multiple_of(4) {
                return Err(Error::invalid_section(format!(
                    "the SHT_GROUP size {} is 0 or not a multiple of 4",
                    data.len()
                ))
                .in_structure(format!("section {index}")));
            }
            let mut words = data
                .as_chunks::<4>()
                .0
                .iter()
                .map(|chunk| encoding.read_u32(chunk, 0));
            let flags = words.next().transpose()?.unwrap_or(0);
            let members = words.collect::<Result<Vec<_>>>()?;
            groups.push(SectionGroup {
                index,
                flags,
                signature: self.group_signature(header, &mut tables)?,
                members,
            });
        }
        Ok(groups)
    }

    /// Return the signature of the group section `header`. `tables` holds the symbol tables
    /// that the function already parsed.
    fn group_signature(
        &self,
        header: &SectionHeader,
        tables: &mut BTreeMap<usize, Option<LinkedSymbols>>,
    ) -> Result<Option<String>> {
        let Ok(link) = usize::try_from(header.link) else {
            return Ok(None);
        };
        let linked = match tables.entry(link) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let is_symbols = self.section_headers().get(link).is_some_and(|table| {
                    table.section_type == SectionType::SYMTAB
                        || table.section_type == SectionType::DYNSYM
                });
                let linked = if is_symbols {
                    Some(self.linked_symbols(link)?)
                } else {
                    None
                };
                entry.insert(linked)
            }
        };
        let Some(linked) = linked else {
            return Ok(None);
        };
        let Some((index, symbol)) = usize::try_from(header.info)
            .ok()
            .and_then(|index| Some((index, *linked.symbols.get(index)?)))
        else {
            return Ok(None);
        };
        if symbol.name == 0 && symbol.symbol_type() == SymbolType::SECTION {
            return Ok(symbol
                .section_index(index, linked.indices.as_ref())
                .and_then(|section| usize::try_from(section).ok())
                .and_then(|section| self.section_names().get(section))
                .cloned());
        }
        table_string(Some(&linked.strings), symbol.name, SYMTAB_STRINGS).map(Some)
    }

    /// Return the index of the `SHT_SYMTAB_SHNDX` section that links to the symbol table at
    /// `symtab`, if it has file bytes.
    pub(super) fn symbol_index_section(&self, symtab: usize) -> Option<usize> {
        self.section_headers().iter().position(|header| {
            header.section_type == SectionType::SYMTAB_SHNDX
                && header.has_file_data()
                && usize::try_from(header.link).is_ok_and(|link| link == symtab)
        })
    }

    /// Return the name of the section at `index`, or an empty string.
    fn section_name(&self, index: usize) -> String {
        self.section_names().get(index).cloned().unwrap_or_default()
    }

    /// Parse the symbol table section at `index`.
    fn symbol_table_at(&self, index: usize) -> Result<SymbolTable> {
        let header = self.section_header(index)?;
        let structure = header.section_type.name().unwrap_or("symbol table");
        SymbolTable::parse_with_entsize(self.section_data(index)?, self.encoding(), header.entsize)
            .map_err(|error| error.in_structure(structure))
    }

    /// Return the string table that `sh_link` of the section at `index` gives.
    fn linked_strings(&self, index: usize) -> Result<StringTable> {
        // An index that does not fit in `usize` is out of range, and `section_data` rejects it.
        let link = usize::try_from(self.section_header(index)?.link).unwrap_or(usize::MAX);
        self.section_data(link)
            .map(StringTable::parse)
            .map_err(|error| error.in_structure(SYMTAB_STRINGS))
    }

    /// Parse the symbol table section at `index`, its string table and its extended section
    /// indices.
    fn linked_symbols(&self, index: usize) -> Result<LinkedSymbols> {
        let indices = self
            .symbol_index_section(index)
            .map(|shndx| {
                SymbolSectionIndexTable::parse(self.section_data(shndx)?, self.encoding())
                    .map_err(|error| error.in_structure("SHT_SYMTAB_SHNDX"))
            })
            .transpose()?;
        Ok(LinkedSymbols {
            symbols: self.symbol_table_at(index)?,
            strings: self.linked_strings(index)?,
            indices,
        })
    }
}
