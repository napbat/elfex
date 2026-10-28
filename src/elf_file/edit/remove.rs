//! Remove a section from an [`ElfFile`] and renumber the section indices in the headers, the
//! symbol tables and the section groups.

use crate::elf_file::ElfFile;
use crate::endian::Class;
use crate::group::GroupTable;
use crate::prelude::*;
use crate::section::{
    SHF_GROUP, SHF_INFO_LINK, SHN_LORESERVE, SHN_UNDEF, SHN_XINDEX, SectionHeader, SectionType,
};
use crate::symbol::{Symbol, SymbolSectionIndexTable, SymbolTable, SymbolType};
use crate::{Error, Result};

/// A field that the removal changes in the file bytes.
#[derive(Debug, Clone, Copy)]
enum Patch {
    /// The `st_shndx` field of a symbol, at a file offset.
    Shndx { offset: usize, value: u16 },
    /// An `SHT_SYMTAB_SHNDX` entry, at a file offset.
    Extended { offset: usize, value: u32 },
}

/// The changes that remove a section. The method collects all changes before it changes the
/// file, so that a failed check leaves the file as it was.
#[derive(Debug, Default)]
struct Removal {
    /// The symbol fields to write.
    patches: Vec<Patch>,
    /// The `STT_SECTION` symbols of the removed section: the index of the symbol table and
    /// the symbol index.
    section_symbols: Vec<(usize, u32)>,
    /// The groups to write again: the index of the group section and its new data.
    groups: Vec<(usize, Vec<u8>)>,
    /// The members of a removed group. They lose `SHF_GROUP`.
    ungrouped: Vec<usize>,
}

/// The section to remove and the index limit for the renumbering.
#[derive(Debug, Clone, Copy)]
struct Target {
    /// The index of the removed section.
    index: usize,
    /// The index of the removed section as a 32-bit value.
    value: u32,
    /// The number of sections before the removal. A larger index is not valid, and the
    /// method does not change it.
    limit: u32,
}

impl Target {
    /// Return the new value of section index `value`, or `None` if it does not change.
    const fn renumber(self, value: u32) -> Option<u32> {
        if value > self.value && value < self.limit {
            Some(value - 1)
        } else {
            None
        }
    }
}

impl ElfFile {
    /// Remove the section at `index` and renumber the sections after it.
    ///
    /// The method decrements each section index above `index` in these items:
    ///
    /// - `sh_link` of each section, and `sh_info` of each section with `SHF_INFO_LINK` and of
    ///   each `SHT_REL` or `SHT_RELA` section.
    /// - `e_shstrndx`.
    /// - `st_shndx` of each symbol in each `SHT_SYMTAB` and `SHT_DYNSYM` section. For a symbol
    ///   with `SHN_XINDEX`, the method changes the `SHT_SYMTAB_SHNDX` entry.
    /// - The member list of each `SHT_GROUP` section. The method also removes the section from
    ///   the member list of its group, and decreases `sh_size` of the group.
    ///
    /// The indices only decrease. Thus no index becomes a reserved value (`SHN_LORESERVE` or
    /// more), and an index in a `SHT_SYMTAB_SHNDX` entry stays there. The method writes the
    /// symbol tables and the groups in place. No other section data holds a section index,
    /// so for example the dynamic table (`.dynamic`) does not change.
    ///
    /// An `STT_SECTION` symbol of the removed section gets `SHN_UNDEF`. No other symbol can be
    /// in the removed section. If the removed section is a `SHT_GROUP` section, its members
    /// lose `SHF_GROUP`.
    ///
    /// The data bytes stay in the file. If no other section, no segment and no header table
    /// uses them, the method sets them to zero.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidSection`](crate::ErrorKind::InvalidSection) in these
    /// conditions:
    ///
    /// - `index` is 0 or out of range.
    /// - The section is the section name string table (`e_shstrndx`).
    /// - Another section names the section in `sh_link`, or in `sh_info` as a section index.
    /// - A symbol that is not an `STT_SECTION` symbol is in the section.
    /// - A relocation entry or the signature of a group refers to an `STT_SECTION` symbol of
    ///   the section.
    /// - A symbol has `SHN_XINDEX`, and no `SHT_SYMTAB_SHNDX` entry gives its index after the
    ///   removal.
    ///
    /// Return an error if a symbol table, a `SHT_SYMTAB_SHNDX` section, a group section or a
    /// relocation section that the method reads is outside the file or does not parse. On
    /// error, the file does not change.
    pub fn remove_section(&mut self, index: usize) -> Result<()> {
        let count = self.headers.section_headers.len();
        if index == 0 || index >= count {
            return Err(Error::invalid_section(format!(
                "cannot remove section {index}: the index is 0 or out of range"
            )));
        }
        let shstrndx = self.shstrndx();
        if shstrndx == Some(index) {
            return Err(Error::invalid_section(
                "cannot remove the section name string table",
            ));
        }
        let target = Target {
            index,
            value: u32::try_from(index)
                .map_err(|_| Error::invalid_section("the section index is too large"))?,
            limit: u32::try_from(count).unwrap_or(u32::MAX),
        };
        self.check_links(target)?;
        let mut removal = Removal::default();
        self.plan_groups(target, &mut removal)?;
        self.plan_symbols(target, &mut removal)?;
        self.check_section_symbols(target, &removal.section_symbols)?;
        self.apply_removal(removal)?;

        let removed = self.headers.section_headers.remove(index);
        if index < self.headers.section_names.len() {
            self.headers.section_names.remove(index);
        }
        for header in &mut self.headers.section_headers {
            if let Some(link) = target.renumber(header.link) {
                header.link = link;
            }
            if info_is_section(header)
                && let Some(info) = target.renumber(header.info)
            {
                header.info = info;
            }
        }
        if let Some(shstrndx) = shstrndx.filter(|shstrndx| *shstrndx > index && *shstrndx < count) {
            self.set_shstrndx(shstrndx - 1)?;
        }
        if let Some(range) = removed.file_range() {
            self.zero_if_unused(&range, None);
        }
        Ok(())
    }

    /// Return an error if another section names the removed section in `sh_link`, or in
    /// `sh_info` as a section index.
    fn check_links(&self, target: Target) -> Result<()> {
        let linked = self
            .headers
            .section_headers
            .iter()
            .enumerate()
            .any(|(other, header)| {
                other != target.index
                    && (header.link == target.value
                        || (info_is_section(header) && header.info == target.value))
            });
        if linked {
            return Err(Error::invalid_section(format!(
                "cannot remove section {}: another section links to it",
                target.index
            )));
        }
        Ok(())
    }

    /// Collect the new member lists of the `SHT_GROUP` sections. If the removed section is a
    /// group, collect its members.
    fn plan_groups(&self, target: Target, removal: &mut Removal) -> Result<()> {
        let encoding = self.encoding();
        for (group, header) in self.headers.section_headers.iter().enumerate() {
            if header.section_type != SectionType::GROUP {
                continue;
            }
            let table = GroupTable::parse(self.section_bytes(header)?, encoding)
                .map_err(|error| error.in_structure(format!("section {group}")))?;
            if group == target.index {
                removal.ungrouped.extend(
                    table
                        .members
                        .iter()
                        .filter(|member| **member != target.value && **member < target.limit)
                        .filter_map(|member| usize::try_from(*member).ok()),
                );
                continue;
            }
            let members: Vec<u32> = table
                .members
                .iter()
                .filter(|member| **member != target.value)
                .map(|member| target.renumber(*member).unwrap_or(*member))
                .collect();
            if members != table.members {
                let table = GroupTable {
                    flags: table.flags,
                    members,
                };
                removal.groups.push((group, table.write(encoding)));
            }
        }
        Ok(())
    }

    /// Collect the new `st_shndx` values and `SHT_SYMTAB_SHNDX` entries of all symbol tables.
    fn plan_symbols(&self, target: Target, removal: &mut Removal) -> Result<()> {
        let encoding = self.encoding();
        for (table, header) in self.headers.section_headers.iter().enumerate() {
            let is_symbols = header.section_type == SectionType::SYMTAB
                || header.section_type == SectionType::DYNSYM;
            if table == target.index || !is_symbols || !header.has_file_data() {
                continue;
            }
            let structure = || format!("section {table}");
            let symbols = SymbolTable::parse_with_entsize(
                self.section_bytes(header)?,
                encoding,
                header.entsize,
            )
            .map_err(|error| error.in_structure(structure()))?;
            // The parser accepted the entry size and the file range, so both fit in `usize`.
            let entsize = match header.entsize {
                0 => Symbol::size(encoding.class),
                size => usize::try_from(size).map_err(|_| too_large())?,
            };
            let start = usize::try_from(header.offset).map_err(|_| too_large())?;
            let extended = self.extended_indices(table, target.index)?;
            for (position, symbol) in symbols.iter().enumerate() {
                let field = position
                    .checked_mul(entsize)
                    .and_then(|offset| offset.checked_add(start))
                    .and_then(|offset| offset.checked_add(shndx_field_offset(encoding.class)))
                    .ok_or_else(too_large)?;
                let entry = SymbolEntry {
                    table,
                    position,
                    symbol,
                    field,
                };
                plan_symbol(target, &entry, extended.as_ref(), removal)?;
            }
        }
        Ok(())
    }

    /// Return the `SHT_SYMTAB_SHNDX` section of the symbol table at `table` and the file
    /// offset of its data. Return `None` if the table has no such section, or if the section
    /// is the removed section.
    fn extended_indices(
        &self,
        table: usize,
        removed: usize,
    ) -> Result<Option<(usize, SymbolSectionIndexTable)>> {
        let Some(shndx) = self
            .symbol_index_section(table)
            .filter(|shndx| *shndx != removed)
        else {
            return Ok(None);
        };
        let header = self.section_header(shndx)?;
        let indices = SymbolSectionIndexTable::parse(self.section_bytes(header)?, self.encoding())
            .map_err(|error| error.in_structure("SHT_SYMTAB_SHNDX"))?;
        let start = usize::try_from(header.offset).map_err(|_| too_large())?;
        Ok(Some((start, indices)))
    }

    /// Return an error if a relocation entry or a group signature refers to an `STT_SECTION`
    /// symbol of the removed section.
    fn check_section_symbols(&self, target: Target, symbols: &[(usize, u32)]) -> Result<()> {
        for (other, header) in self.headers.section_headers.iter().enumerate() {
            let link = usize::try_from(header.link).unwrap_or(usize::MAX);
            let is_relocations =
                header.section_type == SectionType::REL || header.section_type == SectionType::RELA;
            let is_group = header.section_type == SectionType::GROUP;
            if other == target.index
                || !(is_relocations || is_group)
                || !symbols.iter().any(|(table, _)| *table == link)
            {
                continue;
            }
            let refers = |symbol: u32| symbols.contains(&(link, symbol));
            let used = if is_group {
                refers(header.info)
            } else {
                self.section_relocations(other)?
                    .iter()
                    .any(|relocation| refers(relocation.symbol))
            };
            if used {
                return Err(Error::invalid_section(format!(
                    "cannot remove section {}: section {other} refers to its STT_SECTION symbol",
                    target.index
                )));
            }
        }
        Ok(())
    }

    /// Write the collected changes to the symbol tables and the groups.
    fn apply_removal(&mut self, removal: Removal) -> Result<()> {
        let encoding = self.encoding();
        for patch in removal.patches {
            match patch {
                Patch::Shndx { offset, value } => {
                    encoding.put_u16(&mut self.data, offset, value)?;
                }
                Patch::Extended { offset, value } => {
                    encoding.put_u32(&mut self.data, offset, value)?;
                }
            }
        }
        for (group, data) in removal.groups {
            self.set_section_data(group, data)?;
        }
        for member in removal.ungrouped {
            if let Some(header) = self.headers.section_headers.get_mut(member) {
                header.flags &= !SHF_GROUP;
            }
        }
        Ok(())
    }
}

/// A symbol of a symbol table that [`plan_symbol`] checks.
struct SymbolEntry<'a> {
    /// The index of the symbol table section.
    table: usize,
    /// The index of the symbol in the table.
    position: usize,
    /// The symbol.
    symbol: &'a Symbol,
    /// The file offset of the `st_shndx` field.
    field: usize,
}

/// Collect the changes for one symbol. `extended` is the `SHT_SYMTAB_SHNDX` section of the
/// table and the file offset of its data.
fn plan_symbol(
    target: Target,
    entry: &SymbolEntry<'_>,
    extended: Option<&(usize, SymbolSectionIndexTable)>,
    removal: &mut Removal,
) -> Result<()> {
    let shndx = entry.symbol.shndx;
    if shndx == SHN_XINDEX {
        let missing = || {
            Error::invalid_section(format!(
                "symbol {} of section {} has SHN_XINDEX and no SHT_SYMTAB_SHNDX entry",
                entry.position, entry.table
            ))
        };
        let (start, indices) = extended.ok_or_else(missing)?;
        let value = indices.get(entry.position).ok_or_else(missing)?;
        let offset = entry
            .position
            .checked_mul(4)
            .and_then(|offset| offset.checked_add(*start))
            .ok_or_else(too_large)?;
        if value == target.value {
            check_section_symbol(target, entry, removal)?;
            let field = entry.field;
            removal.patches.push(Patch::Shndx {
                offset: field,
                value: SHN_UNDEF,
            });
            removal.patches.push(Patch::Extended { offset, value: 0 });
        } else if let Some(value) = target.renumber(value) {
            removal.patches.push(Patch::Extended { offset, value });
        }
        return Ok(());
    }
    if shndx == SHN_UNDEF || shndx >= SHN_LORESERVE {
        return Ok(());
    }
    let value = if u32::from(shndx) == target.value {
        check_section_symbol(target, entry, removal)?;
        SHN_UNDEF
    } else if let Some(value) = target.renumber(u32::from(shndx)) {
        // The new value is smaller than `shndx`, so it fits in 16 bits.
        u16::try_from(value).map_err(|_| too_large())?
    } else {
        return Ok(());
    };
    removal.patches.push(Patch::Shndx {
        offset: entry.field,
        value,
    });
    Ok(())
}

/// Return an error if the symbol in the removed section is not an `STT_SECTION` symbol. Else
/// record the symbol.
fn check_section_symbol(
    target: Target,
    entry: &SymbolEntry<'_>,
    removal: &mut Removal,
) -> Result<()> {
    if entry.symbol.symbol_type() != SymbolType::SECTION {
        return Err(Error::invalid_section(format!(
            "cannot remove section {}: symbol {} of section {} is in it",
            target.index, entry.position, entry.table
        )));
    }
    let symbol = u32::try_from(entry.position).map_err(|_| too_large())?;
    removal.section_symbols.push((entry.table, symbol));
    Ok(())
}

/// Return the offset of `st_shndx` in `Elf32_Sym` or `Elf64_Sym`.
const fn shndx_field_offset(class: Class) -> usize {
    match class {
        Class::Elf32 => 14,
        Class::Elf64 => 6,
    }
}

/// Return the error for an offset that does not fit in `usize`.
fn too_large() -> Error {
    Error::value_out_of_range("a symbol table offset is too large")
}

/// Return `true` if `sh_info` of `header` holds a section index: the section has
/// `SHF_INFO_LINK`, or it is a `SHT_REL` or `SHT_RELA` section.
fn info_is_section(header: &SectionHeader) -> bool {
    header.flags & SHF_INFO_LINK != 0
        || header.section_type == SectionType::REL
        || header.section_type == SectionType::RELA
}
