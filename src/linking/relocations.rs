//! Read the dynamic relocations and the symbol hash tables.

use super::{AddressSpace, DynamicRelocations, Linker};
use crate::dynamic::DynamicTag;
use crate::hash::{GnuHashTable, SysvHashTable, sysv_hash_entry_size};
use crate::prelude::*;
use crate::reloc::{Relocation, RelocationTable, RelrTable};
use crate::{Error, Result};

/// The dynamic tags of a `Rel` or `Rela` relocation table.
struct RelocationTags {
    /// The tag of the virtual address, for example `DT_RELA`.
    address: DynamicTag,
    /// The tag of the size in bytes, for example `DT_RELASZ`.
    size: DynamicTag,
    /// The tag of the entry size, for example `DT_RELAENT`.
    entry: DynamicTag,
    /// `true` for `Rela` entries.
    with_addend: bool,
}

impl<S: AddressSpace> Linker<'_, S> {
    /// Return the relocation tables that the dynamic table names.
    pub(crate) fn relocations(&self) -> Result<DynamicRelocations> {
        Ok(DynamicRelocations {
            rela: self.relocation_table(&RelocationTags {
                address: DynamicTag::RELA,
                size: DynamicTag::RELASZ,
                entry: DynamicTag::RELAENT,
                with_addend: true,
            })?,
            rel: self.relocation_table(&RelocationTags {
                address: DynamicTag::REL,
                size: DynamicTag::RELSZ,
                entry: DynamicTag::RELENT,
                with_addend: false,
            })?,
            plt: self.plt_relocations()?,
            relr: self.relr()?,
        })
    }

    /// Return the `Rel` or `Rela` table that `tags` names.
    fn relocation_table(&self, tags: &RelocationTags) -> Result<Option<RelocationTable>> {
        let Some(address) = self.pointer(tags.address) else {
            return Ok(None);
        };
        let structure = format!("{}", tags.address);
        let size = self.required_size(tags.size, &structure)?;
        let entsize = match self.value(tags.entry) {
            Some(entsize) => usize::try_from(entsize).map_err(|_| {
                Error::invalid_table(format!("{} {entsize} is too large", tags.entry))
                    .in_structure(structure.clone())
            })?,
            None => Relocation::size(self.encoding().class, tags.with_addend),
        };
        self.parse_relocations(address, size, entsize, tags.with_addend, &structure)
            .map(Some)
    }

    /// Return the PLT relocations at `DT_JMPREL`.
    fn plt_relocations(&self) -> Result<Option<RelocationTable>> {
        let Some(address) = self.pointer(DynamicTag::JMPREL) else {
            return Ok(None);
        };
        let structure = "DT_JMPREL";
        let size = self.required_size(DynamicTag::PLTRELSZ, structure)?;
        let kind = self.required_size(DynamicTag::PLTREL, structure)?;
        let with_addend = match i64::try_from(kind).map(DynamicTag) {
            Ok(DynamicTag::RELA) => true,
            Ok(DynamicTag::REL) => false,
            _ => {
                return Err(Error::invalid_table(format!(
                    "DT_PLTREL {kind:#x} is not DT_REL or DT_RELA"
                ))
                .in_structure(structure));
            }
        };
        let entsize = Relocation::size(self.encoding().class, with_addend);
        self.parse_relocations(address, size, entsize, with_addend, structure)
            .map(Some)
    }

    /// Parse `size` bytes of relocations at `address`.
    fn parse_relocations(
        &self,
        address: u64,
        size: u64,
        entsize: usize,
        with_addend: bool,
        structure: &str,
    ) -> Result<RelocationTable> {
        let bytes = self.bytes(address, size, structure)?;
        RelocationTable::parse_with_entsize(
            bytes,
            self.encoding(),
            self.space.machine(),
            with_addend,
            entsize,
        )
        .map_err(|error| error.in_structure(structure).at_address(address))
    }

    /// Return the `RELR` table at `DT_RELR`, or else at `DT_ANDROID_RELR`.
    fn relr(&self) -> Result<Option<RelrTable>> {
        let tags = if self.value(DynamicTag::RELR).is_some() {
            [DynamicTag::RELR, DynamicTag::RELRSZ, DynamicTag::RELRENT]
        } else {
            [
                DynamicTag::ANDROID_RELR,
                DynamicTag::ANDROID_RELRSZ,
                DynamicTag::ANDROID_RELRENT,
            ]
        };
        let [address_tag, size_tag, entry_tag] = tags;
        let Some(address) = self.pointer(address_tag) else {
            return Ok(None);
        };
        let structure = format!("{address_tag}");
        let size = self.required_size(size_tag, &structure)?;
        let word = self.encoding().addr_size();
        if let Some(entsize) = self.value(entry_tag)
            && usize::try_from(entsize).ok() != Some(word)
        {
            return Err(Error::invalid_table(format!(
                "{entry_tag} {entsize} is not the word size {word}"
            ))
            .in_structure(structure));
        }
        let bytes = self.bytes(address, size, &structure)?;
        RelrTable::parse(bytes, self.encoding())
            .map(Some)
            .map_err(|error| error.in_structure(structure).at_address(address))
    }

    /// Return the System V hash table at `DT_HASH`.
    pub(crate) fn sysv_hash(&self) -> Result<Option<SysvHashTable>> {
        let Some(address) = self.pointer(DynamicTag::HASH) else {
            return Ok(None);
        };
        let encoding = self.encoding();
        let entry_size = sysv_hash_entry_size(self.space.machine(), encoding.class);
        let bytes = self.slice(address, "DT_HASH")?;
        SysvHashTable::parse(bytes, encoding, entry_size)
            .map(Some)
            .map_err(|error| error.at_address(address))
    }

    /// Return the GNU hash table at `DT_GNU_HASH`.
    pub(crate) fn gnu_hash(&self) -> Result<Option<GnuHashTable>> {
        let Some(address) = self.pointer(DynamicTag::GNU_HASH) else {
            return Ok(None);
        };
        let bytes = self.slice(address, "DT_GNU_HASH")?;
        GnuHashTable::parse(bytes, self.encoding())
            .map(Some)
            .map_err(|error| error.at_address(address))
    }
}
