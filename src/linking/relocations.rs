//! Read the dynamic relocations and the symbol hash tables.

use super::{DynamicRelocations, Linker};
use crate::dynamic::DynamicTag;
use crate::hash::{GnuHashTable, SysvHashTable, sysv_hash_entry_size};
use crate::prelude::*;
use crate::reloc::{Relocation, RelocationTable, RelrTable, max_relocation_symbol};
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

/// The tags of the `DT_RELA` table.
const RELA: RelocationTags = RelocationTags {
    address: DynamicTag::RELA,
    size: DynamicTag::RELASZ,
    entry: DynamicTag::RELAENT,
    with_addend: true,
};

/// The tags of the `DT_REL` table.
const REL: RelocationTags = RelocationTags {
    address: DynamicTag::REL,
    size: DynamicTag::RELSZ,
    entry: DynamicTag::RELENT,
    with_addend: false,
};

/// The bytes of a `Rel` or `Rela` table, before the parse.
struct RawRelocations<'a> {
    /// The table bytes.
    bytes: &'a [u8],
    /// The entry size.
    entsize: usize,
    /// `true` for `Rela` entries.
    with_addend: bool,
    /// The name of the table for the error context.
    structure: String,
    /// The virtual address of the table.
    address: u64,
}

impl<'a> Linker<'a> {
    /// Parse the relocation tables that the dynamic table names.
    pub(crate) fn relocations(&self) -> Result<DynamicRelocations> {
        Ok(DynamicRelocations {
            rela: self
                .raw_table(&RELA)?
                .map(|raw| self.parse_raw(raw))
                .transpose()?,
            rel: self
                .raw_table(&REL)?
                .map(|raw| self.parse_raw(raw))
                .transpose()?,
            plt: self.raw_plt()?.map(|raw| self.parse_raw(raw)).transpose()?,
            relr: self.relr()?,
            android: self.android_relocations()?,
            crel: self.crel_relocations()?,
        })
    }

    /// Return the largest symbol index of the relocations of [`Self::relocations`], or
    /// `None` if no relocation exists.
    ///
    /// The function makes the same checks as [`Self::relocations`], so it returns an error if
    /// and only if [`Self::relocations`] returns an error. It does not keep the `Rel` and
    /// `Rela` entries, so it does not allocate memory for them.
    pub(crate) fn max_relocation_symbol(&self) -> Result<Option<u32>> {
        let mut max = None;
        for raw in [
            self.raw_table(&RELA)?,
            self.raw_table(&REL)?,
            self.raw_plt()?,
        ]
        .into_iter()
        .flatten()
        {
            let found = max_relocation_symbol(
                raw.bytes,
                self.encoding(),
                self.space.machine(),
                raw.with_addend,
                raw.entsize,
            )
            .map_err(|error| error.in_structure(raw.structure).at_address(raw.address))?;
            max = max.max(found);
        }
        self.relr()?;
        for table in [self.android_relocations()?, self.crel_relocations()?]
            .into_iter()
            .flatten()
        {
            max = max.max(table.iter().map(|relocation| relocation.symbol).max());
        }
        Ok(max)
    }

    /// Return the bytes of the `Rel` or `Rela` table that `tags` names.
    fn raw_table(&self, tags: &RelocationTags) -> Result<Option<RawRelocations<'a>>> {
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
        Ok(Some(RawRelocations {
            bytes: self.bytes(address, size, &structure)?,
            entsize,
            with_addend: tags.with_addend,
            structure,
            address,
        }))
    }

    /// Return the bytes of the PLT relocations at `DT_JMPREL`.
    fn raw_plt(&self) -> Result<Option<RawRelocations<'a>>> {
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
        Ok(Some(RawRelocations {
            bytes: self.bytes(address, size, structure)?,
            entsize: Relocation::size(self.encoding().class, with_addend),
            with_addend,
            structure: structure.to_string(),
            address,
        }))
    }

    /// Parse the entries of a `Rel` or `Rela` table.
    fn parse_raw(&self, raw: RawRelocations<'_>) -> Result<RelocationTable> {
        RelocationTable::parse_with_entsize(
            raw.bytes,
            self.encoding(),
            self.space.machine(),
            raw.with_addend,
            raw.entsize,
        )
        .map_err(|error| error.in_structure(raw.structure).at_address(raw.address))
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

    /// Return the Android packed relocations at `DT_ANDROID_RELA`, or else at
    /// `DT_ANDROID_REL`.
    fn android_relocations(&self) -> Result<Option<RelocationTable>> {
        let (address_tag, size_tag, with_addend) = if self.value(DynamicTag::ANDROID_RELA).is_some()
        {
            (DynamicTag::ANDROID_RELA, DynamicTag::ANDROID_RELASZ, true)
        } else {
            (DynamicTag::ANDROID_REL, DynamicTag::ANDROID_RELSZ, false)
        };
        let Some(address) = self.pointer(address_tag) else {
            return Ok(None);
        };
        let structure = format!("{address_tag}");
        let size = self.required_size(size_tag, &structure)?;
        let bytes = self.bytes(address, size, &structure)?;
        RelocationTable::parse_android_packed(
            bytes,
            self.encoding(),
            self.space.machine(),
            with_addend,
        )
        .map(Some)
        .map_err(|error| error.in_structure(structure).at_address(address))
    }

    /// Return the CREL relocations at `DT_CREL`. The table has no size tag: it goes to the end
    /// of its segment, and the CREL header gives the entry count.
    fn crel_relocations(&self) -> Result<Option<RelocationTable>> {
        let Some(address) = self.pointer(DynamicTag::CREL) else {
            return Ok(None);
        };
        let bytes = self.slice(address, "DT_CREL")?;
        RelocationTable::parse_crel(bytes, self.encoding())
            .map(Some)
            .map_err(|error| error.in_structure("DT_CREL").at_address(address))
    }

    /// Parse the System V hash table at `DT_HASH`.
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

    /// Parse the GNU hash table at `DT_GNU_HASH`.
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
