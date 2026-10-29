//! Tables of an ELF file: dynamic, symbol, string, relocation, note, hash, version, group and
//! unwind tables.
//!
//! Each table parses from the contiguous bytes of a section, or of a range that the dynamic
//! table names. Most tables also write their bytes. The specialized modules hold the
//! constants of each area and an example of each table: [`crate::dynamic`],
//! [`crate::symbol`], [`crate::strtab`], [`crate::reloc`], [`crate::note`], [`crate::hash`],
//! [`crate::version`], [`crate::group`] and [`crate::eh_frame`].
//!
//! [`SectionGroup`] and [`RelocationSection`] are the results of [`ElfFile`](crate::ElfFile)
//! accessors. [`DynamicRelocations`] and [`VersionTables`] are the results of the dynamic
//! linking accessors, and [`LinkingView`] parses these tables once for many calls (see
//! [`crate::linking`]).

pub use crate::dynamic::{DynamicEntry, DynamicInfo, DynamicTable, DynamicTag};
pub use crate::eh_frame::{
    Cie, EhFrame, EhFrameEntry, EhFrameHdr, EhFrameHdrEntry, Fde, PointerBases,
};
pub use crate::elf_file::{RelocationSection, SectionGroup};
pub use crate::group::GroupTable;
pub use crate::hash::{GnuHashTable, SysvHashTable};
pub use crate::linking::{DynamicRelocations, LinkingView, VersionTables};
pub use crate::note::{AuxvEntry, FileMapping, GnuAbiTag, GnuProperty, Note, NoteTable};
pub use crate::reloc::{Relocation, RelocationKind, RelocationTable, RelrTable, TlsRelocationKind};
pub use crate::strtab::{StringTable, StringTableBuilder};
pub use crate::symbol::{
    BuiltSymbolTable, NamedSymbol, NewSymbol, Symbol, SymbolBinding, SymbolSectionIndexTable,
    SymbolTable, SymbolTableBuilder, SymbolType, SymbolVisibility,
};
pub use crate::version::{
    SymbolVersion, VersionDefinition, VersionDefinitionTable, VersionMap, VersionName,
    VersionNeedEntry, VersionRequirement, VersionRequirementTable, VersymTable,
};
