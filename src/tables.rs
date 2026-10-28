//! Tables of an ELF file: dynamic, symbol, string, relocation, note, hash, version, group and
//! unwind tables.
//!
//! Each table parses from the contiguous bytes of a section, or of a range that the dynamic
//! table names. The specialized modules (for example [`crate::reloc`] and [`crate::note`]) also
//! hold the constants of each area.

pub use crate::dynamic::{DynamicEntry, DynamicInfo, DynamicTable, DynamicTag};
pub use crate::eh_frame::{
    Cie, EhFrame, EhFrameEntry, EhFrameHdr, EhFrameHdrEntry, Fde, PointerBases,
};
pub use crate::elf_file::{RelocationSection, SectionGroup};
pub use crate::hash::{GnuHashTable, SysvHashTable};
pub use crate::linking::{DynamicRelocations, VersionTables};
pub use crate::note::{AuxvEntry, FileMapping, GnuAbiTag, GnuProperty, Note, NoteTable};
pub use crate::reloc::{Relocation, RelocationTable, RelrTable};
pub use crate::strtab::{StringTable, StringTableBuilder};
pub use crate::symbol::{
    BuiltSymbolTable, NamedSymbol, NewSymbol, Symbol, SymbolBinding, SymbolSectionIndexTable,
    SymbolTable, SymbolTableBuilder, SymbolType, SymbolVisibility,
};
pub use crate::version::{
    SymbolVersion, VersionDefinition, VersionDefinitionTable, VersionMap, VersionName,
    VersionNeedEntry, VersionRequirement, VersionRequirementTable, VersymTable,
};
