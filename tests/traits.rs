//! Check at compile time that the public types implement `Send` and `Sync`.

use elfex::{
    AuxvEntry, BuilderLayout, BuiltSymbolTable, Cie, DynamicEntry, DynamicInfo, DynamicRelocations,
    DynamicTable, EhFrameHdr, ElfFile, ElfHeaders, ElfImage, Error, ErrorContext, Fde, FileMapping,
    GnuAbiTag, GnuHashTable, GnuProperty, GroupTable, LinkingView, NamedSymbol, Note, NoteTable,
    RelocationSection, RelocationTable, RelrTable, SectionGroup, SectionPlacement, SectionRef,
    Segment, StringTable, StringTableBuilder, SymbolSectionIndexTable, SymbolTable,
    SymbolTableBuilder, SymbolVersion, SysvHashTable, ValidationIssue, ValidationResult,
    VersionDefinitionTable, VersionMap, VersionName, VersionRequirementTable, VersionTables,
    VersymTable,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn linking_view_is_send_and_sync() {
    assert_send_sync::<LinkingView<'static>>();
}

#[test]
fn public_types_are_send_and_sync() {
    assert_send_sync::<ElfFile>();
    assert_send_sync::<ElfFile<&[u8]>>();
    assert_send_sync::<ElfImage<'static>>();
    assert_send_sync::<ElfHeaders>();
    assert_send_sync::<Segment<'static>>();
    assert_send_sync::<SectionRef<'static>>();
    assert_send_sync::<Error>();
    assert_send_sync::<ErrorContext>();
    assert_send_sync::<ValidationIssue>();
    assert_send_sync::<ValidationResult>();
    assert_send_sync::<BuilderLayout>();
    assert_send_sync::<SectionPlacement>();

    assert_send_sync::<DynamicEntry>();
    assert_send_sync::<DynamicTable>();
    assert_send_sync::<DynamicInfo>();
    assert_send_sync::<DynamicRelocations>();
    assert_send_sync::<StringTable<'static>>();
    assert_send_sync::<StringTableBuilder>();
    assert_send_sync::<SymbolTable>();
    assert_send_sync::<SymbolTableBuilder>();
    assert_send_sync::<BuiltSymbolTable>();
    assert_send_sync::<SymbolSectionIndexTable>();
    assert_send_sync::<NamedSymbol<'static>>();
    assert_send_sync::<RelocationTable>();
    assert_send_sync::<RelrTable>();
    assert_send_sync::<RelocationSection>();
    assert_send_sync::<SectionGroup>();
    assert_send_sync::<GroupTable>();
    assert_send_sync::<Note>();
    assert_send_sync::<NoteTable>();
    assert_send_sync::<FileMapping>();
    assert_send_sync::<AuxvEntry>();
    assert_send_sync::<GnuAbiTag>();
    assert_send_sync::<GnuProperty>();
    assert_send_sync::<SysvHashTable>();
    assert_send_sync::<GnuHashTable>();
    assert_send_sync::<VersymTable>();
    assert_send_sync::<VersionDefinitionTable>();
    assert_send_sync::<VersionRequirementTable>();
    assert_send_sync::<VersionTables>();
    assert_send_sync::<VersionMap>();
    assert_send_sync::<VersionName>();
    assert_send_sync::<SymbolVersion>();
    assert_send_sync::<EhFrameHdr>();
    assert_send_sync::<Cie>();
    assert_send_sync::<Fde>();
}
