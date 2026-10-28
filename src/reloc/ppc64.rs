//! Common 64-bit PowerPC relocation types (`EM_PPC64`). This list is not complete.

reloc_types! {
    R_PPC64_NONE = 0;
    R_PPC64_ADDR32 = 1;
    R_PPC64_ADDR24 = 2;
    R_PPC64_ADDR16 = 3;
    R_PPC64_REL24 = 10;
    R_PPC64_COPY = 19;
    R_PPC64_GLOB_DAT = 20;
    R_PPC64_JMP_SLOT = 21;
    R_PPC64_RELATIVE = 22;
    R_PPC64_REL32 = 26;
    R_PPC64_ADDR64 = 38;
    R_PPC64_REL64 = 44;
    R_PPC64_TOC16 = 47;
    R_PPC64_TOC = 51;
    R_PPC64_DTPMOD64 = 68;
    R_PPC64_TPREL64 = 73;
    R_PPC64_DTPREL64 = 78;
    R_PPC64_JMP_IREL = 247;
    R_PPC64_IRELATIVE = 248;
}
