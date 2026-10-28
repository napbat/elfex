//! Common 32-bit PowerPC relocation types (`EM_PPC`). This list is not complete.

reloc_types! {
    R_PPC_NONE = 0;
    R_PPC_ADDR32 = 1;
    R_PPC_ADDR24 = 2;
    R_PPC_ADDR16 = 3;
    R_PPC_ADDR16_LO = 4;
    R_PPC_ADDR16_HI = 5;
    R_PPC_ADDR16_HA = 6;
    R_PPC_REL24 = 10;
    R_PPC_REL14 = 11;
    R_PPC_PLTREL24 = 18;
    R_PPC_COPY = 19;
    R_PPC_GLOB_DAT = 20;
    R_PPC_JMP_SLOT = 21;
    R_PPC_RELATIVE = 22;
    R_PPC_LOCAL24PC = 23;
    R_PPC_UADDR32 = 24;
    R_PPC_REL32 = 26;
    R_PPC_DTPMOD32 = 68;
    R_PPC_TPREL32 = 73;
    R_PPC_DTPREL32 = 78;
    R_PPC_IRELATIVE = 248;
}
