//! Common S/390 and z/Architecture relocation types (`EM_S390`). This list is not complete.

reloc_types! {
    R_390_NONE = 0;
    R_390_8 = 1;
    R_390_12 = 2;
    R_390_16 = 3;
    R_390_32 = 4;
    R_390_PC32 = 5;
    R_390_GOT12 = 6;
    R_390_GOT32 = 7;
    R_390_PLT32 = 8;
    R_390_COPY = 9;
    R_390_GLOB_DAT = 10;
    R_390_JMP_SLOT = 11;
    R_390_RELATIVE = 12;
    R_390_GOTOFF32 = 13;
    R_390_GOTPC = 14;
    R_390_PC16DBL = 16;
    R_390_PLT16DBL = 17;
    R_390_PC32DBL = 19;
    R_390_PLT32DBL = 20;
    R_390_GOTPCDBL = 21;
    R_390_64 = 22;
    R_390_PC64 = 23;
    R_390_GOT64 = 24;
    R_390_PLT64 = 25;
    R_390_GOTENT = 26;
    R_390_TLS_DTPMOD = 54;
    R_390_TLS_DTPOFF = 55;
    R_390_TLS_TPOFF = 56;
    R_390_IRELATIVE = 61;
}
