//! Common MIPS relocation types (`EM_MIPS`). This list is not complete.
//!
//! In ELF64 MIPS, one entry holds up to three types. See [`Relocation`](super::Relocation) for
//! the packing in `r_type`.

reloc_types! {
    R_MIPS_NONE = 0;
    R_MIPS_16 = 1;
    R_MIPS_32 = 2;
    R_MIPS_REL32 = 3;
    R_MIPS_26 = 4;
    R_MIPS_HI16 = 5;
    R_MIPS_LO16 = 6;
    R_MIPS_GPREL16 = 7;
    R_MIPS_LITERAL = 8;
    R_MIPS_GOT16 = 9;
    R_MIPS_PC16 = 10;
    R_MIPS_CALL16 = 11;
    R_MIPS_GPREL32 = 12;
    R_MIPS_SHIFT5 = 16;
    R_MIPS_SHIFT6 = 17;
    R_MIPS_64 = 18;
    R_MIPS_GOT_DISP = 19;
    R_MIPS_GOT_PAGE = 20;
    R_MIPS_GOT_OFST = 21;
    R_MIPS_GOT_HI16 = 22;
    R_MIPS_GOT_LO16 = 23;
    R_MIPS_SUB = 24;
    R_MIPS_JALR = 37;
    R_MIPS_TLS_DTPMOD32 = 38;
    R_MIPS_TLS_DTPREL32 = 39;
    R_MIPS_TLS_DTPMOD64 = 40;
    R_MIPS_TLS_DTPREL64 = 41;
    R_MIPS_TLS_TPREL32 = 47;
    R_MIPS_TLS_TPREL64 = 48;
    R_MIPS_COPY = 126;
    R_MIPS_JUMP_SLOT = 127;
}
