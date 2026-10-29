//! Dynamic table tags (`d_tag` values) and the `DT_FLAGS` and `DT_FLAGS_1` bit flags.

use crate::header::Machine;

elf_value_type! {
    /// The type of a dynamic table entry: the `d_tag` field of `Elf32_Dyn` and `Elf64_Dyn`.
    ///
    /// The tag tells how to interpret `d_un`: as a virtual address (`d_ptr`), as a value
    /// (`d_val`), or as an offset in the dynamic string table.
    pub struct DynamicTag(i64);
    /// `DT_NULL`: mark the end of the dynamic table.
    NULL = 0, "DT_NULL";
    /// `DT_NEEDED`: string table offset of the name of a needed library.
    NEEDED = 1, "DT_NEEDED";
    /// `DT_PLTRELSZ`: size in bytes of the PLT relocations.
    PLTRELSZ = 2, "DT_PLTRELSZ";
    /// `DT_PLTGOT`: virtual address of the PLT or GOT.
    PLTGOT = 3, "DT_PLTGOT";
    /// `DT_HASH`: virtual address of the SysV symbol hash table.
    HASH = 4, "DT_HASH";
    /// `DT_STRTAB`: virtual address of the dynamic string table.
    STRTAB = 5, "DT_STRTAB";
    /// `DT_SYMTAB`: virtual address of the dynamic symbol table.
    SYMTAB = 6, "DT_SYMTAB";
    /// `DT_RELA`: virtual address of the `Elf*_Rela` relocations.
    RELA = 7, "DT_RELA";
    /// `DT_RELASZ`: size in bytes of the `DT_RELA` relocations.
    RELASZ = 8, "DT_RELASZ";
    /// `DT_RELAENT`: size in bytes of one `DT_RELA` relocation.
    RELAENT = 9, "DT_RELAENT";
    /// `DT_STRSZ`: size in bytes of the dynamic string table.
    STRSZ = 10, "DT_STRSZ";
    /// `DT_SYMENT`: size in bytes of one dynamic symbol.
    SYMENT = 11, "DT_SYMENT";
    /// `DT_INIT`: virtual address of the initialization function.
    INIT = 12, "DT_INIT";
    /// `DT_FINI`: virtual address of the termination function.
    FINI = 13, "DT_FINI";
    /// `DT_SONAME`: string table offset of the shared object name.
    SONAME = 14, "DT_SONAME";
    /// `DT_RPATH`: string table offset of the library search path (deprecated).
    RPATH = 15, "DT_RPATH";
    /// `DT_SYMBOLIC`: start the symbol search in the shared object.
    SYMBOLIC = 16, "DT_SYMBOLIC";
    /// `DT_REL`: virtual address of the `Elf*_Rel` relocations.
    REL = 17, "DT_REL";
    /// `DT_RELSZ`: size in bytes of the `DT_REL` relocations.
    RELSZ = 18, "DT_RELSZ";
    /// `DT_RELENT`: size in bytes of one `DT_REL` relocation.
    RELENT = 19, "DT_RELENT";
    /// `DT_PLTREL`: type of the PLT relocations (`DT_REL` or `DT_RELA`).
    PLTREL = 20, "DT_PLTREL";
    /// `DT_DEBUG`: debugger data. The dynamic linker fills it at run time.
    DEBUG = 21, "DT_DEBUG";
    /// `DT_TEXTREL`: relocations can change a non-writable segment.
    TEXTREL = 22, "DT_TEXTREL";
    /// `DT_JMPREL`: virtual address of the PLT relocations.
    JMPREL = 23, "DT_JMPREL";
    /// `DT_BIND_NOW`: process all relocations before control goes to the program.
    BIND_NOW = 24, "DT_BIND_NOW";
    /// `DT_INIT_ARRAY`: virtual address of the array of initialization functions.
    INIT_ARRAY = 25, "DT_INIT_ARRAY";
    /// `DT_FINI_ARRAY`: virtual address of the array of termination functions.
    FINI_ARRAY = 26, "DT_FINI_ARRAY";
    /// `DT_INIT_ARRAYSZ`: size in bytes of `DT_INIT_ARRAY`.
    INIT_ARRAYSZ = 27, "DT_INIT_ARRAYSZ";
    /// `DT_FINI_ARRAYSZ`: size in bytes of `DT_FINI_ARRAY`.
    FINI_ARRAYSZ = 28, "DT_FINI_ARRAYSZ";
    /// `DT_RUNPATH`: string table offset of the library search path.
    RUNPATH = 29, "DT_RUNPATH";
    /// `DT_FLAGS`: `DF_*` flags.
    FLAGS = 30, "DT_FLAGS";
    /// `DT_PREINIT_ARRAY`: virtual address of the array of pre-initialization functions.
    /// It has the same value as `DT_ENCODING`.
    PREINIT_ARRAY = 32, "DT_PREINIT_ARRAY";
    /// `DT_PREINIT_ARRAYSZ`: size in bytes of `DT_PREINIT_ARRAY`.
    PREINIT_ARRAYSZ = 33, "DT_PREINIT_ARRAYSZ";
    /// `DT_SYMTAB_SHNDX`: virtual address of the `SHT_SYMTAB_SHNDX` section.
    SYMTAB_SHNDX = 34, "DT_SYMTAB_SHNDX";
    /// `DT_RELRSZ`: size in bytes of the `DT_RELR` relocations.
    RELRSZ = 35, "DT_RELRSZ";
    /// `DT_RELR`: virtual address of the `Elf*_Relr` relocations.
    RELR = 36, "DT_RELR";
    /// `DT_RELRENT`: size in bytes of one `DT_RELR` entry.
    RELRENT = 37, "DT_RELRENT";
    /// `DT_CREL`: virtual address of the CREL relocations.
    CREL = 0x4000_0026, "DT_CREL";
    /// `DT_ANDROID_REL`: virtual address of the Android packed `REL` relocations.
    ANDROID_REL = 0x6000_000f, "DT_ANDROID_REL";
    /// `DT_ANDROID_RELSZ`: size in bytes of `DT_ANDROID_REL`.
    ANDROID_RELSZ = 0x6000_0010, "DT_ANDROID_RELSZ";
    /// `DT_ANDROID_RELA`: virtual address of the Android packed `RELA` relocations.
    ANDROID_RELA = 0x6000_0011, "DT_ANDROID_RELA";
    /// `DT_ANDROID_RELASZ`: size in bytes of `DT_ANDROID_RELA`.
    ANDROID_RELASZ = 0x6000_0012, "DT_ANDROID_RELASZ";
    /// `DT_ANDROID_RELR`: virtual address of the Android `RELR` relocations.
    ANDROID_RELR = 0x6fff_e000, "DT_ANDROID_RELR";
    /// `DT_ANDROID_RELRSZ`: size in bytes of `DT_ANDROID_RELR`.
    ANDROID_RELRSZ = 0x6fff_e001, "DT_ANDROID_RELRSZ";
    /// `DT_ANDROID_RELRENT`: size in bytes of one `DT_ANDROID_RELR` entry.
    ANDROID_RELRENT = 0x6fff_e003, "DT_ANDROID_RELRENT";
    /// `DT_GNU_PRELINKED`: prelink time stamp.
    GNU_PRELINKED = 0x6fff_fdf5, "DT_GNU_PRELINKED";
    /// `DT_GNU_CONFLICTSZ`: size in bytes of `DT_GNU_CONFLICT`.
    GNU_CONFLICTSZ = 0x6fff_fdf6, "DT_GNU_CONFLICTSZ";
    /// `DT_GNU_LIBLISTSZ`: size in bytes of `DT_GNU_LIBLIST`.
    GNU_LIBLISTSZ = 0x6fff_fdf7, "DT_GNU_LIBLISTSZ";
    /// `DT_CHECKSUM`: checksum of the object.
    CHECKSUM = 0x6fff_fdf8, "DT_CHECKSUM";
    /// `DT_PLTPADSZ`: size in bytes of `DT_PLTPAD`.
    PLTPADSZ = 0x6fff_fdf9, "DT_PLTPADSZ";
    /// `DT_MOVEENT`: size in bytes of one `DT_MOVETAB` entry.
    MOVEENT = 0x6fff_fdfa, "DT_MOVEENT";
    /// `DT_MOVESZ`: size in bytes of `DT_MOVETAB`.
    MOVESZ = 0x6fff_fdfb, "DT_MOVESZ";
    /// `DT_FEATURE_1`: feature flags.
    FEATURE_1 = 0x6fff_fdfc, "DT_FEATURE_1";
    /// `DT_POSFLAG_1`: flags for the next dynamic entry.
    POSFLAG_1 = 0x6fff_fdfd, "DT_POSFLAG_1";
    /// `DT_SYMINSZ`: size in bytes of `DT_SYMINFO`.
    SYMINSZ = 0x6fff_fdfe, "DT_SYMINSZ";
    /// `DT_SYMINENT`: size in bytes of one `DT_SYMINFO` entry.
    SYMINENT = 0x6fff_fdff, "DT_SYMINENT";
    /// `DT_GNU_HASH`: virtual address of the GNU symbol hash table.
    GNU_HASH = 0x6fff_fef5, "DT_GNU_HASH";
    /// `DT_TLSDESC_PLT`: virtual address of the TLS descriptor PLT entry.
    TLSDESC_PLT = 0x6fff_fef6, "DT_TLSDESC_PLT";
    /// `DT_TLSDESC_GOT`: virtual address of the TLS descriptor GOT entry.
    TLSDESC_GOT = 0x6fff_fef7, "DT_TLSDESC_GOT";
    /// `DT_GNU_CONFLICT`: virtual address of the prelink conflict section.
    GNU_CONFLICT = 0x6fff_fef8, "DT_GNU_CONFLICT";
    /// `DT_GNU_LIBLIST`: virtual address of the prelink library list.
    GNU_LIBLIST = 0x6fff_fef9, "DT_GNU_LIBLIST";
    /// `DT_CONFIG`: string table offset of the configuration file name.
    CONFIG = 0x6fff_fefa, "DT_CONFIG";
    /// `DT_DEPAUDIT`: string table offset of the dependency audit library names.
    DEPAUDIT = 0x6fff_fefb, "DT_DEPAUDIT";
    /// `DT_AUDIT`: string table offset of the audit library names.
    AUDIT = 0x6fff_fefc, "DT_AUDIT";
    /// `DT_PLTPAD`: virtual address of the PLT padding.
    PLTPAD = 0x6fff_fefd, "DT_PLTPAD";
    /// `DT_MOVETAB`: virtual address of the move table.
    MOVETAB = 0x6fff_fefe, "DT_MOVETAB";
    /// `DT_SYMINFO`: virtual address of the symbol information table.
    SYMINFO = 0x6fff_feff, "DT_SYMINFO";
    /// `DT_VERSYM`: virtual address of the `.gnu.version` symbol version table.
    VERSYM = 0x6fff_fff0, "DT_VERSYM";
    /// `DT_RELACOUNT`: number of `R_*_RELATIVE` relocations in `DT_RELA`.
    RELACOUNT = 0x6fff_fff9, "DT_RELACOUNT";
    /// `DT_RELCOUNT`: number of `R_*_RELATIVE` relocations in `DT_REL`.
    RELCOUNT = 0x6fff_fffa, "DT_RELCOUNT";
    /// `DT_FLAGS_1`: `DF_1_*` flags.
    FLAGS_1 = 0x6fff_fffb, "DT_FLAGS_1";
    /// `DT_VERDEF`: virtual address of the version definitions.
    VERDEF = 0x6fff_fffc, "DT_VERDEF";
    /// `DT_VERDEFNUM`: number of version definitions.
    VERDEFNUM = 0x6fff_fffd, "DT_VERDEFNUM";
    /// `DT_VERNEED`: virtual address of the version requirements.
    VERNEED = 0x6fff_fffe, "DT_VERNEED";
    /// `DT_VERNEEDNUM`: number of version requirements.
    VERNEEDNUM = 0x6fff_ffff, "DT_VERNEEDNUM";
    /// `DT_AUXILIARY`: string table offset of the auxiliary filtee name.
    AUXILIARY = 0x7fff_fffd, "DT_AUXILIARY";
    /// `DT_FILTER`: string table offset of the standard filtee name.
    FILTER = 0x7fff_ffff, "DT_FILTER";
}

/// Range bounds and tags that share a value with another tag.
impl DynamicTag {
    /// `DT_ENCODING`: start of the range where even tags are `d_ptr` and odd tags are `d_val`.
    pub const ENCODING: Self = Self(32);
    /// `DT_LOOS`: start of the operating system specific range.
    pub const LOOS: Self = Self(0x6000_000d);
    /// `DT_HIOS`: end of the operating system specific range.
    pub const HIOS: Self = Self(0x6fff_f000);
    /// `DT_LOPROC`: start of the processor specific range.
    pub const LOPROC: Self = Self(0x7000_0000);
    /// `DT_HIPROC`: end of the processor specific range.
    pub const HIPROC: Self = Self(0x7fff_ffff);
}

/// Processor specific tags for MIPS.
impl DynamicTag {
    /// `DT_MIPS_RLD_VERSION`: version of the runtime linker interface.
    pub const MIPS_RLD_VERSION: Self = Self(0x7000_0001);
    /// `DT_MIPS_FLAGS`: `RHF_*` flags.
    pub const MIPS_FLAGS: Self = Self(0x7000_0005);
    /// `DT_MIPS_BASE_ADDRESS`: base virtual address of the object.
    pub const MIPS_BASE_ADDRESS: Self = Self(0x7000_0006);
    /// `DT_MIPS_LOCAL_GOTNO`: number of local GOT entries.
    pub const MIPS_LOCAL_GOTNO: Self = Self(0x7000_000a);
    /// `DT_MIPS_SYMTABNO`: number of dynamic symbols.
    pub const MIPS_SYMTABNO: Self = Self(0x7000_0011);
    /// `DT_MIPS_UNREFEXTNO`: index of the first external dynamic symbol not in the GOT.
    pub const MIPS_UNREFEXTNO: Self = Self(0x7000_0012);
    /// `DT_MIPS_GOTSYM`: index of the first dynamic symbol in the GOT.
    pub const MIPS_GOTSYM: Self = Self(0x7000_0013);
    /// `DT_MIPS_RLD_MAP`: virtual address of the debug map pointer.
    pub const MIPS_RLD_MAP: Self = Self(0x7000_0016);
    /// `DT_MIPS_RLD_MAP_REL`: offset of the debug map pointer relative to this entry.
    pub const MIPS_RLD_MAP_REL: Self = Self(0x7000_0035);
}

/// Processor specific tags for `PowerPC` 64, `AArch64` and RISC-V.
impl DynamicTag {
    /// `DT_PPC64_GLINK`: virtual address of the `.glink` stub area.
    pub const PPC64_GLINK: Self = Self(0x7000_0000);
    /// `DT_AARCH64_BTI_PLT`: the PLT uses BTI instructions.
    pub const AARCH64_BTI_PLT: Self = Self(0x7000_0001);
    /// `DT_AARCH64_PAC_PLT`: the PLT uses PAC instructions.
    pub const AARCH64_PAC_PLT: Self = Self(0x7000_0003);
    /// `DT_AARCH64_VARIANT_PCS`: the object has symbols with a variant procedure call standard.
    pub const AARCH64_VARIANT_PCS: Self = Self(0x7000_0005);
    /// `DT_RISCV_VARIANT_CC`: the object has symbols with a variant calling convention.
    pub const RISCV_VARIANT_CC: Self = Self(0x7000_0001);
}

impl DynamicTag {
    /// Return `true` if the value of this tag is a virtual address (`d_ptr`).
    ///
    /// `DT_DEBUG` returns `false`: the dynamic linker fills it at run time and the file value
    /// is not an address in the object. `DT_CONFIG`, `DT_DEPAUDIT` and `DT_AUDIT` return
    /// `false`: they are string table offsets. Processor specific tags use `machine`.
    #[must_use]
    pub fn is_pointer(self, machine: Machine) -> bool {
        match self {
            Self::PLTGOT
            | Self::HASH
            | Self::STRTAB
            | Self::SYMTAB
            | Self::RELA
            | Self::INIT
            | Self::FINI
            | Self::REL
            | Self::JMPREL
            | Self::INIT_ARRAY
            | Self::FINI_ARRAY
            | Self::PREINIT_ARRAY
            | Self::SYMTAB_SHNDX
            | Self::RELR
            | Self::CREL
            | Self::GNU_HASH
            | Self::VERSYM
            | Self::VERDEF
            | Self::VERNEED
            | Self::TLSDESC_PLT
            | Self::TLSDESC_GOT
            | Self::GNU_CONFLICT
            | Self::GNU_LIBLIST
            | Self::MOVETAB
            | Self::SYMINFO
            | Self::PLTPAD
            | Self::ANDROID_REL
            | Self::ANDROID_RELA
            | Self::ANDROID_RELR => true,
            _ => match machine {
                Machine::PPC64 => self == Self::PPC64_GLINK,
                Machine::MIPS | Machine::MIPS_RS3_LE => {
                    self == Self::MIPS_BASE_ADDRESS || self == Self::MIPS_RLD_MAP
                }
                _ => false,
            },
        }
    }

    /// Return `true` if the value of this tag is an offset in the dynamic string table.
    #[must_use]
    pub fn is_string(self) -> bool {
        matches!(
            self,
            Self::NEEDED
                | Self::SONAME
                | Self::RPATH
                | Self::RUNPATH
                | Self::AUXILIARY
                | Self::FILTER
                | Self::CONFIG
                | Self::DEPAUDIT
                | Self::AUDIT
        )
    }
}

/// `DF_ORIGIN`: the object uses `$ORIGIN`.
pub const DF_ORIGIN: u64 = 0x1;
/// `DF_SYMBOLIC`: start the symbol search in the object.
pub const DF_SYMBOLIC: u64 = 0x2;
/// `DF_TEXTREL`: relocations can change a non-writable segment.
pub const DF_TEXTREL: u64 = 0x4;
/// `DF_BIND_NOW`: process all relocations at load time.
pub const DF_BIND_NOW: u64 = 0x8;
/// `DF_STATIC_TLS`: the object uses the static TLS model.
pub const DF_STATIC_TLS: u64 = 0x10;

/// `DF_1_NOW`: process all relocations at load time.
pub const DF_1_NOW: u64 = 0x1;
/// `DF_1_GLOBAL`: make the symbols of the object global.
pub const DF_1_GLOBAL: u64 = 0x2;
/// `DF_1_GROUP`: the object is a member of a group.
pub const DF_1_GROUP: u64 = 0x4;
/// `DF_1_NODELETE`: do not unload the object.
pub const DF_1_NODELETE: u64 = 0x8;
/// `DF_1_LOADFLTR`: load the filtees immediately.
pub const DF_1_LOADFLTR: u64 = 0x10;
/// `DF_1_INITFIRST`: run the initialization of the object first.
pub const DF_1_INITFIRST: u64 = 0x20;
/// `DF_1_NOOPEN`: do not open the object with `dlopen`.
pub const DF_1_NOOPEN: u64 = 0x40;
/// `DF_1_ORIGIN`: the object uses `$ORIGIN`.
pub const DF_1_ORIGIN: u64 = 0x80;
/// `DF_1_DIRECT`: use direct binding.
pub const DF_1_DIRECT: u64 = 0x100;
/// `DF_1_TRANS`: reserved.
pub const DF_1_TRANS: u64 = 0x200;
/// `DF_1_INTERPOSE`: the object interposes symbols.
pub const DF_1_INTERPOSE: u64 = 0x400;
/// `DF_1_NODEFLIB`: ignore the default library search path.
pub const DF_1_NODEFLIB: u64 = 0x800;
/// `DF_1_NODUMP`: do not dump the object with `dldump`.
pub const DF_1_NODUMP: u64 = 0x1000;
/// `DF_1_CONFALT`: the object is a configuration alternative.
pub const DF_1_CONFALT: u64 = 0x2000;
/// `DF_1_ENDFILTEE`: the filtee ends the filter search.
pub const DF_1_ENDFILTEE: u64 = 0x4000;
/// `DF_1_DISPRELDNE`: displacement relocations are done.
pub const DF_1_DISPRELDNE: u64 = 0x8000;
/// `DF_1_DISPRELPND`: displacement relocations are pending.
pub const DF_1_DISPRELPND: u64 = 0x10000;
/// `DF_1_NODIRECT`: the object has symbols that do not allow direct binding.
pub const DF_1_NODIRECT: u64 = 0x20000;
/// `DF_1_IGNMULDEF`: ignore multiple definitions.
pub const DF_1_IGNMULDEF: u64 = 0x40000;
/// `DF_1_NOKSYMS`: do not export the symbols to the kernel.
pub const DF_1_NOKSYMS: u64 = 0x80000;
/// `DF_1_NOHDR`: the object has no ELF header in its mapping.
pub const DF_1_NOHDR: u64 = 0x10_0000;
/// `DF_1_EDITED`: a tool changed the object after the link.
pub const DF_1_EDITED: u64 = 0x20_0000;
/// `DF_1_NORELOC`: the object has no relocations.
pub const DF_1_NORELOC: u64 = 0x40_0000;
/// `DF_1_SYMINTPOSE`: the object has individual interposer symbols.
pub const DF_1_SYMINTPOSE: u64 = 0x80_0000;
/// `DF_1_GLOBAUDIT`: apply global auditing.
pub const DF_1_GLOBAUDIT: u64 = 0x100_0000;
/// `DF_1_SINGLETON`: the object has singleton symbols.
pub const DF_1_SINGLETON: u64 = 0x200_0000;
/// `DF_1_STUB`: the object is a stub.
pub const DF_1_STUB: u64 = 0x400_0000;
/// `DF_1_PIE`: the object is a position-independent executable.
pub const DF_1_PIE: u64 = 0x800_0000;
/// `DF_1_KMOD`: the object is a kernel module.
pub const DF_1_KMOD: u64 = 0x1000_0000;
/// `DF_1_WEAKFILTER`: the object is a weak filter.
pub const DF_1_WEAKFILTER: u64 = 0x2000_0000;
/// `DF_1_NOCOMMON`: the object has no common symbols.
pub const DF_1_NOCOMMON: u64 = 0x4000_0000;
