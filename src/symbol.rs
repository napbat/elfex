//! Symbol tables (`SHT_SYMTAB` and `SHT_DYNSYM` sections, and the `DT_SYMTAB` data).
//!
//! A symbol table is an array of `Elf32_Sym` or `Elf64_Sym` entries. Entry 0 is the null
//! symbol. The `st_name` field of each entry is an offset in the linked string table.
//!
//! - Use [`SymbolTable`] to parse and write the entries.
//! - Use [`SymbolSectionIndexTable`] to read the extended section indices of an
//!   `SHT_SYMTAB_SHNDX` section.
//! - Use [`SymbolTableBuilder`] to make a new symbol table and its string table.

mod builder;
#[cfg(test)]
mod tests;

pub use builder::{BuiltSymbolTable, NewSymbol, SymbolTableBuilder};

use crate::endian::{ByteReader, Class, Encoding};
use crate::prelude::*;
use crate::section::{SHN_UNDEF, SHN_XINDEX};
use crate::strtab::StringTable;
use crate::{Error, Result};

/// The size of an `Elf32_Sym` entry in bytes.
const ELF32_SYMBOL_SIZE: usize = 16;
/// The size of an `Elf64_Sym` entry in bytes.
const ELF64_SYMBOL_SIZE: usize = 24;

elf_value_type! {
    /// The binding of a symbol: the high 4 bits of `st_info` (`ELF32_ST_BIND`, `ELF64_ST_BIND`).
    pub struct SymbolBinding(u8);
    /// `STB_LOCAL`: the symbol is not visible outside its object file.
    LOCAL = 0, "STB_LOCAL";
    /// `STB_GLOBAL`: the symbol is visible to all object files.
    GLOBAL = 1, "STB_GLOBAL";
    /// `STB_WEAK`: a global symbol with a lower precedence.
    WEAK = 2, "STB_WEAK";
    /// `STB_GNU_UNIQUE`: a global symbol that is unique in the process (GNU extension).
    GNU_UNIQUE = 10, "STB_GNU_UNIQUE";
}

impl SymbolBinding {
    /// `STB_LOOS`: the first operating-system-specific binding.
    pub const LOOS: Self = Self(10);
    /// `STB_HIOS`: the last operating-system-specific binding.
    pub const HIOS: Self = Self(12);
    /// `STB_LOPROC`: the first processor-specific binding.
    pub const LOPROC: Self = Self(13);
    /// `STB_HIPROC`: the last processor-specific binding.
    pub const HIPROC: Self = Self(15);
}

elf_value_type! {
    /// The type of a symbol: the low 4 bits of `st_info` (`ELF32_ST_TYPE`, `ELF64_ST_TYPE`).
    pub struct SymbolType(u8);
    /// `STT_NOTYPE`: the type is not specified.
    NOTYPE = 0, "STT_NOTYPE";
    /// `STT_OBJECT`: a data object, for example a variable or an array.
    OBJECT = 1, "STT_OBJECT";
    /// `STT_FUNC`: a function or other executable code.
    FUNC = 2, "STT_FUNC";
    /// `STT_SECTION`: a section. The symbol is local.
    SECTION = 3, "STT_SECTION";
    /// `STT_FILE`: the name of the source file of the object file.
    FILE = 4, "STT_FILE";
    /// `STT_COMMON`: an uninitialized common block.
    COMMON = 5, "STT_COMMON";
    /// `STT_TLS`: a thread-local storage entity. The value is an offset, not an address.
    TLS = 6, "STT_TLS";
    /// `STT_GNU_IFUNC`: an indirect function (GNU extension). The value is the address of the
    /// resolver function.
    GNU_IFUNC = 10, "STT_GNU_IFUNC";
}

impl SymbolType {
    /// `STT_LOOS`: the first operating-system-specific type.
    pub const LOOS: Self = Self(10);
    /// `STT_HIOS`: the last operating-system-specific type.
    pub const HIOS: Self = Self(12);
    /// `STT_LOPROC`: the first processor-specific type.
    pub const LOPROC: Self = Self(13);
    /// `STT_HIPROC`: the last processor-specific type.
    pub const HIPROC: Self = Self(15);
}

elf_value_type! {
    /// The visibility of a symbol: the low 2 bits of `st_other` (`ELF32_ST_VISIBILITY`,
    /// `ELF64_ST_VISIBILITY`).
    pub struct SymbolVisibility(u8);
    /// `STV_DEFAULT`: the binding of the symbol sets the visibility.
    DEFAULT = 0, "STV_DEFAULT";
    /// `STV_INTERNAL`: the processor supplement defines the meaning. Usually the same as
    /// `STV_HIDDEN`.
    INTERNAL = 1, "STV_INTERNAL";
    /// `STV_HIDDEN`: other components cannot see the symbol.
    HIDDEN = 2, "STV_HIDDEN";
    /// `STV_PROTECTED`: other components can see the symbol, but cannot preempt it.
    PROTECTED = 3, "STV_PROTECTED";
}

/// A symbol table entry (`Elf32_Sym` or `Elf64_Sym`).
///
/// The fields keep the names of the specification without the `st_` prefix. The two classes
/// use a different field order in the file:
///
/// - `Elf32_Sym`: `st_name`, `st_value`, `st_size`, `st_info`, `st_other`, `st_shndx`.
/// - `Elf64_Sym`: `st_name`, `st_info`, `st_other`, `st_shndx`, `st_value`, `st_size`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Symbol {
    /// The offset of the symbol name in the linked string table (`st_name`). 0 means no name.
    pub name: u32,
    /// The value of the symbol (`st_value`). In an executable or a shared object, this is
    /// usually a virtual address. In a relocatable file, this is an offset in the section
    /// `shndx`. For `STT_TLS`, this is an offset in the TLS template.
    pub value: u64,
    /// The size of the symbol in bytes (`st_size`), or 0.
    pub size: u64,
    /// The binding and the type of the symbol (`st_info`).
    pub info: u8,
    /// The visibility of the symbol in the low 2 bits (`st_other`).
    pub other: u8,
    /// The index of the related section, or a reserved `SHN_*` value (`st_shndx`).
    pub shndx: u16,
}

impl Symbol {
    /// Return the size of the structure for `class`: 16 or 24 bytes.
    #[must_use]
    pub const fn size(class: Class) -> usize {
        match class {
            Class::Elf32 => ELF32_SYMBOL_SIZE,
            Class::Elf64 => ELF64_SYMBOL_SIZE,
        }
    }

    /// Return the name of the structure for `class`: `Elf32_Sym` or `Elf64_Sym`.
    const fn structure_name(class: Class) -> &'static str {
        match class {
            Class::Elf32 => "Elf32_Sym",
            Class::Elf64 => "Elf64_Sym",
        }
    }

    /// Return the `st_info` value for a binding and a type.
    ///
    /// The function keeps the low 4 bits of each value.
    #[must_use]
    pub const fn make_info(binding: SymbolBinding, symbol_type: SymbolType) -> u8 {
        ((binding.0 & 0x0f) << 4) | (symbol_type.0 & 0x0f)
    }

    /// Parse a symbol from the start of `bytes`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes` is
    /// shorter than the structure.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        let entry_size = Self::size(encoding.class);
        let bytes = bytes
            .get(..entry_size)
            .ok_or_else(|| Error::buffer_too_small(entry_size, bytes.len()))?;
        let mut reader = ByteReader::new(bytes, encoding);
        if encoding.is_64bit() {
            let name = reader.u32()?;
            let info = reader.u8()?;
            let other = reader.u8()?;
            let shndx = reader.u16()?;
            Ok(Self {
                name,
                value: reader.u64()?,
                size: reader.u64()?,
                info,
                other,
                shndx,
            })
        } else {
            Ok(Self {
                name: reader.u32()?,
                value: u64::from(reader.u32()?),
                size: u64::from(reader.u32()?),
                info: reader.u8()?,
                other: reader.u8()?,
                shndx: reader.u16()?,
            })
        }
    }

    /// Append the serialized symbol to `out`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if the class
    /// is ELF32 and `value` or `size` does not fit in 32 bits.
    pub fn write(&self, out: &mut Vec<u8>, encoding: Encoding) -> Result<()> {
        if encoding.is_64bit() {
            encoding.write_u32(out, self.name);
            out.push(self.info);
            out.push(self.other);
            encoding.write_u16(out, self.shndx);
            encoding.write_u64(out, self.value);
            encoding.write_u64(out, self.size);
        } else {
            // Check both values first, so that `out` does not change on an error.
            let value = narrow_elf32("st_value", self.value)?;
            let size = narrow_elf32("st_size", self.size)?;
            encoding.write_u32(out, self.name);
            encoding.write_u32(out, value);
            encoding.write_u32(out, size);
            out.push(self.info);
            out.push(self.other);
            encoding.write_u16(out, self.shndx);
        }
        Ok(())
    }

    /// Return the binding of the symbol (the high 4 bits of `st_info`).
    #[must_use]
    pub const fn binding(&self) -> SymbolBinding {
        SymbolBinding(self.info >> 4)
    }

    /// Return the type of the symbol (the low 4 bits of `st_info`).
    #[must_use]
    pub const fn symbol_type(&self) -> SymbolType {
        SymbolType(self.info & 0x0f)
    }

    /// Return the visibility of the symbol (the low 2 bits of `st_other`).
    #[must_use]
    pub const fn visibility(&self) -> SymbolVisibility {
        SymbolVisibility(self.other & 0x03)
    }

    /// Set the binding of the symbol. Keep the type.
    pub const fn set_binding(&mut self, binding: SymbolBinding) {
        self.info = Self::make_info(binding, self.symbol_type());
    }

    /// Set the type of the symbol. Keep the binding.
    pub const fn set_symbol_type(&mut self, symbol_type: SymbolType) {
        self.info = Self::make_info(self.binding(), symbol_type);
    }

    /// Set the visibility of the symbol. Keep the other bits of `st_other`.
    pub const fn set_visibility(&mut self, visibility: SymbolVisibility) {
        self.other = (self.other & !0x03) | (visibility.0 & 0x03);
    }

    /// Return `true` if `st_shndx` is `SHN_UNDEF`.
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        self.shndx == SHN_UNDEF
    }

    /// Return `true` if `st_shndx` is not `SHN_UNDEF`.
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        !self.is_undefined()
    }

    /// Return `true` if the binding is `STB_LOCAL`.
    #[must_use]
    pub const fn is_local(&self) -> bool {
        self.binding().0 == SymbolBinding::LOCAL.0
    }

    /// Return `true` if the binding is `STB_GLOBAL` or `STB_WEAK`.
    #[must_use]
    pub const fn is_global_or_weak(&self) -> bool {
        let binding = self.binding().0;
        binding == SymbolBinding::GLOBAL.0 || binding == SymbolBinding::WEAK.0
    }

    /// Return the section index of the symbol.
    ///
    /// `index_in_table` is the index of this symbol in its symbol table. `shndx` is the
    /// `SHT_SYMTAB_SHNDX` table of the symbol table, if the file has one.
    ///
    /// - If `st_shndx` is `SHN_XINDEX`, return the entry `index_in_table` of `shndx`. Return
    ///   `None` if `shndx` is `None` or has no such entry.
    /// - Otherwise, return `st_shndx` without a change. This includes `SHN_UNDEF` and the
    ///   reserved values, for example `SHN_ABS` and `SHN_COMMON`. Compare the result with
    ///   these values before you use it as a section index.
    #[must_use]
    pub fn section_index(
        &self,
        index_in_table: usize,
        shndx: Option<&SymbolSectionIndexTable>,
    ) -> Option<u32> {
        if self.shndx == SHN_XINDEX {
            shndx.and_then(|table| table.get(index_in_table))
        } else {
            Some(u32::from(self.shndx))
        }
    }
}

/// A parsed symbol table (`SHT_SYMTAB`, `SHT_DYNSYM` or the `DT_SYMTAB` data).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolTable {
    /// The entries in table order. Entry 0 is usually the null symbol.
    pub symbols: Vec<Symbol>,
}

impl SymbolTable {
    /// Parse a symbol table from all of `bytes`, with the standard entry size.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is not a multiple of the entry size.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        Self::parse_with_entsize(bytes, encoding, 0)
    }

    /// Parse a symbol table from all of `bytes`, with an entry size of `entsize` bytes.
    ///
    /// `entsize` is usually the `sh_entsize` or the `DT_SYMENT` value. 0 means the standard
    /// size. The parser ignores the bytes of each entry after the standard structure.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if `entsize` is
    /// smaller than the structure, or if the length of `bytes` is not a multiple of
    /// `entsize`.
    pub fn parse_with_entsize(bytes: &[u8], encoding: Encoding, entsize: u64) -> Result<Self> {
        let name = Symbol::structure_name(encoding.class);
        let entry_size = entry_size(encoding, entsize)?;
        if !bytes.len().is_multiple_of(entry_size) {
            return Err(Error::invalid_table(format!(
                "symbol table size {} is not a multiple of the entry size {entry_size}",
                bytes.len()
            ))
            .in_structure(name));
        }
        let symbols = bytes
            .chunks_exact(entry_size)
            .map(|chunk| Symbol::parse(chunk, encoding))
            .collect::<Result<Vec<_>>>()
            .map_err(|error| error.in_structure(name))?;
        Ok(Self { symbols })
    }

    /// Parse exactly `count` entries with the standard size from the start of `bytes`.
    ///
    /// Use this function when the symbol count comes from a different source, for example
    /// a hash table. The parser ignores the bytes after the last entry.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::BufferTooSmall`](crate::ErrorKind::BufferTooSmall) if `bytes`
    ///   is shorter than `count` entries.
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the size of
    ///   `count` entries does not fit in `usize`.
    pub fn parse_count(bytes: &[u8], encoding: Encoding, count: u64) -> Result<Self> {
        let name = Symbol::structure_name(encoding.class);
        let entry_size = Symbol::size(encoding.class);
        let total = usize::try_from(count)
            .ok()
            .and_then(|count| count.checked_mul(entry_size))
            .ok_or_else(|| {
                Error::invalid_table(format!("symbol count {count} is too large"))
                    .in_structure(name)
            })?;
        let bytes = bytes
            .get(..total)
            .ok_or_else(|| Error::buffer_too_small(total, bytes.len()).in_structure(name))?;
        Self::parse_with_entsize(bytes, encoding, 0)
    }

    /// Return the symbol at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&Symbol> {
        self.symbols.get(index)
    }

    /// Return the number of symbols, including the null symbol.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Return `true` if the table has no symbols.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Return an iterator over the symbols in table order.
    pub fn iter(&self) -> core::slice::Iter<'_, Symbol> {
        self.symbols.iter()
    }

    /// Serialize the symbols with the standard entry size.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if the class
    /// is ELF32 and a value or a size does not fit in 32 bits.
    pub fn write(&self, encoding: Encoding) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(
            self.symbols
                .len()
                .saturating_mul(Symbol::size(encoding.class)),
        );
        for symbol in &self.symbols {
            symbol.write(&mut out, encoding)?;
        }
        Ok(out)
    }

    /// Return the index of the first symbol that is not `STB_LOCAL`.
    ///
    /// If all symbols are local, return the number of symbols. In a well-formed table, all
    /// local symbols come first, and this value is the `sh_info` value of the section.
    #[must_use]
    pub fn first_non_local(&self) -> usize {
        self.symbols
            .iter()
            .position(|symbol| !symbol.is_local())
            .unwrap_or(self.symbols.len())
    }

    /// Find the first symbol with the name `name` in `strings`.
    ///
    /// Return the index of the symbol and the symbol. The search skips symbols with an
    /// invalid name offset.
    #[must_use]
    pub fn find_by_name(&self, strings: &StringTable, name: &[u8]) -> Option<(usize, &Symbol)> {
        self.symbols.iter().enumerate().find(|(_, symbol)| {
            strings
                .get_bytes(symbol.name)
                .is_ok_and(|found| found == name)
        })
    }
}

impl<'a> IntoIterator for &'a SymbolTable {
    type Item = &'a Symbol;
    type IntoIter = core::slice::Iter<'a, Symbol>;

    fn into_iter(self) -> Self::IntoIter {
        self.symbols.iter()
    }
}

/// Convert an `Elf32_Sym` field value to `u32`, or return a `ValueOutOfRange` error.
fn narrow_elf32(field: &str, value: u64) -> Result<u32> {
    u32::try_from(value).map_err(|_| {
        Error::value_out_of_range(format!("{field} {value:#x} does not fit in an ELF32 field"))
            .in_structure("Elf32_Sym")
    })
}

/// Return the entry size in bytes for an `entsize` value. 0 means the standard size.
fn entry_size(encoding: Encoding, entsize: u64) -> Result<usize> {
    let standard = Symbol::size(encoding.class);
    if entsize == 0 {
        return Ok(standard);
    }
    usize::try_from(entsize)
        .ok()
        .filter(|size| *size >= standard)
        .ok_or_else(|| {
            Error::invalid_table(format!(
                "symbol entry size {entsize} is smaller than {standard} or too large"
            ))
            .in_structure(Symbol::structure_name(encoding.class))
        })
}

/// The extended section indices of a symbol table (an `SHT_SYMTAB_SHNDX` section).
///
/// Entry `i` is an `Elf32_Word` with the section index of symbol `i`, if the `st_shndx` field
/// of that symbol is `SHN_XINDEX`. Other entries are 0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolSectionIndexTable {
    /// The section index of each symbol, in symbol table order.
    pub indices: Vec<u32>,
}

impl SymbolSectionIndexTable {
    /// Parse the table from all of `bytes`.
    ///
    /// # Errors
    ///
    /// Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if the length of
    /// `bytes` is not a multiple of 4.
    pub fn parse(bytes: &[u8], encoding: Encoding) -> Result<Self> {
        if !bytes.len().is_multiple_of(4) {
            return Err(Error::invalid_table(format!(
                "SHT_SYMTAB_SHNDX size {} is not a multiple of 4",
                bytes.len()
            )));
        }
        let indices = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| encoding.read_u32(chunk, 0))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { indices })
    }

    /// Return the entry for the symbol at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<u32> {
        self.indices.get(index).copied()
    }

    /// Return the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    /// Return `true` if the table has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    /// Serialize the entries.
    #[must_use]
    pub fn write(&self, encoding: Encoding) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.indices.len().saturating_mul(4));
        for &index in &self.indices {
            encoding.write_u32(&mut out, index);
        }
        out
    }
}
