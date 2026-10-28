//! A builder for a new symbol table and its string table.

use super::{Symbol, SymbolBinding, SymbolType, SymbolVisibility};
use crate::endian::Encoding;
use crate::prelude::*;
use crate::section::SHN_UNDEF;
use crate::strtab::StringTableBuilder;
use crate::{Error, Result};

/// A symbol to add to a [`SymbolTableBuilder`].
///
/// [`NewSymbol::new`] makes an undefined symbol with the value 0, the size 0 and the
/// visibility `STV_DEFAULT`. Use the `with_*` methods to set the other fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSymbol {
    /// The name of the symbol, without a NUL terminator. An empty name gives `st_name` 0.
    pub name: Vec<u8>,
    /// The value of the symbol (`st_value`), usually a virtual address.
    pub value: u64,
    /// The size of the symbol in bytes (`st_size`).
    pub size: u64,
    /// The binding of the symbol (the high 4 bits of `st_info`).
    pub binding: SymbolBinding,
    /// The type of the symbol (the low 4 bits of `st_info`).
    pub symbol_type: SymbolType,
    /// The visibility of the symbol (the low 2 bits of `st_other`).
    pub visibility: SymbolVisibility,
    /// The index of the related section, or a reserved `SHN_*` value (`st_shndx`).
    pub shndx: u16,
}

impl NewSymbol {
    /// Create an undefined symbol with a name, a binding and a type.
    #[must_use]
    pub fn new(name: impl Into<Vec<u8>>, binding: SymbolBinding, symbol_type: SymbolType) -> Self {
        Self {
            name: name.into(),
            value: 0,
            size: 0,
            binding,
            symbol_type,
            visibility: SymbolVisibility::DEFAULT,
            shndx: SHN_UNDEF,
        }
    }

    /// Set the value of the symbol (`st_value`).
    #[must_use]
    pub const fn with_value(mut self, value: u64) -> Self {
        self.value = value;
        self
    }

    /// Set the size of the symbol in bytes (`st_size`).
    #[must_use]
    pub const fn with_size(mut self, size: u64) -> Self {
        self.size = size;
        self
    }

    /// Set the section index of the symbol (`st_shndx`).
    #[must_use]
    pub const fn with_shndx(mut self, shndx: u16) -> Self {
        self.shndx = shndx;
        self
    }

    /// Set the visibility of the symbol.
    #[must_use]
    pub const fn with_visibility(mut self, visibility: SymbolVisibility) -> Self {
        self.visibility = visibility;
        self
    }
}

/// The output of [`SymbolTableBuilder::try_build`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuiltSymbolTable {
    /// The serialized symbol table. Entry 0 is the null symbol.
    pub symbols: Vec<u8>,
    /// The serialized string table for the `st_name` fields.
    pub strings: Vec<u8>,
    /// The index of the first symbol that is not local: the `sh_info` value of the section.
    pub first_non_local: u32,
    /// The output index of each added symbol, in the order of the `add` calls.
    pub indices: Vec<u32>,
}

/// A builder for a new symbol table (`SHT_SYMTAB` or `SHT_DYNSYM`) and its string table.
///
/// The output starts with the null symbol. The local symbols follow in the order of the
/// `add` calls, then all other symbols in the order of the `add` calls. Symbols with the same
/// name use the same string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolTableBuilder {
    encoding: Encoding,
    symbols: Vec<NewSymbol>,
}

impl SymbolTableBuilder {
    /// Create an empty builder for `encoding`.
    #[must_use]
    pub const fn new(encoding: Encoding) -> Self {
        Self {
            encoding,
            symbols: Vec::new(),
        }
    }

    /// Add a symbol and return its add index (the position in
    /// [`BuiltSymbolTable::indices`]).
    pub fn add(&mut self, symbol: NewSymbol) -> usize {
        self.symbols.push(symbol);
        self.symbols.len() - 1
    }

    /// Return the number of added symbols. The null symbol is not included.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Return `true` if no symbol was added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Build the symbol table and its string table.
    ///
    /// # Errors
    ///
    /// - Return [`ErrorKind::InvalidTable`](crate::ErrorKind::InvalidTable) if a name
    ///   contains a NUL byte.
    /// - Return [`ErrorKind::ValueOutOfRange`](crate::ErrorKind::ValueOutOfRange) if the
    ///   class is ELF32 and a value or a size does not fit in 32 bits, or if a string offset
    ///   or a symbol index does not fit in 32 bits.
    pub fn try_build(&self) -> Result<BuiltSymbolTable> {
        let entry_size = Symbol::size(self.encoding.class);
        let count = self.symbols.len().saturating_add(1);
        let mut symbols = Vec::with_capacity(count.saturating_mul(entry_size));
        let mut strings = StringTableBuilder::new();
        let mut indices = vec![0; self.symbols.len()];

        Symbol::default().write(&mut symbols, self.encoding)?;

        let is_local = |symbol: &NewSymbol| symbol.binding == SymbolBinding::LOCAL;
        let locals = self
            .symbols
            .iter()
            .filter(|symbol| is_local(symbol))
            .count();
        let first_non_local = to_index(locals.saturating_add(1))?;
        let ordered = self
            .symbols
            .iter()
            .enumerate()
            .filter(|(_, symbol)| is_local(symbol))
            .chain(
                self.symbols
                    .iter()
                    .enumerate()
                    .filter(|(_, symbol)| !is_local(symbol)),
            );
        for (position, (added, new)) in ordered.enumerate() {
            let output = to_index(position.saturating_add(1))?;
            let symbol = Symbol {
                name: strings.add(&new.name)?,
                value: new.value,
                size: new.size,
                info: Symbol::make_info(new.binding, new.symbol_type),
                other: new.visibility.0 & 0x03,
                shndx: new.shndx,
            };
            symbol.write(&mut symbols, self.encoding)?;
            if let Some(slot) = indices.get_mut(added) {
                *slot = output;
            }
        }

        Ok(BuiltSymbolTable {
            symbols,
            strings: strings.into_bytes(),
            first_non_local,
            indices,
        })
    }

    /// Build the symbol table and its string table.
    ///
    /// # Panics
    ///
    /// Panic if [`try_build`](Self::try_build) returns an error: a name contains a NUL byte,
    /// or a value does not fit in its field. Use `try_build` to handle invalid input.
    #[must_use]
    pub fn build(&self) -> BuiltSymbolTable {
        self.try_build()
            .expect("invalid symbol table: use try_build() to handle invalid input")
    }
}

/// Convert a symbol index to `u32`, or return a `ValueOutOfRange` error.
fn to_index(index: usize) -> Result<u32> {
    u32::try_from(index).map_err(|_| {
        Error::value_out_of_range(format!("symbol index {index} does not fit in 32 bits"))
    })
}
