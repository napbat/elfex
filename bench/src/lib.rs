//! # Elfex benchmark support
//!
//! This package measures the speed and the memory use of `elfex`. The library part gives the
//! inputs and the operations. The `elfex` benchmark (Criterion) and the `memory` binary use
//! them.
//!
//! - [`inputs`] gives the synthetic shared object and the files in `ELFEX_BENCH_FILES`.
//! - [`Operation`] names each measured operation. [`Operation::with_runner`] prepares the
//!   state of an operation and gives a function that runs it once.

use std::error::Error as StdError;
use std::hint::black_box;
use std::path::PathBuf;

use elfex::{ElfFile, ElfHeaders, ElfImage, LinkingView, Result};

pub mod synthetic;

/// The error type of the benchmark setup.
pub type BoxError = Box<dyn StdError + Send + Sync>;

/// The environment variable with more input files. Separate the paths like `PATH`.
pub const FILES_VARIABLE: &str = "ELFEX_BENCH_FILES";

/// The number of names that the lookup operations search for.
pub const LOOKUP_NAMES: usize = 1_000;

/// The number of names for [`Operation::LookupEach`]. Each lookup parses the tables again.
pub const LOOKUP_EACH_NAMES: usize = 16;

/// One benchmark input: a name and the file bytes.
#[derive(Debug, Clone)]
pub struct Input {
    /// The name of the input: `synthetic` or the file name.
    pub name: String,
    /// The bytes of the ELF file.
    pub bytes: Vec<u8>,
}

/// Return the synthetic shared object and each file in `ELFEX_BENCH_FILES`.
///
/// # Errors
///
/// Return an error if the synthetic file does not build or an input file cannot be read.
pub fn inputs() -> core::result::Result<Vec<Input>, BoxError> {
    let mut inputs = vec![Input {
        name: "synthetic".to_string(),
        bytes: synthetic::shared_object()?,
    }];
    for path in input_paths() {
        let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let name = path.file_name().map_or_else(
            || path.display().to_string(),
            |name| name.to_string_lossy().into_owned(),
        );
        inputs.push(Input { name, bytes });
    }
    Ok(inputs)
}

/// Return the paths in `ELFEX_BENCH_FILES`.
fn input_paths() -> Vec<PathBuf> {
    std::env::var_os(FILES_VARIABLE)
        .map(|value| {
            std::env::split_paths(&value)
                .filter(|path| !path.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// An input with its parsed forms and the names to look up.
#[derive(Debug)]
pub struct Prepared<'a> {
    /// The input.
    pub input: &'a Input,
    /// The parsed file. It borrows the input bytes.
    pub file: ElfFile<&'a [u8]>,
    /// The parsed image. It borrows the input bytes.
    pub image: ElfImage<'a>,
    /// [`LOOKUP_NAMES`] names: exported dynamic symbols and some names that are not in the
    /// file.
    pub names: Vec<String>,
}

impl<'a> Prepared<'a> {
    /// Parse `input` and select the names to look up.
    ///
    /// # Errors
    ///
    /// Return an error if the input does not parse or its dynamic symbols do not parse.
    pub fn new(input: &'a Input) -> Result<Self> {
        let file = ElfFile::parse(&input.bytes)?;
        let image = ElfImage::parse(&input.bytes)?;
        let exports = file.exports()?;
        // One name in ten is not in the file.
        let found = LOOKUP_NAMES - LOOKUP_NAMES / 10;
        let step = (exports.len() / found).max(1);
        let mut names: Vec<String> = exports
            .iter()
            .step_by(step)
            .take(found)
            .map(|symbol| symbol.name.to_string())
            .collect();
        let missing = LOOKUP_NAMES - names.len();
        names.extend((0..missing).map(|index| format!("elfex_bench_missing_{index:04}")));
        Ok(Self {
            input,
            file,
            image,
            names,
        })
    }
}

/// One measured operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// `ElfHeaders::from_slice`.
    Headers,
    /// `ElfFile::parse`.
    FileParse,
    /// `ElfImage::parse`.
    ImageParse,
    /// `ElfFile::dynamic_symbol_list`: all dynamic symbols with names and versions.
    DynamicSymbols,
    /// `ElfImage::dynamic_symbol_list`.
    ImageDynamicSymbols,
    /// `ElfFile::linking`, then `LinkingView::symbol_table` and `LinkingView::string_table`:
    /// the name bytes of all dynamic symbols, without `NamedSymbol`.
    LinkingNames,
    /// `ElfFile::symbol_list`: all `.symtab` symbols with names.
    StaticSymbols,
    /// `ElfFile::linking`, then `LinkingView::lookup` for [`LOOKUP_NAMES`] names.
    LookupCold,
    /// `LinkingView::lookup` for [`LOOKUP_NAMES`] names on a view that has its tables.
    LookupWarm,
    /// `ElfFile::lookup_dynamic_symbol` for [`LOOKUP_EACH_NAMES`] names.
    LookupEach,
    /// `ElfFile::dynamic_relocations`, then iterate all relocations.
    Relocations,
    /// `ElfFile::notes` and `ElfFile::build_id`.
    Notes,
    /// `ElfFile::try_build`.
    RoundTrip,
    /// `ElfImage::to_mapped_image`.
    MappedImage,
}

impl Operation {
    /// All operations, in report order.
    pub const ALL: [Self; 14] = [
        Self::Headers,
        Self::FileParse,
        Self::ImageParse,
        Self::DynamicSymbols,
        Self::ImageDynamicSymbols,
        Self::LinkingNames,
        Self::StaticSymbols,
        Self::LookupCold,
        Self::LookupWarm,
        Self::LookupEach,
        Self::Relocations,
        Self::Notes,
        Self::RoundTrip,
        Self::MappedImage,
    ];

    /// Return the short name of the operation.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Headers => "headers_from_slice",
            Self::FileParse => "file_parse",
            Self::ImageParse => "image_parse",
            Self::DynamicSymbols => "dynamic_symbol_list",
            Self::ImageDynamicSymbols => "image_dynamic_symbol_list",
            Self::LinkingNames => "linking_symbol_names",
            Self::StaticSymbols => "symbol_list",
            Self::LookupCold => "lookup_1000_cold",
            Self::LookupWarm => "lookup_1000_warm",
            Self::LookupEach => "lookup_dynamic_symbol_16",
            Self::Relocations => "dynamic_relocations",
            Self::Notes => "notes_build_id",
            Self::RoundTrip => "file_try_build",
            Self::MappedImage => "to_mapped_image",
        }
    }

    /// Prepare the state of the operation and call `body` with a function that runs the
    /// operation once. The function returns a count of the results, for example the number
    /// of symbols.
    ///
    /// The preparation (for example the tables of the view for [`Self::LookupWarm`]) is not
    /// part of the function.
    ///
    /// # Errors
    ///
    /// Return an error if the preparation fails.
    pub fn with_runner<R>(
        self,
        prepared: &Prepared<'_>,
        body: impl FnOnce(&mut dyn FnMut() -> Result<usize>) -> R,
    ) -> Result<R> {
        if self == Self::LookupWarm {
            let view = prepared.file.linking()?;
            lookup(&view, &prepared.names)?;
            return Ok(body(&mut || lookup(&view, &prepared.names)));
        }
        Ok(body(&mut || self.run(prepared)))
    }

    /// Run the operation once and return a count of the results.
    fn run(self, prepared: &Prepared<'_>) -> Result<usize> {
        let bytes = prepared.input.bytes.as_slice();
        let file = &prepared.file;
        let count = match self {
            Self::Headers => black_box(ElfHeaders::from_slice(bytes)?)
                .section_headers
                .len(),
            Self::FileParse => black_box(ElfFile::parse(bytes)?).len(),
            Self::ImageParse => black_box(ElfImage::parse(bytes)?).program_headers().len(),
            Self::DynamicSymbols => black_box(file.dynamic_symbol_list()?).len(),
            Self::ImageDynamicSymbols => black_box(prepared.image.dynamic_symbol_list()?).len(),
            Self::LinkingNames => linking_names(&file.linking()?)?,
            Self::StaticSymbols => black_box(file.symbol_list()?).len(),
            Self::LookupCold | Self::LookupWarm => lookup(&file.linking()?, &prepared.names)?,
            Self::LookupEach => {
                let mut found = 0;
                for name in prepared.names.iter().take(LOOKUP_EACH_NAMES) {
                    found += usize::from(black_box(file.lookup_dynamic_symbol(name)?).is_some());
                }
                found
            }
            Self::Relocations => black_box(file.dynamic_relocations()?).iter().count(),
            Self::Notes => {
                let notes = black_box(file.notes()?).len();
                notes + black_box(file.build_id()?).map_or(0, |id| id.len())
            }
            Self::RoundTrip => black_box(file.try_build()?).len(),
            Self::MappedImage => black_box(prepared.image.to_mapped_image()?).len(),
        };
        Ok(count)
    }
}

/// Read the name bytes of all dynamic symbols through `view`. Return the total name length.
fn linking_names(view: &LinkingView<'_>) -> Result<usize> {
    let (Some(symbols), Some(strings)) = (view.symbol_table()?, view.string_table()?) else {
        return Ok(0);
    };
    let mut total = 0;
    for symbol in &symbols.symbols {
        total += black_box(strings.get_bytes(symbol.name)?).len();
    }
    Ok(total)
}

/// Look up each name in `names` through `view`. Return the number of found symbols.
fn lookup(view: &LinkingView<'_>, names: &[String]) -> Result<usize> {
    let mut found = 0;
    for name in names {
        found += usize::from(black_box(view.lookup(name)?).is_some());
    }
    Ok(found)
}
