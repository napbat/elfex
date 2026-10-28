//! The self-consistency checks: parsing, round trips, validation, accessors and the loader
//! view.

use elfex::{EhFrame, ElfFile, ElfImage, FileType, NamedSymbol, SectionType};

use crate::defects;
use crate::report::{ACCESSORS, Findings, IMAGE, LOOKUP, PARSE, ROUND_TRIP, VALIDATE};

/// The runtime base for the relocation check of a shared object.
const RUNTIME_BASE: u64 = 0x7f00_0000_0000;

/// Call each accessor in the list on `$target` and record each error.
macro_rules! call_accessors {
    ($findings:expr, $what:literal, $target:expr, [$($name:ident),* $(,)?]) => {
        $(
            if let Err(error) = $target.$name() {
                $findings.fail(
                    ACCESSORS,
                    format!("{}::{}: {error}", $what, stringify!($name)),
                );
            }
        )*
    };
}

/// Parse the file, and check the round trip, the validation and the accessors of `ElfFile`.
///
/// Return the parsed file, or `None` if it does not parse.
pub fn check_file(bytes: &[u8], findings: &mut Findings) -> Option<ElfFile> {
    let file = match ElfFile::parse(bytes) {
        Ok(file) => file,
        Err(error) => {
            findings.fail(PARSE, format!("ElfFile::parse: {error}"));
            return None;
        }
    };
    findings.accept(defects::known_defects(&file));
    match file.try_build() {
        Ok(built) if built == bytes => {}
        Ok(built) => findings.fail(ROUND_TRIP, first_difference(bytes, &built)),
        Err(error) => findings.fail(ROUND_TRIP, format!("ElfFile::try_build: {error}")),
    }
    for issue in file.validate().errors() {
        findings.fail(VALIDATE, format!("{issue:?}"));
    }
    call_accessors!(
        findings,
        "ElfFile",
        file,
        [
            dynamic,
            dynamic_strings,
            dynamic_symbols,
            needed_libraries,
            soname,
            rpath,
            runpath,
            interpreter,
            notes,
            build_id,
            dynamic_relocations,
            sysv_hash_table,
            gnu_hash_table,
            version_tables,
            dynamic_symbol_list,
            exports,
            imports,
            init_array,
            fini_array,
            preinit_array,
            eh_frame_hdr,
            symbols,
            symbol_strings,
            symbol_list,
            relocation_sections,
            section_groups,
            core_file_mappings,
            auxv,
        ]
    );
    check_eh_frame(&file, findings);
    if let Ok(exports) = file.exports() {
        check_lookup(
            &exports,
            "ElfFile",
            |name| file.lookup_dynamic_symbol(name),
            findings,
        );
    }
    Some(file)
}

/// Parse `.eh_frame` if the file has it with file bytes.
fn check_eh_frame(file: &ElfFile, findings: &mut Findings) {
    for section in file.sections() {
        let header = section.header;
        if section.name != ".eh_frame" || header.section_type == SectionType::NOBITS {
            continue;
        }
        if let Err(error) = EhFrame::parse(section.data, file.encoding(), header.addr) {
            findings.fail(ACCESSORS, format!("EhFrame::parse: {error}"));
        }
    }
}

/// Check that `lookup` finds each exported name.
fn check_lookup<F>(exports: &[NamedSymbol], what: &str, lookup: F, findings: &mut Findings)
where
    F: Fn(&str) -> elfex::Result<Option<NamedSymbol>>,
{
    for symbol in exports {
        match lookup(&symbol.name) {
            Ok(Some(found)) if found.name == symbol.name => {}
            Ok(found) => findings.fail(
                LOOKUP,
                format!(
                    "{what}::lookup_dynamic_symbol({:?}) gives {:?}",
                    symbol.name,
                    found.map(|found| found.name)
                ),
            ),
            Err(error) => findings.fail(
                LOOKUP,
                format!("{what}::lookup_dynamic_symbol({:?}): {error}", symbol.name),
            ),
        }
    }
}

/// Return a message with the first offset where `built` differs from `bytes`.
fn first_difference(bytes: &[u8], built: &[u8]) -> String {
    let offset = bytes
        .iter()
        .zip(built)
        .position(|(left, right)| left != right)
        .unwrap_or(bytes.len().min(built.len()));
    format!(
        "try_build gives {} bytes for {} input bytes; first difference at {offset:#x}",
        built.len(),
        bytes.len()
    )
}

/// Check the loader view of the file: the accessors of `ElfImage`, the mapped image and the
/// raw file that `ElfImage::try_build` writes.
pub fn check_image(file: &ElfFile, bytes: &[u8], findings: &mut Findings) {
    let image = match ElfImage::parse(bytes) {
        Ok(image) => image,
        Err(error) => {
            findings.fail(IMAGE, format!("ElfImage::parse: {error}"));
            return;
        }
    };
    call_accessors!(
        findings,
        "ElfImage",
        image,
        [
            dynamic,
            dynamic_strings,
            dynamic_symbols,
            needed_libraries,
            soname,
            rpath,
            runpath,
            interpreter,
            notes,
            build_id,
            dynamic_relocations,
            sysv_hash_table,
            gnu_hash_table,
            version_tables,
            dynamic_symbol_list,
            exports,
            imports,
            init_array,
            fini_array,
            preinit_array,
            eh_frame_hdr,
            core_file_mappings,
            auxv,
        ]
    );
    if let Ok(exports) = image.exports() {
        check_lookup(
            &exports,
            "ElfImage",
            |name| image.lookup_dynamic_symbol(name),
            findings,
        );
    }
    match image.try_build() {
        Ok(built) => {
            if let Err(error) = ElfImage::parse(&built) {
                findings.fail(
                    IMAGE,
                    format!("ElfImage::try_build output does not parse: {error}"),
                );
            }
        }
        Err(error) => findings.fail(IMAGE, format!("ElfImage::try_build: {error}")),
    }
    let loadable = matches!(file.file_type(), FileType::EXEC | FileType::DYN);
    if loadable && image.load_segments().next().is_some() {
        check_mapped(file, &image, findings);
    }
}

/// Map the image, parse the mapped bytes and compare the exports and the needed libraries.
fn check_mapped(file: &ElfFile, image: &ElfImage, findings: &mut Findings) {
    let mapped = match image.to_mapped_image() {
        Ok(mapped) => mapped,
        Err(error) => {
            findings.fail(IMAGE, format!("ElfImage::to_mapped_image: {error}"));
            return;
        }
    };
    match ElfImage::parse_mapped(&mapped) {
        Ok(view) => {
            compare_lists(
                "exports",
                file.exports().map(|list| export_keys(&list)),
                view.exports().map(|list| export_keys(&list)),
                findings,
            );
            compare_lists(
                "needed libraries",
                file.needed_libraries(),
                view.needed_libraries(),
                findings,
            );
        }
        Err(error) => findings.fail(IMAGE, format!("ElfImage::parse_mapped: {error}")),
    }
    if file.file_type() == FileType::DYN
        && let Err(error) = image.to_mapped_image_at(RUNTIME_BASE)
    {
        findings.fail(IMAGE, format!("ElfImage::to_mapped_image_at: {error}"));
    }
}

/// Return the name, the version and the value of each symbol.
fn export_keys(list: &[NamedSymbol]) -> Vec<(String, Option<String>, u64)> {
    list.iter()
        .map(|symbol| {
            (
                symbol.name.clone(),
                symbol.version.clone(),
                symbol.symbol.value,
            )
        })
        .collect()
}

/// Record a failure if the file list and the mapped list are different.
fn compare_lists<T: PartialEq + std::fmt::Debug>(
    what: &str,
    file: elfex::Result<Vec<T>>,
    mapped: elfex::Result<Vec<T>>,
    findings: &mut Findings,
) {
    match (file, mapped) {
        (Ok(file), Ok(mapped)) => {
            if file != mapped {
                let index = file
                    .iter()
                    .zip(&mapped)
                    .position(|(left, right)| left != right);
                findings.fail(
                    IMAGE,
                    format!(
                        "mapped {what}: {} entries in the file, {} in the mapped image; first difference at {index:?}",
                        file.len(),
                        mapped.len()
                    ),
                );
            }
        }
        (Ok(_), Err(error)) => findings.fail(IMAGE, format!("mapped {what}: {error}")),
        (Err(_), _) => {}
    }
}
