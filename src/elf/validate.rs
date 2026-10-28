//! Check the ELF headers for structural problems.
//!
//! The image types call [`validate_headers`] from their `validate` methods. The checks use the
//! file header, the program headers and the section headers only. They do not read segment or
//! section data.

use super::ElfHeaders;
use crate::header::{FileHeader, FileType, Machine};
use crate::ident::EV_CURRENT;
use crate::prelude::*;
use crate::program::{ProgramHeader, SegmentType};
use crate::section::{SHF_INFO_LINK, SHN_UNDEF, SHN_XINDEX, SectionHeader, SectionType};
use crate::validation::{ValidationCode, ValidationIssue, ValidationResult};

/// The segment types that a file can have only once.
const UNIQUE_SEGMENT_TYPES: [SegmentType; 6] = [
    SegmentType::INTERP,
    SegmentType::DYNAMIC,
    SegmentType::PHDR,
    SegmentType::TLS,
    SegmentType::GNU_STACK,
    SegmentType::GNU_RELRO,
];

/// The segment types that the loader reads from memory. A `PT_LOAD` segment must map them.
const LOADED_SEGMENT_TYPES: [SegmentType; 3] =
    [SegmentType::PHDR, SegmentType::DYNAMIC, SegmentType::INTERP];

/// An index of ranges with a key. It finds a range that contains a query range in
/// `O(log n)` time.
///
/// The validation and the image parser use this index to avoid a quadratic search through
/// many program headers.
#[derive(Debug, Clone, Default)]
pub(crate) struct RangeIndex {
    /// The entries `(key, start, end)`, sorted by key and start.
    entries: Vec<(u64, u64, u64)>,
    /// For each entry, the largest end of this entry and the entries before it with the same
    /// key.
    max_ends: Vec<u64>,
}

impl RangeIndex {
    /// Make an index from entries `(key, start, end)`.
    pub(crate) fn new(mut entries: Vec<(u64, u64, u64)>) -> Self {
        entries.sort_unstable();
        let mut max_ends = Vec::with_capacity(entries.len());
        let mut previous: Option<(u64, u64)> = None;
        for &(key, _, end) in &entries {
            let max_end = match previous {
                Some((previous_key, previous_end)) if previous_key == key => previous_end.max(end),
                _ => end,
            };
            max_ends.push(max_end);
            previous = Some((key, max_end));
        }
        Self { entries, max_ends }
    }

    /// Make an index of the file ranges of the `PT_LOAD` segments. The key is 0.
    pub(crate) fn load_file_ranges(segments: &[ProgramHeader]) -> Self {
        Self::new(
            segments
                .iter()
                .filter(|segment| segment.is_load())
                .filter_map(|segment| {
                    let range = segment.file_range()?;
                    Some((0, range.start, range.end))
                })
                .collect(),
        )
    }

    /// Return `true` if an entry with `key` contains the range `start..end`.
    pub(crate) fn contains(&self, key: u64, start: u64, end: u64) -> bool {
        let count = self
            .entries
            .partition_point(|&(entry_key, entry_start, _)| {
                (entry_key, entry_start) <= (key, start)
            });
        let Some(last) = count.checked_sub(1) else {
            return false;
        };
        self.entries
            .get(last)
            .is_some_and(|&(entry_key, _, _)| entry_key == key)
            && self
                .max_ends
                .get(last)
                .is_some_and(|&max_end| max_end >= end)
    }
}

/// Check the file header, the program headers and the section headers.
///
/// `file_size` is the size of the raw file. If it is `None`, the checks against the end of the
/// file do not occur.
pub(crate) fn validate_headers(
    headers: &ElfHeaders,
    file_size: Option<u64>,
    result: &mut ValidationResult,
) {
    check_versions(&headers.header, result);
    check_header_sizes(headers, result);
    check_file_type(headers, result);
    check_entry_point(headers, result);
    check_program_header_table(headers, file_size, result);
    for (index, segment) in headers.program_headers.iter().enumerate() {
        check_segment(index, segment, file_size, result);
        if is_loadable(headers.file_type()) {
            check_page_congruence(index, segment, result);
        }
    }
    check_load_order(headers, result);
    check_load_overlaps(headers, result);
    check_unique_segments(headers, result);
    check_loaded_segments(headers, result);
    if !headers.section_headers.is_empty() {
        check_sections(headers, file_size, result);
    }
}

/// Return the context text for a program header.
fn segment_context(index: usize, segment: &ProgramHeader) -> String {
    format!("program header {index} ({})", segment.segment_type)
}

/// Return the context text for a section header.
fn section_context(headers: &ElfHeaders, index: usize) -> String {
    let name = headers.section_names.get(index).map_or("", String::as_str);
    format!("section {index} ({name})")
}

/// Check `EI_VERSION` and `e_version`.
fn check_versions(header: &FileHeader, result: &mut ValidationResult) {
    if header.ident.version != EV_CURRENT {
        result.push(
            ValidationIssue::error(
                ValidationCode::UnsupportedVersion,
                format!("EI_VERSION is {}, not EV_CURRENT", header.ident.version),
            )
            .with_context("e_ident"),
        );
    }
    if header.version != u32::from(EV_CURRENT) {
        result.push(
            ValidationIssue::error(
                ValidationCode::UnsupportedVersion,
                format!("e_version is {}, not EV_CURRENT", header.version),
            )
            .with_context("e_version"),
        );
    }
}

/// Check `e_ehsize`, `e_phentsize` and `e_shentsize` against the structure sizes.
fn check_header_sizes(headers: &ElfHeaders, result: &mut ValidationResult) {
    let header = &headers.header;
    let class = header.ident.class;
    check_entry_size(
        "e_ehsize",
        header.ehsize,
        FileHeader::standard_size(class),
        true,
        result,
    );
    let has_program_headers = header.phnum != 0 || !headers.program_headers.is_empty();
    check_entry_size(
        "e_phentsize",
        header.phentsize,
        ProgramHeader::standard_size(class),
        has_program_headers,
        result,
    );
    let has_section_headers =
        header.shnum != 0 || header.shoff != 0 || !headers.section_headers.is_empty();
    check_entry_size(
        "e_shentsize",
        header.shentsize,
        SectionHeader::standard_size(class),
        has_section_headers,
        result,
    );
}

/// Check one size field. A larger size is a warning. A smaller size is an error.
fn check_entry_size(
    field: &str,
    value: u16,
    standard: u16,
    used: bool,
    result: &mut ValidationResult,
) {
    if !used || value == standard {
        return;
    }
    let issue = if value > standard {
        ValidationIssue::warning(
            ValidationCode::InvalidHeaderSize,
            format!("{field} is {value}, larger than the structure size {standard}"),
        )
    } else {
        ValidationIssue::error(
            ValidationCode::InvalidHeaderSize,
            format!("{field} is {value}, smaller than the structure size {standard}"),
        )
    };
    result.push(issue.with_context(field));
}

/// Return `true` for `ET_EXEC` and `ET_DYN`.
fn is_loadable(file_type: FileType) -> bool {
    file_type == FileType::EXEC || file_type == FileType::DYN
}

/// Check that an executable or a shared object has `PT_LOAD` segments.
fn check_file_type(headers: &ElfHeaders, result: &mut ValidationResult) {
    let file_type = headers.file_type();
    if is_loadable(file_type) && headers.load_segments().next().is_none() {
        result.push(
            ValidationIssue::error(
                ValidationCode::InconsistentFileType,
                format!("the {file_type} file has no PT_LOAD segment"),
            )
            .with_context("e_type"),
        );
    }
}

/// The `EF_PPC64_ABI` bits of `e_flags`: 1 for the `ELFv1` ABI, 2 for the `ELFv2` ABI, 0 if
/// the file does not say. A file without the bits uses the `ELFv1` ABI.
const EF_PPC64_ABI: u32 = 3;

/// Return `true` if `e_entry` is the address of a function descriptor, not of code.
///
/// In the 64-bit PowerPC `ELFv1` ABI, `e_entry` points to the function descriptor of the
/// entry function in `.opd`. `.opd` is data, so the segment is not executable.
fn entry_is_descriptor(headers: &ElfHeaders) -> bool {
    headers.machine() == Machine::PPC64 && headers.header.flags & EF_PPC64_ABI != 2
}

/// Check that the entry point is in an executable `PT_LOAD` segment. For a function
/// descriptor (see [`entry_is_descriptor`]), any `PT_LOAD` segment is correct.
fn check_entry_point(headers: &ElfHeaders, result: &mut ValidationResult) {
    let entry = headers.entry_point();
    if !is_loadable(headers.file_type()) || entry == 0 {
        return;
    }
    let descriptor = entry_is_descriptor(headers);
    let in_code = headers
        .load_segments()
        .any(|segment| (descriptor || segment.is_executable()) && segment.contains_vaddr(entry));
    if !in_code {
        let segment = if descriptor { "a" } else { "an executable" };
        result.push(
            ValidationIssue::error(
                ValidationCode::EntryPointOutOfBounds,
                format!("the entry point {entry:#x} is not in {segment} PT_LOAD segment"),
            )
            .with_context("e_entry"),
        );
    }
}

/// Check that the program header table is in the file.
fn check_program_header_table(
    headers: &ElfHeaders,
    file_size: Option<u64>,
    result: &mut ValidationResult,
) {
    let Some(size) = file_size else {
        return;
    };
    if headers.program_headers.is_empty() {
        return;
    }
    let end = u64::try_from(headers.program_headers.len())
        .ok()
        .and_then(|count| count.checked_mul(u64::from(headers.header.phentsize)))
        .and_then(|table_size| headers.header.phoff.checked_add(table_size));
    if end.is_none_or(|end| end > size) {
        result.push(
            ValidationIssue::error(
                ValidationCode::SegmentOutOfFile,
                format!("the program header table goes past the end of the file ({size:#x} bytes)"),
            )
            .with_context("e_phoff"),
        );
    }
}

/// Check the file range, the sizes and the alignment of one segment.
fn check_segment(
    index: usize,
    segment: &ProgramHeader,
    file_size: Option<u64>,
    result: &mut ValidationResult,
) {
    if segment.filesz > 0
        && let Some(size) = file_size
        && segment.file_range().is_none_or(|range| range.end > size)
    {
        result.push(
            ValidationIssue::error(
                ValidationCode::SegmentOutOfFile,
                format!(
                    "the file range at {:#x} with {:#x} bytes goes past the end of the file ({size:#x} bytes)",
                    segment.offset, segment.filesz
                ),
            )
            .with_context(segment_context(index, segment)),
        );
    }
    if !segment.is_load() {
        return;
    }
    if segment.filesz > segment.memsz {
        result.push(
            ValidationIssue::error(
                ValidationCode::SegmentFileSizeTooLarge,
                format!(
                    "p_filesz {:#x} is larger than p_memsz {:#x}",
                    segment.filesz, segment.memsz
                ),
            )
            .with_context(segment_context(index, segment)),
        );
    }
    check_segment_alignment(index, segment, result);
}

/// Check `p_align` of a `PT_LOAD` segment.
fn check_segment_alignment(index: usize, segment: &ProgramHeader, result: &mut ValidationResult) {
    let align = segment.align;
    if align <= 1 {
        return;
    }
    if !align.is_power_of_two() {
        result.push(
            ValidationIssue::error(
                ValidationCode::MisalignedSegment,
                format!("p_align {align:#x} is not a power of 2"),
            )
            .with_context(segment_context(index, segment)),
        );
        return;
    }
    if segment.offset % align != segment.vaddr % align {
        result.push(
            ValidationIssue::error(
                ValidationCode::MisalignedSegment,
                format!(
                    "p_offset {:#x} and p_vaddr {:#x} do not agree modulo p_align {align:#x}",
                    segment.offset, segment.vaddr
                ),
            )
            .with_context(segment_context(index, segment)),
        );
    }
}

/// The smallest page size of the Linux loader: 4 KiB.
const MIN_PAGE_SIZE: u64 = 0x1000;

/// Check that `p_offset` and `p_vaddr` of a `PT_LOAD` segment agree modulo 4 KiB.
///
/// The Linux loader maps each `PT_LOAD` segment with `mmap`. It rejects a segment whose
/// offset and address do not agree modulo the page size, also when `p_align` is smaller.
/// The check gives a warning, because other loaders can accept such a segment.
fn check_page_congruence(index: usize, segment: &ProgramHeader, result: &mut ValidationResult) {
    if !segment.is_load() || segment.offset % MIN_PAGE_SIZE == segment.vaddr % MIN_PAGE_SIZE {
        return;
    }
    result.push(
        ValidationIssue::warning(
            ValidationCode::MisalignedSegment,
            format!(
                "p_offset {:#x} and p_vaddr {:#x} do not agree modulo the 4 KiB page size",
                segment.offset, segment.vaddr
            ),
        )
        .with_context(segment_context(index, segment)),
    );
}

/// Check that the `PT_LOAD` segments are sorted by virtual address.
fn check_load_order(headers: &ElfHeaders, result: &mut ValidationResult) {
    let mut previous: Option<u64> = None;
    for (index, segment) in headers.program_headers.iter().enumerate() {
        if !segment.is_load() {
            continue;
        }
        if previous.is_some_and(|previous| segment.vaddr < previous) {
            result.push(
                ValidationIssue::warning(
                    ValidationCode::UnsortedSegments,
                    "the PT_LOAD segments are not sorted by virtual address",
                )
                .with_context(segment_context(index, segment)),
            );
            return;
        }
        previous = Some(segment.vaddr);
    }
}

/// Check that no two `PT_LOAD` segments overlap in memory.
fn check_load_overlaps(headers: &ElfHeaders, result: &mut ValidationResult) {
    let mut ranges: Vec<(u64, u64, usize)> = headers
        .program_headers
        .iter()
        .enumerate()
        .filter(|(_, segment)| segment.is_load() && segment.memsz > 0)
        .filter_map(|(index, segment)| {
            let range = segment.memory_range()?;
            Some((range.start, range.end, index))
        })
        .collect();
    ranges.sort_unstable();
    let mut covering: Option<(u64, usize)> = None;
    for &(start, end, index) in &ranges {
        if let Some((covering_end, other)) = covering
            && start < covering_end
        {
            let context = headers
                .program_headers
                .get(index)
                .map_or_else(String::new, |segment| segment_context(index, segment));
            result.push(
                ValidationIssue::error(
                    ValidationCode::OverlappingSegments,
                    format!("PT_LOAD segments {other} and {index} overlap in memory"),
                )
                .with_context(context),
            );
        }
        if covering.is_none_or(|(covering_end, _)| end > covering_end) {
            covering = Some((end, index));
        }
    }
}

/// Check that the file has at most one segment of each unique type.
fn check_unique_segments(headers: &ElfHeaders, result: &mut ValidationResult) {
    for segment_type in UNIQUE_SEGMENT_TYPES {
        let count = headers
            .program_headers
            .iter()
            .filter(|segment| segment.segment_type == segment_type)
            .count();
        if count > 1 {
            result.push(
                ValidationIssue::error(
                    ValidationCode::DuplicateSegment,
                    format!("the file has {count} {segment_type} segments"),
                )
                .with_context(segment_type.to_string()),
            );
        }
    }
}

/// Check that a `PT_LOAD` segment maps each `PT_PHDR`, `PT_DYNAMIC` and `PT_INTERP` segment.
fn check_loaded_segments(headers: &ElfHeaders, result: &mut ValidationResult) {
    let index = RangeIndex::new(
        headers
            .load_segments()
            .filter_map(|segment| {
                let range = segment.memory_range()?;
                Some((0, range.start, range.end))
            })
            .collect(),
    );
    for (position, segment) in headers.program_headers.iter().enumerate() {
        if !LOADED_SEGMENT_TYPES.contains(&segment.segment_type) {
            continue;
        }
        let loaded = segment
            .memory_range()
            .is_some_and(|range| index.contains(0, range.start, range.end));
        if !loaded {
            result.push(
                ValidationIssue::error(
                    ValidationCode::SegmentNotLoaded,
                    format!(
                        "the {} segment at {:#x} is not in a PT_LOAD segment",
                        segment.segment_type, segment.vaddr
                    ),
                )
                .with_context(segment_context(position, segment)),
            );
        }
    }
}

/// Check the section header table and each section header.
fn check_sections(headers: &ElfHeaders, file_size: Option<u64>, result: &mut ValidationResult) {
    check_section_table(headers, file_size, result);
    let count = u64::try_from(headers.section_headers.len()).unwrap_or(u64::MAX);
    let check_segments = headers.file_type() != FileType::REL;
    let loads = RangeIndex::new(
        headers
            .load_segments()
            .filter_map(|segment| {
                let range = segment.file_range()?;
                Some((
                    segment.vaddr.wrapping_sub(segment.offset),
                    range.start,
                    range.end,
                ))
            })
            .collect(),
    );
    // Section header 0 holds the extended counts, not a section.
    for (index, section) in headers.section_headers.iter().enumerate().skip(1) {
        check_section_file_range(headers, index, section, file_size, result);
        if check_segments {
            check_section_in_segment(headers, index, section, &loads, result);
        }
        check_section_links(headers, index, section, count, result);
        check_section_alignment(headers, index, section, result);
    }
    check_string_table_index(headers, result);
}

/// Check that the section header table is in the file.
fn check_section_table(
    headers: &ElfHeaders,
    file_size: Option<u64>,
    result: &mut ValidationResult,
) {
    let Some(size) = file_size else {
        return;
    };
    let end = u64::try_from(headers.section_headers.len())
        .ok()
        .and_then(|count| count.checked_mul(u64::from(headers.header.shentsize)))
        .and_then(|table_size| headers.header.shoff.checked_add(table_size));
    if end.is_none_or(|end| end > size) {
        result.push(
            ValidationIssue::error(
                ValidationCode::SectionOutOfFile,
                format!("the section header table goes past the end of the file ({size:#x} bytes)"),
            )
            .with_context("e_shoff"),
        );
    }
}

/// Check that the file bytes of a section are in the file.
fn check_section_file_range(
    headers: &ElfHeaders,
    index: usize,
    section: &SectionHeader,
    file_size: Option<u64>,
    result: &mut ValidationResult,
) {
    let Some(size) = file_size else {
        return;
    };
    if !section.has_file_data() || section.size == 0 {
        return;
    }
    if section.file_range().is_none_or(|range| range.end > size) {
        result.push(
            ValidationIssue::error(
                ValidationCode::SectionOutOfFile,
                format!(
                    "the section data at {:#x} with {:#x} bytes goes past the end of the file ({size:#x} bytes)",
                    section.offset, section.size
                ),
            )
            .with_context(section_context(headers, index)),
        );
    }
}

/// Check that a `SHF_ALLOC` section with file bytes is in a `PT_LOAD` segment, at the same
/// distance from the segment start in the file and in memory.
fn check_section_in_segment(
    headers: &ElfHeaders,
    index: usize,
    section: &SectionHeader,
    loads: &RangeIndex,
    result: &mut ValidationResult,
) {
    if !section.is_alloc() || !section.has_file_data() || section.size == 0 {
        return;
    }
    let inside = section.file_range().is_some_and(|range| {
        loads.contains(
            section.addr.wrapping_sub(section.offset),
            range.start,
            range.end,
        )
    });
    if !inside {
        result.push(
            ValidationIssue::warning(
                ValidationCode::SectionOutsideSegment,
                format!(
                    "the SHF_ALLOC section at file offset {:#x} and address {:#x} is not in a PT_LOAD segment",
                    section.offset, section.addr
                ),
            )
            .with_context(section_context(headers, index)),
        );
    }
}

/// Check `sh_link`, and `sh_info` if the section has `SHF_INFO_LINK`.
fn check_section_links(
    headers: &ElfHeaders,
    index: usize,
    section: &SectionHeader,
    count: u64,
    result: &mut ValidationResult,
) {
    if u64::from(section.link) >= count {
        result.push(
            ValidationIssue::error(
                ValidationCode::InvalidSectionLink,
                format!(
                    "sh_link {} is not a section index ({count} sections)",
                    section.link
                ),
            )
            .with_context(section_context(headers, index)),
        );
    }
    if section.flags & SHF_INFO_LINK != 0 && u64::from(section.info) >= count {
        result.push(
            ValidationIssue::error(
                ValidationCode::InvalidSectionLink,
                format!(
                    "sh_info {} is not a section index ({count} sections)",
                    section.info
                ),
            )
            .with_context(section_context(headers, index)),
        );
    }
}

/// Check `sh_addralign` and the alignment of `sh_addr`.
fn check_section_alignment(
    headers: &ElfHeaders,
    index: usize,
    section: &SectionHeader,
    result: &mut ValidationResult,
) {
    let align = section.addralign;
    if align <= 1 {
        return;
    }
    if !align.is_power_of_two() {
        result.push(
            ValidationIssue::error(
                ValidationCode::MisalignedSection,
                format!("sh_addralign {align:#x} is not 0 or a power of 2"),
            )
            .with_context(section_context(headers, index)),
        );
        return;
    }
    if !section.addr.is_multiple_of(align) {
        result.push(
            ValidationIssue::error(
                ValidationCode::MisalignedSection,
                format!(
                    "sh_addr {:#x} is not aligned to sh_addralign {align:#x}",
                    section.addr
                ),
            )
            .with_context(section_context(headers, index)),
        );
    }
}

/// Check that `e_shstrndx` is `SHN_UNDEF` or names a `SHT_STRTAB` section.
fn check_string_table_index(headers: &ElfHeaders, result: &mut ValidationResult) {
    let index = if headers.header.shstrndx == SHN_XINDEX {
        headers
            .section_headers
            .first()
            .map_or(u32::MAX, |zero| zero.link)
    } else {
        u32::from(headers.header.shstrndx)
    };
    if index == u32::from(SHN_UNDEF) {
        return;
    }
    let valid = usize::try_from(index)
        .ok()
        .and_then(|index| headers.section_headers.get(index))
        .is_some_and(|section| section.section_type == SectionType::STRTAB);
    if !valid {
        result.push(
            ValidationIssue::error(
                ValidationCode::InvalidStringTableIndex,
                format!("e_shstrndx {index} does not name a SHT_STRTAB section"),
            )
            .with_context("e_shstrndx"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endian::Encoding;
    use crate::header::Machine;
    use crate::program::{PF_R, PF_W, PF_X};
    use crate::section::SHF_ALLOC;

    /// The size of the file that the sample headers describe.
    const FILE_SIZE: u64 = 0x3000;

    /// Return a `PT_LOAD` program header with equal file and memory sizes.
    fn load(flags: u32, offset: u64, vaddr: u64, size: u64) -> ProgramHeader {
        ProgramHeader {
            segment_type: SegmentType::LOAD,
            flags,
            offset,
            vaddr,
            paddr: vaddr,
            filesz: size,
            memsz: size,
            align: 0x1000,
        }
    }

    /// Return the headers of a valid ELF64 executable with two `PT_LOAD` segments.
    fn sample() -> ElfHeaders {
        let mut header = FileHeader::new(Encoding::ELF64_LE, FileType::EXEC, Machine::X86_64);
        header.phoff = 64;
        header.phnum = 2;
        header.entry = 0x40_1000;
        ElfHeaders {
            header,
            program_headers: vec![
                load(PF_R | PF_X, 0, 0x40_0000, 0x2000),
                load(PF_R | PF_W, 0x2000, 0x40_2000, 0x1000),
            ],
            section_headers: Vec::new(),
            section_names: Vec::new(),
        }
    }

    /// Return the sample headers with a `.text` section and a section name table.
    fn sample_with_sections() -> ElfHeaders {
        let mut headers = sample();
        headers.header.shoff = 0x2900;
        headers.header.shnum = 3;
        headers.header.shstrndx = 2;
        headers.section_headers = vec![
            SectionHeader::default(),
            SectionHeader {
                name: 1,
                section_type: SectionType::PROGBITS,
                flags: SHF_ALLOC,
                addr: 0x40_1000,
                offset: 0x1000,
                size: 0x100,
                addralign: 16,
                ..SectionHeader::default()
            },
            SectionHeader {
                name: 7,
                section_type: SectionType::STRTAB,
                offset: 0x2800,
                size: 0x20,
                addralign: 1,
                ..SectionHeader::default()
            },
        ];
        headers.section_names = vec![String::new(), ".text".to_string(), ".shstrtab".to_string()];
        headers
    }

    /// Validate `headers` against a file of `FILE_SIZE` bytes.
    fn check(headers: &ElfHeaders) -> ValidationResult {
        let mut result = ValidationResult::new();
        validate_headers(headers, Some(FILE_SIZE), &mut result);
        result
    }

    #[test]
    fn valid_headers_have_no_issues() {
        assert!(check(&sample()).is_ok(), "{:?}", check(&sample()));
        let result = check(&sample_with_sections());
        assert!(result.is_ok(), "{result:?}");
        // Without a file size, the file range checks do not occur.
        let mut headers = sample_with_sections();
        headers.header.shoff = FILE_SIZE;
        headers.section_headers[2].offset = FILE_SIZE;
        let mut result = ValidationResult::new();
        validate_headers(&headers, None, &mut result);
        assert!(result.is_ok(), "{result:?}");
    }

    /// Return the context of the first issue with `code`.
    fn context_of(result: &ValidationResult, code: ValidationCode) -> Option<&str> {
        result
            .iter()
            .find(|issue| issue.code == code)
            .and_then(|issue| issue.context.as_deref())
    }

    #[test]
    fn detects_header_tables_out_of_file() {
        let mut headers = sample();
        headers.header.phoff = FILE_SIZE - 0x10;
        let result = check(&headers);
        assert_eq!(
            context_of(&result, ValidationCode::SegmentOutOfFile),
            Some("e_phoff")
        );

        let mut headers = sample_with_sections();
        headers.header.shoff = u64::MAX - 0x10;
        let result = check(&headers);
        assert_eq!(
            context_of(&result, ValidationCode::SectionOutOfFile),
            Some("e_shoff")
        );
    }

    #[test]
    fn detects_segment_out_of_file() {
        let mut result = ValidationResult::new();
        validate_headers(&sample(), Some(0x2800), &mut result);
        assert!(result.contains(ValidationCode::SegmentOutOfFile));
        let mut result = ValidationResult::new();
        validate_headers(&sample(), None, &mut result);
        assert!(result.is_ok());
    }

    #[test]
    fn detects_overlapping_and_unsorted_loads() {
        let mut headers = sample();
        headers.program_headers[1].vaddr = 0x40_1000;
        let result = check(&headers);
        assert!(result.contains(ValidationCode::OverlappingSegments));
        assert!(!result.contains(ValidationCode::MisalignedSegment));

        let mut headers = sample();
        headers.program_headers.swap(0, 1);
        let result = check(&headers);
        assert!(result.contains(ValidationCode::UnsortedSegments));
        assert!(!result.has_errors(), "{result:?}");
    }

    #[test]
    fn detects_misaligned_segment() {
        let mut headers = sample();
        headers.program_headers[1].vaddr = 0x40_2010;
        assert!(check(&headers).contains(ValidationCode::MisalignedSegment));
        let mut headers = sample();
        headers.program_headers[1].align = 0x3000;
        assert!(check(&headers).contains(ValidationCode::MisalignedSegment));
    }

    #[test]
    fn warns_about_a_segment_that_is_not_congruent_modulo_4_kib() {
        let mut headers = sample();
        headers.program_headers[1].vaddr = 0x40_2010;
        headers.program_headers[1].align = 0x10;
        let result = check(&headers);
        assert!(result.contains(ValidationCode::MisalignedSegment));
        assert!(!result.has_errors(), "{result:?}");
        headers.header.file_type = FileType::CORE;
        assert!(!check(&headers).contains(ValidationCode::MisalignedSegment));
    }

    #[test]
    fn detects_entry_point_out_of_bounds() {
        let mut headers = sample();
        headers.header.entry = 0x40_2010;
        assert!(check(&headers).contains(ValidationCode::EntryPointOutOfBounds));
        headers.header.file_type = FileType::CORE;
        assert!(!check(&headers).contains(ValidationCode::EntryPointOutOfBounds));
    }

    #[test]
    fn accepts_a_ppc64_elfv1_entry_point_in_a_data_segment() {
        // The ELFv1 entry point is a function descriptor in `.opd`, in a data segment.
        let mut headers = sample();
        headers.header.machine = Machine::PPC64;
        headers.header.entry = 0x40_2010;
        for flags in [0, 1] {
            headers.header.flags = flags;
            assert!(check(&headers).is_ok(), "{:?}", check(&headers));
        }
        headers.header.entry = 0x50_0000;
        assert!(check(&headers).contains(ValidationCode::EntryPointOutOfBounds));
        // The ELFv2 entry point is code.
        headers.header.flags = 2;
        headers.header.entry = 0x40_2010;
        assert!(check(&headers).contains(ValidationCode::EntryPointOutOfBounds));
    }

    #[test]
    fn detects_segment_type_problems() {
        let mut headers = sample();
        headers.program_headers[1].filesz = 0x1001;
        assert!(check(&headers).contains(ValidationCode::SegmentFileSizeTooLarge));

        let mut headers = sample();
        let dynamic = ProgramHeader {
            segment_type: SegmentType::DYNAMIC,
            align: 8,
            ..load(PF_R, 0x2000, 0x50_0000, 0x100)
        };
        headers.program_headers.extend([dynamic, dynamic]);
        let result = check(&headers);
        assert!(result.contains(ValidationCode::DuplicateSegment));
        assert!(result.contains(ValidationCode::SegmentNotLoaded));

        let mut headers = sample();
        headers.program_headers.clear();
        assert!(check(&headers).contains(ValidationCode::InconsistentFileType));
    }

    #[test]
    fn detects_header_problems() {
        let mut headers = sample();
        headers.header.version = 2;
        assert!(check(&headers).contains(ValidationCode::UnsupportedVersion));

        let mut headers = sample();
        headers.header.phentsize = 60;
        let result = check(&headers);
        assert!(result.contains(ValidationCode::InvalidHeaderSize));
        assert!(!result.has_errors());
        headers.header.phentsize = 40;
        assert!(check(&headers).has_errors());
    }

    #[test]
    fn detects_section_outside_segment() {
        let mut headers = sample_with_sections();
        headers.section_headers[1].addr = 0x40_5000;
        let result = check(&headers);
        assert!(result.contains(ValidationCode::SectionOutsideSegment));
        assert!(!result.has_errors(), "{result:?}");
        headers.header.file_type = FileType::REL;
        headers.header.entry = 0;
        assert!(!check(&headers).contains(ValidationCode::SectionOutsideSegment));
    }

    #[test]
    fn detects_section_problems() {
        let mut headers = sample_with_sections();
        headers.section_headers[1].offset = 0x2f80;
        assert!(check(&headers).contains(ValidationCode::SectionOutOfFile));

        let mut headers = sample_with_sections();
        headers.section_headers[1].link = 9;
        assert!(check(&headers).contains(ValidationCode::InvalidSectionLink));

        let mut headers = sample_with_sections();
        headers.section_headers[1].flags |= SHF_INFO_LINK;
        headers.section_headers[1].info = 3;
        assert!(check(&headers).contains(ValidationCode::InvalidSectionLink));
        headers.section_headers[1].info = 2;
        assert!(check(&headers).is_ok());

        let mut headers = sample_with_sections();
        headers.header.shstrndx = 1;
        assert!(check(&headers).contains(ValidationCode::InvalidStringTableIndex));
        headers.header.shstrndx = SHN_UNDEF;
        assert!(check(&headers).is_ok());

        let mut headers = sample_with_sections();
        headers.section_headers[1].addralign = 3;
        assert!(check(&headers).contains(ValidationCode::MisalignedSection));

        let mut headers = sample_with_sections();
        headers.section_headers[1].addr = 0x40_1004;
        headers.section_headers[1].offset = 0x1004;
        let result = check(&headers);
        assert!(result.contains(ValidationCode::MisalignedSection));
        assert!(!result.contains(ValidationCode::SectionOutsideSegment));
    }

    #[test]
    fn range_index_finds_containing_ranges() {
        let index = RangeIndex::new(vec![
            (0, 0x100, 0x200),
            (0, 0x150, 0x180),
            (1, 0x400, 0x500),
        ]);
        assert!(index.contains(0, 0x160, 0x1f0));
        assert!(index.contains(0, 0x100, 0x200));
        assert!(!index.contains(0, 0x1f0, 0x210));
        assert!(!index.contains(0, 0x80, 0x90));
        assert!(index.contains(1, 0x400, 0x500));
        assert!(!index.contains(2, 0x400, 0x500));
        assert!(!RangeIndex::default().contains(0, 0, 0));
    }
}
