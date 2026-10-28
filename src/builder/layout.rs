//! Lay out the sections and segments of an [`ElfBuilder`] and serialize the file.

use super::{
    BuilderLayout, BuilderSection, DEFAULT_EXEC_BASE, ElfBuilder, EntryPoint, SectionPlacement,
};
use crate::endian::Encoding;
use crate::header::{FileHeader, FileType};
use crate::prelude::*;
use crate::program::{PF_R, PF_W, PF_X, ProgramHeader, SegmentType};
use crate::section::{
    SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHN_LORESERVE, SHN_XINDEX, SectionHeader, SectionType,
};
use crate::{Error, Result};

/// The name of the section name string table.
const SHSTRTAB_NAME: &str = ".shstrtab";

/// The name of the interpreter section.
const INTERP_NAME: &str = ".interp";

/// The `p_align` value of the `PT_GNU_STACK` segment.
const GNU_STACK_ALIGN: u64 = 16;

/// A section with its header in the output order. The header has no `sh_name` and no
/// `sh_link` yet.
struct Placed<'a> {
    section: &'a BuilderSection,
    header: SectionHeader,
}

/// The sections and the `PT_LOAD` segments of the file.
struct Layout<'a> {
    /// The sections in section header order, without the null section and `.shstrtab`.
    sections: Vec<Placed<'a>>,
    /// The `PT_LOAD` program headers, sorted by virtual address.
    loads: Vec<ProgramHeader>,
    /// The file offset after the data of the last section.
    file_end: u64,
}

/// The fixed sizes of the file header and the program header table.
struct HeaderSizes {
    /// The size of the file header (`e_ehsize`).
    ehsize: u64,
    /// The number of program headers.
    phnum: u16,
    /// The file offset after the program header table.
    end: u64,
}

/// The planned file of a builder: the headers and the layout, without the file bytes.
struct Plan<'a> {
    /// The sections and the `PT_LOAD` segments.
    layout: Layout<'a>,
    /// The file header.
    header: FileHeader,
    /// The program headers.
    program_headers: Vec<ProgramHeader>,
    /// The section headers, from the null section to `.shstrtab`.
    section_headers: Vec<SectionHeader>,
    /// The content of `.shstrtab`.
    shstrtab: Vec<u8>,
}

/// Return the `.interp` section of `builder`, if it has an interpreter.
fn interp_section(builder: &ElfBuilder) -> Option<BuilderSection> {
    builder.interpreters.first().map(|path| {
        let mut data = path.as_bytes().to_vec();
        data.push(0);
        BuilderSection::progbits(INTERP_NAME, SHF_ALLOC, data)
    })
}

/// Lay out the file of `builder` and make all headers. `interp` is the `.interp` section.
fn plan<'a>(builder: &'a ElfBuilder, interp: Option<&'a BuilderSection>) -> Result<Plan<'a>> {
    check_input(builder)?;
    let encoding = builder.encoding;
    let sizes = header_sizes(builder, interp.is_some())?;
    let base = builder
        .base_address
        .unwrap_or(if builder.file_type == FileType::EXEC {
            DEFAULT_EXEC_BASE
        } else {
            0
        });
    let layout = layout_sections(builder, interp, sizes.end, base)?;
    let program_headers = program_headers(builder, &layout, &sizes, base)?;
    check_class_range(encoding, &program_headers)?;

    let (mut section_headers, shstrtab) = section_headers(&layout)?;
    let shstrndx = section_headers.len().saturating_sub(1);
    let addr_size = to_u64(encoding.addr_size());
    let shoff = align_up(add(layout.file_end, to_u64(shstrtab.len()))?, addr_size)?;

    let mut header = FileHeader::new(encoding, builder.file_type, builder.machine);
    header.ident.os_abi = builder.os_abi;
    header.flags = builder.flags;
    header.entry = entry_point(builder, &layout)?;
    header.phoff = sizes.ehsize;
    header.phnum = sizes.phnum;
    header.shoff = shoff;
    set_section_counts(&mut header, &mut section_headers, shstrndx)?;
    Ok(Plan {
        layout,
        header,
        program_headers,
        section_headers,
        shstrtab,
    })
}

/// Lay out the file of `builder` and return the placement of each section.
pub(super) fn preview(builder: &ElfBuilder) -> Result<BuilderLayout> {
    let interp = interp_section(builder);
    let plan = plan(builder, interp.as_ref())?;
    let names = plan
        .layout
        .sections
        .iter()
        .map(|placed| placed.section.name.as_str())
        .chain([SHSTRTAB_NAME]);
    // Section 0 is the null section. The other headers follow the order of `names`.
    let sections = names
        .zip(plan.section_headers.iter().enumerate().skip(1))
        .map(|(name, (index, header))| {
            let placement = SectionPlacement {
                index,
                addr: header.addr,
                offset: header.offset,
                size: header.size,
            };
            (String::from(name), placement)
        })
        .collect();
    let entry = match builder.entry {
        EntryPoint::None => None,
        EntryPoint::Address(_) | EntryPoint::Section { .. } => Some(plan.header.entry),
    };
    Ok(BuilderLayout { sections, entry })
}

/// Lay out and serialize the file of `builder`.
pub(super) fn write(builder: &ElfBuilder) -> Result<Vec<u8>> {
    let interp = interp_section(builder);
    let plan = plan(builder, interp.as_ref())?;
    let encoding = builder.encoding;
    let mut out = Vec::new();
    plan.header.write(&mut out)?;
    for segment in &plan.program_headers {
        segment.write(&mut out, encoding)?;
    }
    for placed in &plan.layout.sections {
        if placed.header.has_file_data() {
            put(&mut out, placed.header.offset, &placed.section.data)?;
        }
    }
    put(&mut out, plan.layout.file_end, &plan.shstrtab)?;
    let mut table = Vec::new();
    for section in &plan.section_headers {
        section.write(&mut table, encoding)?;
    }
    put(&mut out, plan.header.shoff, &table)?;
    Ok(out)
}

/// Check the builder input that the layout does not check.
fn check_input(builder: &ElfBuilder) -> Result<()> {
    if !builder.page_size.is_power_of_two() {
        return Err(Error::invalid_segment(format!(
            "the page size {:#x} is not a power of two",
            builder.page_size
        )));
    }
    if builder.interpreters.len() > 1 {
        return Err(Error::invalid_section(
            "the builder has more than one interpreter",
        ));
    }
    if builder
        .interpreters
        .iter()
        .any(|path| path.as_bytes().contains(&0))
    {
        return Err(Error::invalid_section(
            "the interpreter path contains a NUL byte",
        ));
    }
    for section in &builder.sections {
        if section.name == SHSTRTAB_NAME {
            return Err(Error::invalid_section(
                "the builder makes the .shstrtab section: do not add it",
            ));
        }
        if section.name == INTERP_NAME && !builder.interpreters.is_empty() {
            return Err(Error::invalid_section(
                "the builder has an interpreter and a .interp section",
            ));
        }
        if section.name.as_bytes().contains(&0) {
            return Err(Error::invalid_section("a section name contains a NUL byte"));
        }
        if section.addralign > 1 && !section.addralign.is_power_of_two() {
            return Err(Error::invalid_section(format!(
                "the alignment {:#x} of section {} is not 0 or a power of two",
                section.addralign, section.name
            )));
        }
        if section.section_type == SectionType::NOBITS && !section.data.is_empty() {
            return Err(Error::invalid_section(format!(
                "the SHT_NOBITS section {} has data",
                section.name
            )));
        }
    }
    Ok(())
}

/// Return the number of program headers and the size of the headers at the file start.
fn header_sizes(builder: &ElfBuilder, has_interp: bool) -> Result<HeaderSizes> {
    let class = builder.encoding.class;
    let mut groups = [false; 2];
    for section in builder
        .sections
        .iter()
        .filter(|section| section.flags & SHF_ALLOC != 0)
    {
        if section.flags & SHF_WRITE != 0 {
            groups[1] = true;
        } else if section.flags & SHF_EXECINSTR != 0 {
            groups[0] = true;
        }
    }
    let loads = 1 + groups.iter().filter(|present| **present).count();
    let phnum = 1
        + usize::from(has_interp)
        + loads
        + builder.segments.len()
        + usize::from(builder.gnu_stack.is_some());
    let phnum = u16::try_from(phnum)
        .ok()
        .filter(|phnum| *phnum < crate::program::PN_XNUM)
        .ok_or_else(|| Error::value_out_of_range("the builder has too many segments"))?;
    let ehsize = to_u64(FileHeader::size(class));
    let table = u64::from(phnum)
        .checked_mul(to_u64(ProgramHeader::size(class)))
        .ok_or_else(overflow)?;
    Ok(HeaderSizes {
        ehsize,
        phnum,
        end: add(ehsize, table)?,
    })
}

/// Place all sections and make the `PT_LOAD` program headers.
fn layout_sections<'a>(
    builder: &'a ElfBuilder,
    interp: Option<&'a BuilderSection>,
    headers_end: u64,
    base: u64,
) -> Result<Layout<'a>> {
    let page = builder.page_size;
    let mut read: Vec<&BuilderSection> = interp.into_iter().collect();
    let mut exec = Vec::new();
    let mut write = Vec::new();
    let mut other = Vec::new();
    for section in &builder.sections {
        if section.flags & SHF_ALLOC == 0 {
            other.push(section);
        } else if section.flags & SHF_WRITE != 0 {
            write.push(section);
        } else if section.flags & SHF_EXECINSTR != 0 {
            exec.push(section);
        } else {
            read.push(section);
        }
    }

    let mut placed = Vec::new();
    if !base.is_multiple_of(group_align(&read, page)) {
        return Err(Error::invalid_segment(format!(
            "the base address {base:#x} is not aligned to the page size and the section alignments"
        )));
    }
    let (file_end, mem_end) = place_sections(&read, 0, base, headers_end, &mut placed)?;
    let mut loads = vec![load(PF_R, 0, base, file_end, mem_end, page)?];
    let mut cursor = file_end;
    let mut memory = mem_end;
    for (group, flags) in [(&exec, PF_R | PF_X), (&write, PF_R | PF_W)] {
        if group.is_empty() {
            continue;
        }
        let align = group_align(group, page);
        let first_align = group
            .iter()
            .find(|section| section.section_type != SectionType::NOBITS)
            .map_or(1, |section| section.addralign);
        let offset = align_up(cursor, first_align)?;
        let vaddr = add(align_up(memory, align)?, offset % align)?;
        let (file_end, mem_end) = place_sections(group, offset, vaddr, offset, &mut placed)?;
        loads.push(load(flags, offset, vaddr, file_end, mem_end, page)?);
        cursor = file_end;
        memory = mem_end;
    }
    for section in other {
        let offset = if section.section_type == SectionType::NOBITS {
            cursor
        } else {
            let offset = align_up(cursor, section.addralign)?;
            cursor = add(offset, section.section_size())?;
            offset
        };
        placed.push(Placed {
            section,
            header: section_header(section, offset, 0),
        });
    }
    Ok(Layout {
        sections: placed,
        loads,
        file_end: cursor,
    })
}

/// Return the alignment of a segment start: the page size, or a larger section alignment.
fn group_align(sections: &[&BuilderSection], page: u64) -> u64 {
    sections
        .iter()
        .map(|section| section.addralign)
        .fold(page, u64::max)
}

/// Place the sections of one segment. The segment starts at file offset `segment_offset`
/// and virtual address `segment_vaddr`. The first section goes at or after file offset
/// `cursor`. Return the end of the file bytes and the end of the memory range.
///
/// The sections with file bytes come first. The `SHT_NOBITS` sections follow in memory.
fn place_sections<'a>(
    sections: &[&'a BuilderSection],
    segment_offset: u64,
    segment_vaddr: u64,
    cursor: u64,
    placed: &mut Vec<Placed<'a>>,
) -> Result<(u64, u64)> {
    let mut file_end = cursor;
    for section in sections
        .iter()
        .copied()
        .filter(|section| section.section_type != SectionType::NOBITS)
    {
        let offset = align_up(file_end, section.addralign)?;
        let addr = add(segment_vaddr, sub(offset, segment_offset)?)?;
        placed.push(Placed {
            section,
            header: section_header(section, offset, addr),
        });
        file_end = add(offset, section.section_size())?;
    }
    let mut mem_end = add(segment_vaddr, sub(file_end, segment_offset)?)?;
    for section in sections
        .iter()
        .copied()
        .filter(|section| section.section_type == SectionType::NOBITS)
    {
        let addr = align_up(mem_end, section.addralign)?;
        placed.push(Placed {
            section,
            header: section_header(section, file_end, addr),
        });
        mem_end = add(addr, section.section_size())?;
    }
    Ok((file_end, mem_end))
}

/// Make the section header of `section` at file offset `offset` and address `addr`.
fn section_header(section: &BuilderSection, offset: u64, addr: u64) -> SectionHeader {
    SectionHeader {
        name: 0,
        section_type: section.section_type,
        flags: section.flags,
        addr,
        offset,
        size: section.section_size(),
        link: 0,
        info: section.info,
        addralign: section.addralign,
        entsize: section.entsize,
    }
}

/// Make a `PT_LOAD` program header from the start and the ends of a segment.
fn load(
    flags: u32,
    offset: u64,
    vaddr: u64,
    file_end: u64,
    mem_end: u64,
    page: u64,
) -> Result<ProgramHeader> {
    Ok(ProgramHeader {
        segment_type: SegmentType::LOAD,
        flags,
        offset,
        vaddr,
        paddr: vaddr,
        filesz: sub(file_end, offset)?,
        memsz: sub(mem_end, vaddr)?,
        align: page,
    })
}

/// Make all program headers: `PT_PHDR`, `PT_INTERP`, the `PT_LOAD` segments, the segments
/// for sections and `PT_GNU_STACK`.
fn program_headers(
    builder: &ElfBuilder,
    layout: &Layout<'_>,
    sizes: &HeaderSizes,
    base: u64,
) -> Result<Vec<ProgramHeader>> {
    let class = builder.encoding.class;
    let table_size = sub(sizes.end, sizes.ehsize)?;
    let phdr_vaddr = add(base, sizes.ehsize)?;
    let mut headers = Vec::with_capacity(usize::from(sizes.phnum));
    headers.push(ProgramHeader {
        segment_type: SegmentType::PHDR,
        flags: PF_R,
        offset: sizes.ehsize,
        vaddr: phdr_vaddr,
        paddr: phdr_vaddr,
        filesz: table_size,
        memsz: table_size,
        align: to_u64(class.addr_size()),
    });
    if !builder.interpreters.is_empty() {
        headers.push(section_segment(SegmentType::INTERP, layout, INTERP_NAME)?);
    }
    headers.extend_from_slice(&layout.loads);
    for (segment_type, name) in &builder.segments {
        headers.push(section_segment(*segment_type, layout, name)?);
    }
    if let Some(flags) = builder.gnu_stack {
        headers.push(ProgramHeader {
            segment_type: SegmentType::GNU_STACK,
            flags,
            offset: 0,
            vaddr: 0,
            paddr: 0,
            filesz: 0,
            memsz: 0,
            align: GNU_STACK_ALIGN,
        });
    }
    Ok(headers)
}

/// Make a segment of `segment_type` that covers the section `name`.
fn section_segment(
    segment_type: SegmentType,
    layout: &Layout<'_>,
    name: &str,
) -> Result<ProgramHeader> {
    let header = &find_section(layout, name)?.header;
    if !header.is_alloc() {
        return Err(Error::invalid_section(format!(
            "the {segment_type} segment needs a SHF_ALLOC section, but {name} does not have SHF_ALLOC"
        )));
    }
    let mut flags = PF_R;
    if header.is_writable() {
        flags |= PF_W;
    }
    if header.is_executable() {
        flags |= PF_X;
    }
    Ok(ProgramHeader {
        segment_type,
        flags,
        offset: header.offset,
        vaddr: header.addr,
        paddr: header.addr,
        filesz: if header.has_file_data() {
            header.size
        } else {
            0
        },
        memsz: header.size,
        align: header.addralign.max(1),
    })
}

/// Return the first placed section named `name`.
fn find_section<'l, 'a>(layout: &'l Layout<'a>, name: &str) -> Result<&'l Placed<'a>> {
    layout
        .sections
        .iter()
        .find(|placed| placed.section.name == name)
        .ok_or_else(|| Error::invalid_section(format!("the builder has no section named {name}")))
}

/// Return the entry point address.
fn entry_point(builder: &ElfBuilder, layout: &Layout<'_>) -> Result<u64> {
    match &builder.entry {
        EntryPoint::None => Ok(0),
        EntryPoint::Address(address) => Ok(*address),
        EntryPoint::Section { name, offset } => {
            let header = &find_section(layout, name)?.header;
            if !header.is_alloc() {
                return Err(Error::invalid_section(format!(
                    "the entry section {name} does not have SHF_ALLOC"
                )));
            }
            add(header.addr, *offset)
        }
    }
}

/// Make the section headers and the content of `.shstrtab`. The null section is the first
/// header, and `.shstrtab` is the last header. `.shstrtab` starts at the end of the section
/// data.
fn section_headers(layout: &Layout<'_>) -> Result<(Vec<SectionHeader>, Vec<u8>)> {
    let shstrtab_index = layout.sections.len() + 1;
    let mut strings = vec![0u8];
    let mut headers = Vec::with_capacity(shstrtab_index + 1);
    headers.push(SectionHeader::default());
    for placed in &layout.sections {
        let mut header = placed.header;
        header.name = u32::try_from(strings.len()).map_err(|_| overflow())?;
        strings.extend_from_slice(placed.section.name.as_bytes());
        strings.push(0);
        if let Some(link_name) = &placed.section.link_name {
            let index = if link_name == SHSTRTAB_NAME {
                shstrtab_index
            } else {
                layout
                    .sections
                    .iter()
                    .position(|other| other.section.name == *link_name)
                    .map(|index| index + 1)
                    .ok_or_else(|| {
                        Error::invalid_section(format!(
                            "the link name {link_name} of section {} is unknown",
                            placed.section.name
                        ))
                    })?
            };
            header.link = u32::try_from(index).map_err(|_| overflow())?;
        }
        headers.push(header);
    }
    let shstrtab_name = u32::try_from(strings.len()).map_err(|_| overflow())?;
    strings.extend_from_slice(SHSTRTAB_NAME.as_bytes());
    strings.push(0);
    headers.push(SectionHeader {
        name: shstrtab_name,
        section_type: SectionType::STRTAB,
        offset: layout.file_end,
        size: to_u64(strings.len()),
        addralign: 1,
        ..SectionHeader::default()
    });
    Ok((headers, strings))
}

/// Set `e_shnum` and `e_shstrndx`. Use extended numbering in section header 0 for large
/// values.
fn set_section_counts(
    header: &mut FileHeader,
    sections: &mut [SectionHeader],
    shstrndx: usize,
) -> Result<()> {
    let count = sections.len();
    let zero = sections.first_mut().ok_or_else(overflow)?;
    match u16::try_from(count) {
        Ok(count) if count < SHN_LORESERVE => header.shnum = count,
        _ => {
            header.shnum = 0;
            zero.size = to_u64(count);
        }
    }
    match u16::try_from(shstrndx) {
        Ok(index) if index < SHN_LORESERVE => header.shstrndx = index,
        _ => {
            header.shstrndx = SHN_XINDEX;
            zero.link = u32::try_from(shstrndx).map_err(|_| overflow())?;
        }
    }
    Ok(())
}

/// Check that each `PT_LOAD` segment fits in the address space of an ELF32 file.
fn check_class_range(encoding: Encoding, headers: &[ProgramHeader]) -> Result<()> {
    if encoding.is_64bit() {
        return Ok(());
    }
    let limit = 1u64 << 32;
    for segment in headers {
        let memory_end = add(segment.vaddr, segment.memsz)?;
        let file_end = add(segment.offset, segment.filesz)?;
        if memory_end > limit || file_end > limit {
            return Err(Error::value_out_of_range(format!(
                "the segment at {:#x} does not fit in the ELF32 address space",
                segment.vaddr
            )));
        }
    }
    Ok(())
}

/// Copy `bytes` into `out` at file offset `offset`. Extend `out` with zeros if necessary.
fn put(out: &mut Vec<u8>, offset: u64, bytes: &[u8]) -> Result<()> {
    let start = usize::try_from(offset).map_err(|_| overflow())?;
    let end = start.checked_add(bytes.len()).ok_or_else(overflow)?;
    if end > out.len() {
        out.try_reserve(end - out.len())
            .map_err(|_| Error::generic("the output file is too large to allocate"))?;
        out.resize(end, 0);
    }
    out[start..end].copy_from_slice(bytes);
    Ok(())
}

/// Round `value` up to a multiple of `align`. An alignment of 0 or 1 means no alignment.
fn align_up(value: u64, align: u64) -> Result<u64> {
    if align <= 1 {
        return Ok(value);
    }
    value.checked_next_multiple_of(align).ok_or_else(overflow)
}

/// Add two layout values, or return a `ValueOutOfRange` error on overflow.
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).ok_or_else(overflow)
}

/// Subtract two layout values, or return a `ValueOutOfRange` error on underflow.
fn sub(a: u64, b: u64) -> Result<u64> {
    a.checked_sub(b).ok_or_else(overflow)
}

/// Convert a size to `u64`. The conversion does not fail on targets with a `usize` of 64
/// bits or less.
fn to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

/// Return the error for a layout value that overflows.
fn overflow() -> Error {
    Error::value_out_of_range("the layout overflows the address space")
}
