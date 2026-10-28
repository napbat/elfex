//! Make a loader-mapped image for a runtime base and apply the relative relocations.

use super::ElfImage;
use crate::elf::SourceLayout;
use crate::endian::Encoding;
use crate::prelude::*;
use crate::reloc::Relocation;
use crate::{Error, Result};

/// Change the class-sized words of a mapped image at virtual addresses.
struct Patcher<'a> {
    /// The mapped image. Offset 0 is the image origin.
    image: &'a mut [u8],
    /// The virtual address of offset 0.
    origin: u64,
    /// The class and the byte order.
    encoding: Encoding,
}

impl Patcher<'_> {
    /// Return the offset in the image of the word at the virtual address `vaddr`.
    fn offset(&self, vaddr: u64) -> Result<usize> {
        let word = self.encoding.addr_size();
        vaddr
            .checked_sub(self.origin)
            .and_then(|offset| usize::try_from(offset).ok())
            .filter(|offset| {
                offset
                    .checked_add(word)
                    .is_some_and(|end| end <= self.image.len())
            })
            .ok_or_else(|| Error::invalid_address(vaddr).in_structure("relocation offset"))
    }

    /// Cut `value` to the class size: ELF32 address arithmetic wraps at 32 bits.
    fn wrap(&self, value: u64) -> u64 {
        if self.encoding.is_64bit() {
            value
        } else {
            value & u64::from(u32::MAX)
        }
    }

    /// Write `value` to the word at `vaddr`.
    fn write(&mut self, vaddr: u64, value: u64) -> Result<()> {
        let offset = self.offset(vaddr)?;
        let value = self.wrap(value);
        self.encoding.put_addr(self.image, offset, value)
    }

    /// Add `delta` to the word at `vaddr`.
    fn add(&mut self, vaddr: u64, delta: u64) -> Result<()> {
        let offset = self.offset(vaddr)?;
        let value = self.encoding.read_addr(self.image, offset)?;
        let value = self.wrap(value.wrapping_add(delta));
        self.encoding.put_addr(self.image, offset, value)
    }
}

impl ElfImage {
    /// Make a loader-mapped image for the runtime base `runtime_base`, and apply the relative
    /// relocations.
    ///
    /// The function starts from [`Self::to_mapped_image`]. The new load bias is
    /// `runtime_base` minus the image origin. The current load bias is [`Self::load_bias`]
    /// for a loader-mapped source with a known runtime base, and 0 for all other images.
    /// The function applies only these relocations, in this order:
    ///
    /// 1. Each relative `Rela` entry (`Relocation::is_relative`) of `DT_RELA` and
    ///    `DT_JMPREL`: write the new load bias plus the addend to the word.
    /// 2. Each relative `Rel` entry of `DT_REL` and `DT_JMPREL`: add the new load bias minus
    ///    the current load bias to the word.
    /// 3. Each `DT_RELR` address: add the new load bias minus the current load bias to the
    ///    word.
    ///
    /// The words are class-sized. In an ELF32 image, the arithmetic wraps at 32 bits, as
    /// on the target. A machine without a relative relocation type (for example MIPS) gets
    /// only the `RELR` relocations. The function does not change the dynamic table.
    ///
    /// # Errors
    ///
    /// - Return an error for the same conditions as [`Self::to_mapped_image`] and
    ///   [`Self::dynamic_relocations`].
    /// - Return [`ErrorKind::InvalidAddress`](crate::ErrorKind::InvalidAddress) if a
    ///   relocated word is outside the mapped image.
    pub fn to_mapped_image_at(&self, runtime_base: u64) -> Result<Vec<u8>> {
        let mut image = self.to_mapped_image()?;
        let origin = self.image_origin().ok_or_else(|| {
            Error::invalid_segment("the image has no PT_LOAD segment with a defined origin")
        })?;
        let new_bias = runtime_base.wrapping_sub(origin);
        let current_bias = match self.source_layout {
            SourceLayout::Mapped => self.load_bias().unwrap_or(0),
            SourceLayout::File => 0,
        };
        let delta = new_bias.wrapping_sub(current_bias);
        let relocations = self.dynamic_relocations()?;
        let machine = self.machine();
        let mut patcher = Patcher {
            image: &mut image,
            origin,
            encoding: self.encoding(),
        };
        for relocation in relocations
            .iter()
            .filter(|relocation| relocation.is_relative(machine))
        {
            apply_relative(&mut patcher, relocation, new_bias, delta)?;
        }
        for &address in relocations.relr.iter().flatten() {
            patcher.add(address, delta)?;
        }
        Ok(image)
    }
}

/// Apply one relative relocation: write `new_bias` plus the addend of a `Rela` entry, or add
/// `delta` to the word of a `Rel` entry.
fn apply_relative(
    patcher: &mut Patcher<'_>,
    relocation: &Relocation,
    new_bias: u64,
    delta: u64,
) -> Result<()> {
    match relocation.addend {
        Some(addend) => patcher.write(relocation.offset, new_bias.wrapping_add_signed(addend)),
        None => patcher.add(relocation.offset, delta),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorKind;

    fn patcher(image: &mut [u8], encoding: Encoding) -> Patcher<'_> {
        Patcher {
            image,
            origin: 0x1000,
            encoding,
        }
    }

    #[test]
    fn rela_writes_bias_plus_addend() {
        let mut image = vec![0xaa; 16];
        let mut patch = patcher(&mut image, Encoding::ELF64_LE);
        let relocation = Relocation::with_addend(0x1008, 0, 8, -0x10);
        apply_relative(&mut patch, &relocation, 0x5000, 0).unwrap();
        assert_eq!(image[..8], [0xaa; 8]);
        assert_eq!(image[8..], 0x4ff0_u64.to_le_bytes());
    }

    #[test]
    fn rel_adds_delta_and_wraps_elf32() {
        let mut image = vec![0; 8];
        Encoding::ELF32_BE
            .put_u32(&mut image, 4, 0xffff_fff0)
            .unwrap();
        let mut patch = patcher(&mut image, Encoding::ELF32_BE);
        let relocation = Relocation::new(0x1004, 0, 22);
        apply_relative(&mut patch, &relocation, 0, 0x20).unwrap();
        assert_eq!(Encoding::ELF32_BE.read_u32(&image, 4).unwrap(), 0x10);
    }

    #[test]
    fn rela_wraps_elf32() {
        let mut image = vec![0; 4];
        let mut patch = patcher(&mut image, Encoding::ELF32_LE);
        let relocation = Relocation::with_addend(0x1000, 0, 8, 0x30);
        apply_relative(&mut patch, &relocation, 0xffff_fff0, 0).unwrap();
        assert_eq!(Encoding::ELF32_LE.read_u32(&image, 0).unwrap(), 0x20);
    }

    #[test]
    fn offsets_outside_the_image_fail() {
        let mut image = vec![0; 8];
        let mut patch = patcher(&mut image, Encoding::ELF64_LE);
        for vaddr in [0x0fff, 0x1001, u64::MAX] {
            let error = patch.add(vaddr, 1).unwrap_err();
            assert!(matches!(error.kind(), ErrorKind::InvalidAddress(a) if *a == vaddr));
        }
        patch.add(0x1000, 1).unwrap();
        assert_eq!(image, 1_u64.to_le_bytes());
    }
}
