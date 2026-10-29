//! The call frame instruction opcodes (`DW_CFA_*`) of DWARF 5 (section 6.4.2, table 7.29) and
//! the GNU extensions.
//!
//! elfex does not interpret the call frame instructions of a [`Cie`](super::Cie) or an
//! [`Fde`](super::Fde). These constants help a caller that decodes the instruction bytes.
//!
//! The three primary opcodes keep an operand in the low 6 bits of the opcode byte. Use
//! [`DW_CFA_HIGH_MASK`] to get the primary opcode and [`DW_CFA_LOW_MASK`] to get the operand.
//! If the high 2 bits are 0, the whole byte is an extended opcode.

/// The mask of the primary opcode in the high 2 bits of an opcode byte.
///
/// # Examples
///
/// ```
/// use elfex::eh_frame::{
///     DW_CFA_ADVANCE_LOC, DW_CFA_DEF_CFA_OFFSET, DW_CFA_HIGH_MASK, DW_CFA_LOW_MASK,
/// };
///
/// // `DW_CFA_advance_loc 1`, then `DW_CFA_def_cfa_offset 16`.
/// let instructions = [0x41, 0x0e, 0x10];
/// assert_eq!(instructions[0] & DW_CFA_HIGH_MASK, DW_CFA_ADVANCE_LOC);
/// assert_eq!(instructions[0] & DW_CFA_LOW_MASK, 1);
/// assert_eq!(instructions[1], DW_CFA_DEF_CFA_OFFSET);
/// ```
pub const DW_CFA_HIGH_MASK: u8 = 0xc0;
/// The mask of the operand of a primary opcode in the low 6 bits of an opcode byte.
pub const DW_CFA_LOW_MASK: u8 = 0x3f;

/// `DW_CFA_advance_loc`: a primary opcode. The low 6 bits are the delta, in units of the code
/// alignment factor.
pub const DW_CFA_ADVANCE_LOC: u8 = 0x40;
/// `DW_CFA_offset`: a primary opcode. The low 6 bits are the register, and a ULEB128 factored
/// offset follows.
pub const DW_CFA_OFFSET: u8 = 0x80;
/// `DW_CFA_restore`: a primary opcode. The low 6 bits are the register.
pub const DW_CFA_RESTORE: u8 = 0xc0;

/// `DW_CFA_nop`: no operation, for padding.
pub const DW_CFA_NOP: u8 = 0x00;
/// `DW_CFA_set_loc`: an encoded address operand.
pub const DW_CFA_SET_LOC: u8 = 0x01;
/// `DW_CFA_advance_loc1`: a 1-byte delta operand.
pub const DW_CFA_ADVANCE_LOC1: u8 = 0x02;
/// `DW_CFA_advance_loc2`: a 2-byte delta operand.
pub const DW_CFA_ADVANCE_LOC2: u8 = 0x03;
/// `DW_CFA_advance_loc4`: a 4-byte delta operand.
pub const DW_CFA_ADVANCE_LOC4: u8 = 0x04;
/// `DW_CFA_offset_extended`: ULEB128 register and ULEB128 factored offset operands.
pub const DW_CFA_OFFSET_EXTENDED: u8 = 0x05;
/// `DW_CFA_restore_extended`: a ULEB128 register operand.
pub const DW_CFA_RESTORE_EXTENDED: u8 = 0x06;
/// `DW_CFA_undefined`: a ULEB128 register operand.
pub const DW_CFA_UNDEFINED: u8 = 0x07;
/// `DW_CFA_same_value`: a ULEB128 register operand.
pub const DW_CFA_SAME_VALUE: u8 = 0x08;
/// `DW_CFA_register`: two ULEB128 register operands.
pub const DW_CFA_REGISTER: u8 = 0x09;
/// `DW_CFA_remember_state`: push the register rules on a stack.
pub const DW_CFA_REMEMBER_STATE: u8 = 0x0a;
/// `DW_CFA_restore_state`: pop the register rules from the stack.
pub const DW_CFA_RESTORE_STATE: u8 = 0x0b;
/// `DW_CFA_def_cfa`: ULEB128 register and ULEB128 offset operands.
pub const DW_CFA_DEF_CFA: u8 = 0x0c;
/// `DW_CFA_def_cfa_register`: a ULEB128 register operand.
pub const DW_CFA_DEF_CFA_REGISTER: u8 = 0x0d;
/// `DW_CFA_def_cfa_offset`: a ULEB128 offset operand.
pub const DW_CFA_DEF_CFA_OFFSET: u8 = 0x0e;
/// `DW_CFA_def_cfa_expression`: a DWARF expression block operand.
pub const DW_CFA_DEF_CFA_EXPRESSION: u8 = 0x0f;
/// `DW_CFA_expression`: ULEB128 register and DWARF expression block operands.
pub const DW_CFA_EXPRESSION: u8 = 0x10;
/// `DW_CFA_offset_extended_sf`: ULEB128 register and SLEB128 factored offset operands.
pub const DW_CFA_OFFSET_EXTENDED_SF: u8 = 0x11;
/// `DW_CFA_def_cfa_sf`: ULEB128 register and SLEB128 factored offset operands.
pub const DW_CFA_DEF_CFA_SF: u8 = 0x12;
/// `DW_CFA_def_cfa_offset_sf`: an SLEB128 factored offset operand.
pub const DW_CFA_DEF_CFA_OFFSET_SF: u8 = 0x13;
/// `DW_CFA_val_offset`: ULEB128 register and ULEB128 factored offset operands.
pub const DW_CFA_VAL_OFFSET: u8 = 0x14;
/// `DW_CFA_val_offset_sf`: ULEB128 register and SLEB128 factored offset operands.
pub const DW_CFA_VAL_OFFSET_SF: u8 = 0x15;
/// `DW_CFA_val_expression`: ULEB128 register and DWARF expression block operands.
pub const DW_CFA_VAL_EXPRESSION: u8 = 0x16;
/// `DW_CFA_GNU_args_size` (GNU): a ULEB128 size of the outgoing arguments.
pub const DW_CFA_GNU_ARGS_SIZE: u8 = 0x2e;
/// `DW_CFA_GNU_negative_offset_extended` (GNU, obsolete): ULEB128 register and ULEB128
/// offset operands. The factored offset is the negated value.
pub const DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED: u8 = 0x2f;

#[cfg(test)]
mod tests {
    use super::*;

    /// A primary opcode byte splits into the opcode and the operand. An extended opcode has no
    /// high bits.
    #[test]
    fn primary_opcodes_keep_their_operand_in_the_low_bits() {
        for primary in [DW_CFA_ADVANCE_LOC, DW_CFA_OFFSET, DW_CFA_RESTORE] {
            let byte = primary | 0x25;
            assert_eq!(byte & DW_CFA_HIGH_MASK, primary);
            assert_eq!(byte & DW_CFA_LOW_MASK, 0x25);
        }
        for extended in [
            DW_CFA_NOP,
            DW_CFA_DEF_CFA,
            DW_CFA_VAL_EXPRESSION,
            DW_CFA_GNU_ARGS_SIZE,
            DW_CFA_GNU_NEGATIVE_OFFSET_EXTENDED,
        ] {
            assert_eq!(extended & DW_CFA_HIGH_MASK, 0);
        }
    }
}
