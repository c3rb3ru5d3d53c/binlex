// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::*;

pub(super) fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or("");
    match instruction.id().0 {
        id if id == Arm64Insn::ARM64_INS_ADR as u32 || id == Arm64Insn::ARM64_INS_ADRP as u32 => {
            build_move(machine, operands)
        }
        id if id == Arm64Insn::ARM64_INS_MOV as u32 => build_move(machine, operands),
        _ if mnemonic == "movk" => build_movk(machine, operands),
        _ if mnemonic == "movz" => build_movz(machine, operands),
        _ if mnemonic == "movn" => build_movn(machine, operands),
        id if id == Arm64Insn::ARM64_INS_ADD as u32 || mnemonic == "adds" => build_binary_assign(
            machine,
            operands,
            SemanticOperationBinary::Add,
            mnemonic == "adds",
        ),
        _ if mnemonic == "adc" => build_adc(machine, operands),
        id if id == Arm64Insn::ARM64_INS_SUB as u32 || mnemonic == "subs" => build_binary_assign(
            machine,
            operands,
            SemanticOperationBinary::Sub,
            mnemonic == "subs",
        ),
        _ if mnemonic == "sbc" => build_sbc(machine, operands),
        id if id == Arm64Insn::ARM64_INS_AND as u32 || mnemonic == "ands" => build_binary_assign(
            machine,
            operands,
            SemanticOperationBinary::And,
            mnemonic == "ands",
        ),
        _ if mnemonic == "eon" => build_eon(machine, operands),
        id if id == Arm64Insn::ARM64_INS_ORR as u32 => {
            build_binary_assign(machine, operands, SemanticOperationBinary::Or, false)
        }
        _ if mnemonic == "orn" => build_orn(machine, operands),
        id if id == Arm64Insn::ARM64_INS_EOR as u32 => {
            build_binary_assign(machine, operands, SemanticOperationBinary::Xor, false)
        }
        _ if mnemonic == "lsl" => {
            build_shift_assign(machine, operands, SemanticOperationBinary::Shl)
        }
        _ if mnemonic == "lsr" => {
            build_shift_assign(machine, operands, SemanticOperationBinary::LShr)
        }
        _ if mnemonic == "csel" => build_conditional_select(machine, operands, condition_code),
        _ if mnemonic == "cset" => build_cset(machine, operands, condition_code),
        _ if mnemonic == "csetm" => build_csetm(machine, operands, condition_code),
        _ if mnemonic == "csinc" => {
            build_conditional_select_increment(machine, operands, condition_code)
        }
        _ if mnemonic == "cinc" => build_conditional_increment(machine, operands, condition_code),
        _ if mnemonic == "csinv" => {
            build_conditional_select_invert(machine, operands, condition_code)
        }
        _ if mnemonic == "csneg" => {
            build_conditional_select_negate(machine, operands, condition_code)
        }
        _ if mnemonic == "cneg" => build_conditional_negate(machine, operands, condition_code),
        _ if mnemonic == "fcsel" => build_conditional_select(machine, operands, condition_code),
        _ if mnemonic == "sxtw" => build_sign_extend_word(machine, operands),
        _ if mnemonic == "sxtb" => build_sign_extend_byte(machine, operands),
        _ if mnemonic == "sxth" => build_sign_extend_halfword(machine, operands),
        _ if mnemonic == "asr" => {
            build_shift_assign(machine, operands, SemanticOperationBinary::AShr)
        }
        _ if mnemonic == "ror" => {
            build_shift_assign(machine, operands, SemanticOperationBinary::RotateRight)
        }
        _ if mnemonic == "ubfx" => {
            build_unsigned_bitfield_extract(machine, operands).or_else(|| {
                build_intrinsic_fallthrough(
                    machine,
                    instruction,
                    operands,
                    Some(vec![operand_location(machine, operands.first()?)?]),
                )
            })
        }
        _ if mnemonic == "sbfx" => build_signed_bitfield_extract(machine, operands).or_else(|| {
            build_intrinsic_fallthrough(
                machine,
                instruction,
                operands,
                Some(vec![operand_location(machine, operands.first()?)?]),
            )
        }),
        _ if mnemonic == "ubfiz" => {
            build_unsigned_bitfield_insert(machine, operands).or_else(|| {
                build_intrinsic_fallthrough(
                    machine,
                    instruction,
                    operands,
                    Some(vec![operand_location(machine, operands.first()?)?]),
                )
            })
        }
        _ if mnemonic == "bfi" => build_bitfield_insert(machine, operands).or_else(|| {
            build_intrinsic_fallthrough(
                machine,
                instruction,
                operands,
                Some(vec![operand_location(machine, operands.first()?)?]),
            )
        }),
        _ if mnemonic == "bfxil" => build_bitfield_insert_low(machine, operands).or_else(|| {
            build_intrinsic_fallthrough(
                machine,
                instruction,
                operands,
                Some(vec![operand_location(machine, operands.first()?)?]),
            )
        }),
        _ if mnemonic == "sbfiz" => build_signed_bitfield_insert(machine, operands).or_else(|| {
            build_intrinsic_fallthrough(
                machine,
                instruction,
                operands,
                Some(vec![operand_location(machine, operands.first()?)?]),
            )
        }),
        _ if mnemonic == "clz" => build_clz(machine, operands),
        id if id == Arm64Insn::ARM64_INS_CMP as u32 => build_compare_flags(machine, operands),
        _ if mnemonic == "cmn" => build_compare_add_flags(machine, operands),
        _ if mnemonic == "ccmp" => build_conditional_compare(
            machine,
            operands,
            condition_code,
            SemanticOperationBinary::Sub,
        ),
        _ if mnemonic == "ccmn" => build_conditional_compare(
            machine,
            operands,
            condition_code,
            SemanticOperationBinary::Add,
        ),
        _ if mnemonic == "bic" => build_bic(machine, operands),
        _ if mnemonic == "bics" => build_bics(machine, operands),
        id if id == Arm64Insn::ARM64_INS_TST as u32 => build_test_flags(instruction, operands),
        _ if mnemonic == "rbit" => build_rbit(machine, operands),
        _ if mnemonic == "rev" => build_rev(machine, operands),
        _ if mnemonic == "rev16" => build_rev16(machine, operands),
        _ if mnemonic == "rev32" => build_rev32(machine, operands),
        _ if mnemonic == "mvn" => build_mvn(machine, operands),
        _ if mnemonic == "neg" => build_neg(machine, operands),
        _ if mnemonic == "uxtb" => build_zero_extend_byte(machine, operands),
        _ if mnemonic == "uxth" => build_zero_extend_halfword(machine, operands),
        _ => None,
    }
}
