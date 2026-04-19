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

extern crate capstone;

use crate::Architecture;
use crate::semantics::{
    InstructionSemantics, SemanticDiagnosticKind, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86Reg};

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    if is_return(instruction) {
        return Some(common::complete(
            SemanticTerminator::Return { expression: None },
            Vec::new(),
        ));
    }

    if is_call(instruction) {
        let target = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        return Some(common::complete(
            SemanticTerminator::Call {
                target,
                return_target: Some(common::const_u64(
                    instruction.address() + instruction.bytes().len() as u64,
                    common::pointer_bits(machine),
                )),
                does_return: Some(true),
            },
            Vec::new(),
        ));
    }

    if is_setcc(instruction) {
        let mnemonic = instruction.mnemonic().unwrap_or("unknown");
        let Some(dst) = operands
            .first()
            .and_then(|operand| common::operand_location(machine, operand))
        else {
            return Some(common::unsupported_with_kind(
                instruction,
                SemanticDiagnosticKind::UnsupportedOperandForm,
                "setcc destination operand not supported",
                SemanticTerminator::FallThrough,
            ));
        };
        let Some(condition) = common::condition_from_mnemonic(mnemonic) else {
            return Some(common::partial_with_effects(
                SemanticTerminator::FallThrough,
                vec![common::diagnostic(
                    SemanticDiagnosticKind::PartialFlags,
                    format!(
                        "0x{:x}: setcc condition modeled as intrinsic",
                        instruction.address()
                    ),
                )],
                vec![SemanticEffect::Set {
                    dst,
                    expression: common::condition_intrinsic(instruction),
                }],
            ));
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Set {
                dst,
                expression: condition,
            }],
        ));
    }

    if is_cmovcc(instruction) {
        let mnemonic = instruction.mnemonic().unwrap_or("unknown");
        let Some(dst) = operands
            .first()
            .and_then(|operand| common::operand_location(machine, operand))
        else {
            return Some(common::unsupported_with_kind(
                instruction,
                SemanticDiagnosticKind::UnsupportedOperandForm,
                "cmovcc destination operand not supported",
                SemanticTerminator::FallThrough,
            ));
        };
        let Some(when_true) = operands
            .get(1)
            .and_then(|operand| common::operand_expr(machine, operand))
        else {
            return Some(common::unsupported_with_kind(
                instruction,
                SemanticDiagnosticKind::UnsupportedOperandForm,
                "cmovcc source operand not supported",
                SemanticTerminator::FallThrough,
            ));
        };
        let bits = common::location_bits(&dst);
        let when_false = SemanticExpression::Read(Box::new(dst.clone()));
        let Some(condition) = common::condition_from_mnemonic(mnemonic) else {
            return Some(common::partial_with_effects(
                SemanticTerminator::FallThrough,
                vec![common::diagnostic(
                    SemanticDiagnosticKind::PartialFlags,
                    format!(
                        "0x{:x}: cmovcc condition modeled as intrinsic",
                        instruction.address()
                    ),
                )],
                vec![SemanticEffect::Set {
                    dst,
                    expression: SemanticExpression::Select {
                        condition: Box::new(common::condition_intrinsic(instruction)),
                        when_true: Box::new(when_true),
                        when_false: Box::new(when_false),
                        bits,
                    },
                }],
            ));
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Set {
                dst,
                expression: SemanticExpression::Select {
                    condition: Box::new(condition),
                    when_true: Box::new(when_true),
                    when_false: Box::new(when_false),
                    bits,
                },
            }],
        ));
    }

    if is_conditional_jump(instruction) {
        let true_target = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        let false_target = common::const_u64(
            instruction.address() + instruction.bytes().len() as u64,
            common::pointer_bits(machine),
        );
        if is_count_zero_jump(instruction) {
            let counter = count_zero_jump_location(instruction, machine);
            let counter_bits = common::location_bits(&counter);
            return Some(common::complete(
                SemanticTerminator::Branch {
                    condition: common::compare(
                        crate::semantics::SemanticOperationCompare::Eq,
                        SemanticExpression::Read(Box::new(counter)),
                        common::const_u64(0, counter_bits),
                    ),
                    true_target,
                    false_target,
                },
                Vec::new(),
            ));
        }
        let mnemonic = instruction.mnemonic().unwrap_or("unknown");
        if let Some(condition) = common::condition_from_mnemonic(mnemonic) {
            return Some(common::complete(
                SemanticTerminator::Branch {
                    condition,
                    true_target,
                    false_target,
                },
                Vec::new(),
            ));
        }
        return Some(common::partial(
            SemanticTerminator::Branch {
                condition: common::condition_intrinsic(instruction),
                true_target,
                false_target,
            },
            vec![common::diagnostic(
                SemanticDiagnosticKind::PartialFlags,
                format!(
                    "0x{:x}: branch condition modeled as intrinsic",
                    instruction.address()
                ),
            )],
        ));
    }

    if is_loop_family(instruction) {
        let true_target = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        let false_target = common::const_u64(
            instruction.address() + instruction.bytes().len() as u64,
            common::pointer_bits(machine),
        );
        let counter = loop_counter_location(machine);
        let counter_bits = common::location_bits(&counter);
        let decremented_counter = common::sub(
            SemanticExpression::Read(Box::new(counter.clone())),
            common::const_u64(1, counter_bits),
            counter_bits,
        );
        let counter_nonzero = common::compare(
            crate::semantics::SemanticOperationCompare::Ne,
            decremented_counter.clone(),
            common::const_u64(0, counter_bits),
        );
        let condition = match instruction.id() {
            InsnId(id) if id == X86Insn::X86_INS_LOOPE as u32 => {
                common::and(counter_nonzero, common::flag_expr("zf"), 1)
            }
            InsnId(id) if id == X86Insn::X86_INS_LOOPNE as u32 => common::and(
                counter_nonzero,
                common::compare(
                    crate::semantics::SemanticOperationCompare::Eq,
                    common::flag_expr("zf"),
                    common::bool_const(false),
                ),
                1,
            ),
            _ => counter_nonzero,
        };
        return Some(common::complete(
            SemanticTerminator::Branch {
                condition,
                true_target,
                false_target,
            },
            vec![SemanticEffect::Set {
                dst: counter,
                expression: decremented_counter,
            }],
        ));
    }

    if is_jump(instruction) {
        let target = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .unwrap_or_else(|| SemanticExpression::Undefined {
                bits: common::pointer_bits(machine),
            });
        return Some(common::complete(
            SemanticTerminator::Jump { target },
            Vec::new(),
        ));
    }

    None
}

fn is_jump(instruction: &Insn) -> bool {
    matches!(
        instruction.id(),
        InsnId(id)
            if [
                X86Insn::X86_INS_JMP as u32,
                X86Insn::X86_INS_LJMP as u32,
            ]
            .contains(&id)
    )
}

fn is_conditional_jump(instruction: &Insn) -> bool {
    matches!(
        instruction.id(),
        InsnId(id)
            if [
                X86Insn::X86_INS_JAE as u32,
                X86Insn::X86_INS_JA as u32,
                X86Insn::X86_INS_JBE as u32,
                X86Insn::X86_INS_JB as u32,
                X86Insn::X86_INS_JCXZ as u32,
                X86Insn::X86_INS_JECXZ as u32,
                X86Insn::X86_INS_JE as u32,
                X86Insn::X86_INS_JGE as u32,
                X86Insn::X86_INS_JG as u32,
                X86Insn::X86_INS_JLE as u32,
                X86Insn::X86_INS_JL as u32,
                X86Insn::X86_INS_JNE as u32,
                X86Insn::X86_INS_JNO as u32,
                X86Insn::X86_INS_JNP as u32,
                X86Insn::X86_INS_JNS as u32,
                X86Insn::X86_INS_JO as u32,
                X86Insn::X86_INS_JP as u32,
                X86Insn::X86_INS_JRCXZ as u32,
                X86Insn::X86_INS_JS as u32,
            ]
            .contains(&id)
    )
}

fn is_loop_family(instruction: &Insn) -> bool {
    matches!(
        instruction.id(),
        InsnId(id)
            if [
                X86Insn::X86_INS_LOOP as u32,
                X86Insn::X86_INS_LOOPE as u32,
                X86Insn::X86_INS_LOOPNE as u32,
            ]
            .contains(&id)
    )
}

fn is_count_zero_jump(instruction: &Insn) -> bool {
    matches!(
        instruction.id(),
        InsnId(id)
            if [
                X86Insn::X86_INS_JCXZ as u32,
                X86Insn::X86_INS_JECXZ as u32,
                X86Insn::X86_INS_JRCXZ as u32,
            ]
            .contains(&id)
    )
}

fn count_zero_jump_location(instruction: &Insn, machine: Architecture) -> SemanticLocation {
    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_JCXZ as u32 => {
            common::reg(common::reg_id_name(X86Reg::X86_REG_CX as u16), 16)
        }
        InsnId(id) if id == X86Insn::X86_INS_JECXZ as u32 => {
            common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32)
        }
        InsnId(id) if id == X86Insn::X86_INS_JRCXZ as u32 => {
            common::reg(common::reg_id_name(X86Reg::X86_REG_RCX as u16), 64)
        }
        _ => loop_counter_location(machine),
    }
}

fn loop_counter_location(machine: Architecture) -> SemanticLocation {
    match machine {
        Architecture::AMD64 => common::reg(common::reg_id_name(X86Reg::X86_REG_RCX as u16), 64),
        Architecture::I386 => common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
        _ => common::reg(common::reg_id_name(X86Reg::X86_REG_CX as u16), 16),
    }
}

fn is_call(instruction: &Insn) -> bool {
    matches!(
        instruction.id(),
        InsnId(id)
            if [X86Insn::X86_INS_CALL as u32, X86Insn::X86_INS_LCALL as u32].contains(&id)
    )
}

fn is_return(instruction: &Insn) -> bool {
    matches!(
        instruction.id(),
        InsnId(id)
            if [X86Insn::X86_INS_RET as u32, X86Insn::X86_INS_RETF as u32].contains(&id)
    )
}

fn is_setcc(instruction: &Insn) -> bool {
    instruction
        .mnemonic()
        .map(|mnemonic| mnemonic.starts_with("set"))
        .unwrap_or(false)
}

fn is_cmovcc(instruction: &Insn) -> bool {
    instruction
        .mnemonic()
        .map(|mnemonic| mnemonic.starts_with("cmov"))
        .unwrap_or(false)
}
