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
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86Insn;

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    if matches!(
        mnemonic,
        "fld"
            | "fst"
            | "fstp"
            | "fild"
            | "fldz"
            | "fld1"
            | "fadd"
            | "faddp"
            | "fmul"
            | "fmulp"
            | "fdiv"
            | "fdivr"
            | "fdivrp"
            | "fsub"
            | "fsubp"
            | "fsubr"
            | "fsubrp"
            | "fcomp"
            | "fcom"
            | "fcompp"
            | "fucom"
            | "fucomp"
            | "fnstsw"
            | "fabs"
            | "fchs"
            | "fxch"
    ) {
        return x87_intrinsic(machine, instruction, operands);
    }

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVSD as u32 => movsd(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_MINSD as u32 => {
            scalar_fp(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_FIMUL as u32 => {
            x87_intrinsic(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_COMISD as u32,
                X86Insn::X86_INS_UCOMISD as u32,
            ]
            .contains(&id) =>
        {
            compare_sd(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_CVTTSD2SI as u32 => {
            scalar_convert(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_CVTDQ2PD as u32 => {
            packed_convert(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_ADDSD as u32,
                X86Insn::X86_INS_MULSD as u32,
                X86Insn::X86_INS_DIVSD as u32,
                X86Insn::X86_INS_SUBSD as u32,
            ]
            .contains(&id) =>
        {
            scalar_fp(machine, instruction, operands)
        }
        _ => None,
    }
}

fn movsd(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let expression = if dst_bits > 64 {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
            })?;
        let lower = SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: 64,
        };
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: dst_bits,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn x87_intrinsic(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("x86.{}", instruction.mnemonic().unwrap_or("x87")),
            args,
            outputs: Vec::new(),
        }],
    ))
}

fn compare_sd(
    _machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(_machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::operation_intrinsic(instruction, 1, args.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Intrinsic {
                    name: format!("x86.{}.pf", instruction.mnemonic().unwrap_or("comisd")),
                    args: args.clone(),
                    bits: 1,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: SemanticExpression::Intrinsic {
                    name: format!("x86.{}.cf", instruction.mnemonic().unwrap_or("comisd")),
                    args,
                    bits: 1,
                },
            },
        ],
    ))
}

fn scalar_convert(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::operation_intrinsic(instruction, bits, args),
        }],
    ))
}

fn packed_convert(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::operation_intrinsic(instruction, bits, args),
        }],
    ))
}

fn scalar_fp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    let dst_bits = common::location_bits(&dst);
    let lower = common::operation_intrinsic(instruction, 64, args);
    let expression = if dst_bits > 64 {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
            })?;
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        lower
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}
