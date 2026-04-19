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
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticOperationBinary,
    SemanticOperationCompare, SemanticTerminator,
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
    if matches!(
        instruction.id(),
        InsnId(id) if id == X86Insn::X86_INS_ANDN as u32
    ) {
        let dst = operands
            .first()
            .and_then(|operand| common::operand_location(machine, operand))?;
        let src1 = operands
            .get(1)
            .and_then(|operand| common::operand_expr(machine, operand))?;
        let src2 = operands
            .get(2)
            .and_then(|operand| common::operand_expr(machine, operand))?;
        let bits = common::location_bits(&dst);
        let result = common::and(common::not(src1, bits), src2, bits);
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![
                SemanticEffect::Set {
                    dst,
                    expression: result.clone(),
                },
                SemanticEffect::Set {
                    dst: common::flag("zf"),
                    expression: common::compare(
                        SemanticOperationCompare::Eq,
                        result.clone(),
                        common::const_u64(0, bits),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("sf"),
                    expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
                },
                SemanticEffect::Set {
                    dst: common::flag("cf"),
                    expression: common::bool_const(false),
                },
                SemanticEffect::Set {
                    dst: common::flag("of"),
                    expression: common::bool_const(false),
                },
                SemanticEffect::Set {
                    dst: common::flag("pf"),
                    expression: common::parity_flag(result),
                },
                SemanticEffect::Set {
                    dst: common::flag("af"),
                    expression: SemanticExpression::Undefined { bits: 1 },
                },
            ],
        ));
    }

    if matches!(
        instruction.id(),
        InsnId(id) if id == X86Insn::X86_INS_TEST as u32
    ) {
        let left = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))?;
        let right = operands
            .get(1)
            .and_then(|operand| common::operand_expr(machine, operand))?;
        let bits = operands
            .first()
            .and_then(|operand| common::operand_location(machine, operand))
            .map(|location| common::location_bits(&location))
            .unwrap_or_else(|| common::pointer_bits(machine));
        let and_expression = SemanticExpression::Binary {
            op: SemanticOperationBinary::And,
            left: Box::new(left.clone()),
            right: Box::new(right.clone()),
            bits,
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![
                SemanticEffect::Set {
                    dst: common::flag("zf"),
                    expression: common::compare(
                        SemanticOperationCompare::Eq,
                        and_expression.clone(),
                        common::const_u64(0, bits),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("sf"),
                    expression: common::extract_bit(and_expression, bits.saturating_sub(1)),
                },
                SemanticEffect::Set {
                    dst: common::flag("cf"),
                    expression: common::bool_const(false),
                },
                SemanticEffect::Set {
                    dst: common::flag("of"),
                    expression: common::bool_const(false),
                },
                SemanticEffect::Set {
                    dst: common::flag("pf"),
                    expression: common::parity_flag(common::and(left, right, bits)),
                },
                SemanticEffect::Set {
                    dst: common::flag("af"),
                    expression: SemanticExpression::Undefined { bits: 1 },
                },
            ],
        ));
    }

    let op = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_AND as u32 => Some(SemanticOperationBinary::And),
        InsnId(id) if id == X86Insn::X86_INS_OR as u32 => Some(SemanticOperationBinary::Or),
        InsnId(id) if id == X86Insn::X86_INS_XOR as u32 => Some(SemanticOperationBinary::Xor),
        _ => None,
    }?;

    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = match &dst {
        crate::semantics::SemanticLocation::Register { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Flag { bits, .. } => *bits,
        crate::semantics::SemanticLocation::ProgramCounter { bits } => *bits,
        crate::semantics::SemanticLocation::Temporary { bits, .. } => *bits,
    };
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}
