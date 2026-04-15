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
    SemanticTerminator,
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
    match instruction.id() {
        InsnId(id)
            if [
                X86Insn::X86_INS_MOVUPS as u32,
                X86Insn::X86_INS_MOVAPS as u32,
                X86Insn::X86_INS_MOVDQU as u32,
                X86Insn::X86_INS_MOVDQA as u32,
                X86Insn::X86_INS_MOVD as u32,
                X86Insn::X86_INS_MOVQ as u32,
            ]
            .contains(&id) =>
        {
            assign(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_UNPCKLPD as u32 => unpack_low_pd(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_PEXTRW as u32 => {
            packed_extract_word(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_PSRLDQ as u32 => shift_right_bytes(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_XORPS as u32 => {
            binary(machine, operands, SemanticOperationBinary::Xor)
        }
        InsnId(id) if id == X86Insn::X86_INS_ANDPS as u32 => {
            binary(machine, operands, SemanticOperationBinary::And)
        }
        _ => None,
    }
}

fn assign(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let expression = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn binary(
    machine: Architecture,
    operands: &[ArchOperand],
    operation: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: operation,
                left: Box::new(left),
                right: Box::new(right),
                bits,
            },
        }],
    ))
}

fn shift_right_bytes(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let count = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(left),
                right: Box::new(SemanticExpression::Binary {
                    op: SemanticOperationBinary::Mul,
                    left: Box::new(count),
                    right: Box::new(common::const_u64(8, bits)),
                    bits,
                }),
                bits,
            },
        }],
    ))
}

fn unpack_low_pd(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if bits < 128 {
        return None;
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![
                    SemanticExpression::Extract {
                        arg: Box::new(right),
                        lsb: 0,
                        bits: 64,
                    },
                    SemanticExpression::Extract {
                        arg: Box::new(left),
                        lsb: 0,
                        bits: 64,
                    },
                ],
                bits,
            },
        }],
    ))
}

fn packed_extract_word(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let lane = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(lane),
        right: Box::new(common::const_u64(16, dst_bits)),
        bits: dst_bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Binary {
                        op: SemanticOperationBinary::LShr,
                        left: Box::new(src),
                        right: Box::new(shift_bits),
                        bits: 128,
                    }),
                    lsb: 0,
                    bits: 16,
                }),
                bits: dst_bits,
            },
        }],
    ))
}
