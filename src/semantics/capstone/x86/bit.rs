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
    SemanticOperationUnary, SemanticTerminator,
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
        InsnId(id) if id == X86Insn::X86_INS_BT as u32 => {
            bit_test(machine, instruction, operands, false)
        }
        InsnId(id) if id == X86Insn::X86_INS_BTC as u32 => bit_complement(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_BTS as u32 => {
            bit_test(machine, instruction, operands, true)
        }
        InsnId(id) if id == X86Insn::X86_INS_BTR as u32 => bit_reset(machine, operands),
        _ => None,
    }
}

fn bit_test(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
    update_base: bool,
) -> Option<InstructionSemantics> {
    let base = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let index = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let mask_bits = if bits.is_power_of_two() {
        bits.trailing_zeros() as u16
    } else {
        bits
    };
    let masked_index = if bits.is_power_of_two() {
        SemanticExpression::Extract {
            arg: Box::new(index.clone()),
            lsb: 0,
            bits: mask_bits,
        }
    } else {
        index.clone()
    };
    let bit_value = SemanticExpression::Extract {
        arg: Box::new(SemanticExpression::Binary {
            op: SemanticOperationBinary::LShr,
            left: Box::new(base.clone()),
            right: Box::new(masked_index.clone()),
            bits,
        }),
        lsb: 0,
        bits: 1,
    };
    let mut effects = vec![SemanticEffect::Set {
        dst: common::flag("cf"),
        expression: bit_value,
    }];
    if update_base {
        let bit_mask = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(common::const_u64(1, bits)),
            right: Box::new(masked_index),
            bits,
        };
        effects.push(SemanticEffect::Set {
            dst,
            expression: common::or(base, bit_mask, bits),
        });
    }
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn bit_reset(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let base = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let index = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let mask_bits = if bits.is_power_of_two() {
        bits.trailing_zeros() as u16
    } else {
        bits
    };
    let masked_index = if bits.is_power_of_two() {
        SemanticExpression::Extract {
            arg: Box::new(index),
            lsb: 0,
            bits: mask_bits,
        }
    } else {
        index
    };
    let bit_mask = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(common::const_u64(1, bits)),
        right: Box::new(masked_index.clone()),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Binary {
                        op: SemanticOperationBinary::LShr,
                        left: Box::new(base.clone()),
                        right: Box::new(masked_index),
                        bits,
                    }),
                    lsb: 0,
                    bits: 1,
                },
            },
            SemanticEffect::Set {
                dst,
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::And,
                    left: Box::new(base),
                    right: Box::new(SemanticExpression::Unary {
                        op: SemanticOperationUnary::Not,
                        arg: Box::new(bit_mask),
                        bits,
                    }),
                    bits,
                },
            },
        ],
    ))
}

fn bit_complement(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let base = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let index = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let mask_bits = if bits.is_power_of_two() {
        bits.trailing_zeros() as u16
    } else {
        bits
    };
    let masked_index = if bits.is_power_of_two() {
        SemanticExpression::Extract {
            arg: Box::new(index),
            lsb: 0,
            bits: mask_bits,
        }
    } else {
        index
    };
    let bit_mask = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(common::const_u64(1, bits)),
        right: Box::new(masked_index.clone()),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Binary {
                        op: SemanticOperationBinary::LShr,
                        left: Box::new(base.clone()),
                        right: Box::new(masked_index),
                        bits,
                    }),
                    lsb: 0,
                    bits: 1,
                },
            },
            SemanticEffect::Set {
                dst,
                expression: SemanticExpression::Binary {
                    op: SemanticOperationBinary::Xor,
                    left: Box::new(base),
                    right: Box::new(bit_mask),
                    bits,
                },
            },
        ],
    ))
}
