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
    SemanticOperationCast, SemanticOperationCompare, SemanticTerminator,
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
    if matches!(instruction.mnemonic().unwrap_or_default(), "shld" | "shrd") {
        let args = operands
            .iter()
            .filter_map(|operand| common::operand_expr(machine, operand))
            .collect::<Vec<_>>();
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: format!("x86.{}", instruction.mnemonic().unwrap_or("shift")),
                args,
                outputs: Vec::new(),
            }],
        ));
    }

    let op = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_SHL as u32 || id == X86Insn::X86_INS_SAL as u32 => {
            Some(SemanticOperationBinary::Shl)
        }
        InsnId(id) if id == X86Insn::X86_INS_SHR as u32 => Some(SemanticOperationBinary::LShr),
        InsnId(id) if id == X86Insn::X86_INS_SAR as u32 => Some(SemanticOperationBinary::AShr),
        InsnId(id) if id == X86Insn::X86_INS_ROL as u32 => {
            Some(SemanticOperationBinary::RotateLeft)
        }
        InsnId(id) if id == X86Insn::X86_INS_ROR as u32 => {
            Some(SemanticOperationBinary::RotateRight)
        }
        _ => None,
    }?;

    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let raw_count = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .unwrap_or_else(|| common::const_u64(1, 8));
    let bits = match &dst {
        crate::semantics::SemanticLocation::Register { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Flag { bits, .. } => *bits,
        crate::semantics::SemanticLocation::ProgramCounter { bits } => *bits,
        crate::semantics::SemanticLocation::Temporary { bits, .. } => *bits,
    };

    let count_mask_bits = if bits == 64 { 6 } else { 5 };
    let effective_count = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(raw_count),
            lsb: 0,
            bits: count_mask_bits,
        }),
        bits,
    };
    let count_is_zero = common::compare(
        SemanticOperationCompare::Eq,
        effective_count.clone(),
        common::const_u64(0, bits),
    );
    let count_is_one = common::compare(
        SemanticOperationCompare::Eq,
        effective_count.clone(),
        common::const_u64(1, bits),
    );
    let shifted = SemanticExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(effective_count.clone()),
        bits,
    };
    let result = SemanticExpression::Select {
        condition: Box::new(count_is_zero.clone()),
        when_true: Box::new(left.clone()),
        when_false: Box::new(shifted.clone()),
        bits,
    };
    let cf_computed = match op {
        SemanticOperationBinary::Shl => SemanticExpression::Extract {
            arg: Box::new(SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(left.clone()),
                right: Box::new(SemanticExpression::Binary {
                    op: SemanticOperationBinary::Sub,
                    left: Box::new(common::const_u64(bits as u64, bits)),
                    right: Box::new(effective_count.clone()),
                    bits,
                }),
                bits,
            }),
            lsb: 0,
            bits: 1,
        },
        SemanticOperationBinary::LShr | SemanticOperationBinary::AShr => {
            SemanticExpression::Extract {
                arg: Box::new(SemanticExpression::Binary {
                    op: SemanticOperationBinary::LShr,
                    left: Box::new(left.clone()),
                    right: Box::new(SemanticExpression::Binary {
                        op: SemanticOperationBinary::Sub,
                        left: Box::new(effective_count.clone()),
                        right: Box::new(common::const_u64(1, bits)),
                        bits,
                    }),
                    bits,
                }),
                lsb: 0,
                bits: 1,
            }
        }
        SemanticOperationBinary::RotateLeft => common::extract_bit(shifted.clone(), 0),
        SemanticOperationBinary::RotateRight => common::extract_bit(shifted.clone(), bits - 1),
        _ => common::bool_const(false),
    };
    let of_formula = match op {
        SemanticOperationBinary::Shl => common::xor(
            common::extract_bit(left.clone(), bits - 1),
            common::extract_bit(shifted.clone(), bits - 1),
            1,
        ),
        SemanticOperationBinary::LShr => common::extract_bit(left.clone(), bits - 1),
        SemanticOperationBinary::AShr => common::bool_const(false),
        SemanticOperationBinary::RotateLeft => common::xor(
            common::extract_bit(shifted.clone(), bits - 1),
            common::extract_bit(shifted.clone(), 0),
            1,
        ),
        SemanticOperationBinary::RotateRight => common::xor(
            common::extract_bit(shifted.clone(), bits - 1),
            common::extract_bit(shifted.clone(), bits - 2),
            1,
        ),
        _ => common::bool_const(false),
    };
    let of_expression = SemanticExpression::Select {
        condition: Box::new(count_is_zero.clone()),
        when_true: Box::new(common::flag_expr("of")),
        when_false: Box::new(SemanticExpression::Select {
            condition: Box::new(count_is_one),
            when_true: Box::new(of_formula),
            when_false: Box::new(SemanticExpression::Undefined { bits: 1 }),
            bits: 1,
        }),
        bits: 1,
    };

    let mut effects = vec![
        SemanticEffect::Set {
            dst,
            expression: result.clone(),
        },
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: SemanticExpression::Select {
                condition: Box::new(count_is_zero.clone()),
                when_true: Box::new(common::flag_expr("cf")),
                when_false: Box::new(cf_computed),
                bits: 1,
            },
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: of_expression,
        },
    ];
    if matches!(
        op,
        SemanticOperationBinary::Shl
            | SemanticOperationBinary::LShr
            | SemanticOperationBinary::AShr
    ) {
        effects.push(SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: SemanticExpression::Select {
                condition: Box::new(count_is_zero.clone()),
                when_true: Box::new(common::flag_expr("zf")),
                when_false: Box::new(common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                )),
                bits: 1,
            },
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: SemanticExpression::Select {
                condition: Box::new(count_is_zero.clone()),
                when_true: Box::new(common::flag_expr("sf")),
                when_false: Box::new(common::extract_bit(result.clone(), bits.saturating_sub(1))),
                bits: 1,
            },
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: SemanticExpression::Select {
                condition: Box::new(count_is_zero.clone()),
                when_true: Box::new(common::flag_expr("pf")),
                when_false: Box::new(common::parity_flag(result.clone())),
                bits: 1,
            },
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Select {
                condition: Box::new(count_is_zero),
                when_true: Box::new(common::flag_expr("af")),
                when_false: Box::new(SemanticExpression::Undefined { bits: 1 }),
                bits: 1,
            },
        });
    } else {
        for flag_name in ["zf", "sf", "pf", "af"] {
            effects.push(SemanticEffect::Set {
                dst: common::flag(flag_name),
                expression: common::flag_expr(flag_name),
            });
        }
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}
