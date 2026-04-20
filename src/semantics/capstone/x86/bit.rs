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
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator,
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
        InsnId(id) if id == X86Insn::X86_INS_BSF as u32 => bit_scan(machine, operands, false),
        InsnId(id) if id == X86Insn::X86_INS_BSR as u32 => bit_scan(machine, operands, true),
        InsnId(id) if id == X86Insn::X86_INS_TZCNT as u32 => count_zeros(machine, operands, false),
        InsnId(id) if id == X86Insn::X86_INS_LZCNT as u32 => count_zeros(machine, operands, true),
        InsnId(id) if id == X86Insn::X86_INS_BLSI as u32 => {
            bls(machine, operands, BlsKind::Isolate)
        }
        InsnId(id) if id == X86Insn::X86_INS_BLSMSK as u32 => bls(machine, operands, BlsKind::Mask),
        InsnId(id) if id == X86Insn::X86_INS_BLSR as u32 => bls(machine, operands, BlsKind::Reset),
        InsnId(id) if id == X86Insn::X86_INS_BEXTR as u32 => bextr(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_BZHI as u32 => bzhi(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_PDEP as u32 => pdep_pext(machine, operands, true),
        InsnId(id) if id == X86Insn::X86_INS_PEXT as u32 => pdep_pext(machine, operands, false),
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum BlsKind {
    Isolate,
    Mask,
    Reset,
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

fn bit_scan(
    machine: Architecture,
    operands: &[ArchOperand],
    reverse: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let src_is_zero = common::compare(
        SemanticOperationCompare::Eq,
        src.clone(),
        common::const_u64(0, bits),
    );
    let scan = if reverse {
        common::sub(
            common::const_u64(bits as u64 - 1, bits),
            SemanticExpression::Unary {
                op: SemanticOperationUnary::CountLeadingZeros,
                arg: Box::new(src.clone()),
                bits,
            },
            bits,
        )
    } else {
        SemanticExpression::Unary {
            op: SemanticOperationUnary::CountTrailingZeros,
            arg: Box::new(src.clone()),
            bits,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: SemanticExpression::Select {
                    condition: Box::new(src_is_zero.clone()),
                    when_true: Box::new(SemanticExpression::Undefined { bits }),
                    when_false: Box::new(scan),
                    bits,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: src_is_zero,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn count_zeros(
    machine: Architecture,
    operands: &[ArchOperand],
    leading: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let src_is_zero = common::compare(
        SemanticOperationCompare::Eq,
        src.clone(),
        common::const_u64(0, bits),
    );
    let count = SemanticExpression::Unary {
        op: if leading {
            SemanticOperationUnary::CountLeadingZeros
        } else {
            SemanticOperationUnary::CountTrailingZeros
        },
        arg: Box::new(src.clone()),
        bits,
    };
    let result = SemanticExpression::Select {
        condition: Box::new(src_is_zero.clone()),
        when_true: Box::new(common::const_u64(bits as u64, bits)),
        when_false: Box::new(count),
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
                dst: common::flag("cf"),
                expression: src_is_zero,
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
                dst: common::flag("of"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn bls(
    machine: Architecture,
    operands: &[ArchOperand],
    kind: BlsKind,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let src_minus_one = common::sub(src.clone(), common::const_u64(1, bits), bits);
    let result = match kind {
        BlsKind::Isolate => common::and(
            src.clone(),
            SemanticExpression::Unary {
                op: SemanticOperationUnary::Neg,
                arg: Box::new(src.clone()),
                bits,
            },
            bits,
        ),
        BlsKind::Mask => common::xor(src.clone(), src_minus_one.clone(), bits),
        BlsKind::Reset => common::and(src.clone(), src_minus_one, bits),
    };
    let src_zero = common::compare(
        SemanticOperationCompare::Eq,
        src.clone(),
        common::const_u64(0, bits),
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: src_zero,
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
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn bextr(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let start = SemanticExpression::Cast {
        op: crate::semantics::SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(control.clone()),
            lsb: 0,
            bits: 8,
        }),
        bits,
    };
    let len = SemanticExpression::Cast {
        op: crate::semantics::SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(control),
            lsb: 8,
            bits: 8,
        }),
        bits,
    };
    let len_is_zero = common::compare(
        SemanticOperationCompare::Eq,
        len.clone(),
        common::const_u64(0, bits),
    );
    let start_in_range = common::compare(
        SemanticOperationCompare::Ult,
        start.clone(),
        common::const_u64(bits as u64, bits),
    );
    let len_ge_bits = common::compare(
        SemanticOperationCompare::Uge,
        len.clone(),
        common::const_u64(bits as u64, bits),
    );
    let shifted = SemanticExpression::Binary {
        op: SemanticOperationBinary::LShr,
        left: Box::new(src),
        right: Box::new(start.clone()),
        bits,
    };
    let variable_mask = common::sub(
        SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(common::const_u64(1, bits)),
            right: Box::new(len.clone()),
            bits,
        },
        common::const_u64(1, bits),
        bits,
    );
    let mask = SemanticExpression::Select {
        condition: Box::new(len_ge_bits),
        when_true: Box::new(common::const_u64(u64::MAX, bits)),
        when_false: Box::new(variable_mask),
        bits,
    };
    let extracted = common::and(shifted, mask, bits);
    let result = SemanticExpression::Select {
        condition: Box::new(common::and(
            start_in_range,
            common::compare(
                SemanticOperationCompare::Eq,
                len_is_zero.clone(),
                common::bool_const(false),
            ),
            1,
        )),
        when_true: Box::new(extracted),
        when_false: Box::new(common::const_u64(0, bits)),
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
                    result,
                    common::const_u64(0, bits),
                ),
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
                dst: common::flag("sf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn bzhi(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let index = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let n = SemanticExpression::Cast {
        op: crate::semantics::SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(index),
            lsb: 0,
            bits: 8,
        }),
        bits,
    };
    let index_out_of_range = common::compare(
        SemanticOperationCompare::Uge,
        n.clone(),
        common::const_u64(bits as u64, bits),
    );
    let variable_mask = common::sub(
        SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(common::const_u64(1, bits)),
            right: Box::new(n.clone()),
            bits,
        },
        common::const_u64(1, bits),
        bits,
    );
    let result = SemanticExpression::Select {
        condition: Box::new(index_out_of_range.clone()),
        when_true: Box::new(src.clone()),
        when_false: Box::new(common::and(src, variable_mask, bits)),
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
                dst: common::flag("cf"),
                expression: index_out_of_range,
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result, bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn pdep_pext(
    machine: Architecture,
    operands: &[ArchOperand],
    deposit: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let mask = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if !matches!(bits, 32 | 64) {
        return None;
    }

    let expression = if deposit {
        pdep_expression(src, mask, bits)
    } else {
        pext_expression(src, mask, bits)
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn pdep_expression(
    src: SemanticExpression,
    mask: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    let mut low_to_high_parts = Vec::with_capacity(bits as usize);
    let mut rank = common::const_u64(0, bits);
    for bit in 0..bits {
        let mask_bit = common::extract_bit(mask.clone(), bit);
        let src_bit = SemanticExpression::Extract {
            arg: Box::new(SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(src.clone()),
                right: Box::new(rank.clone()),
                bits,
            }),
            lsb: 0,
            bits: 1,
        };
        low_to_high_parts.push(SemanticExpression::Select {
            condition: Box::new(common::compare(
                SemanticOperationCompare::Eq,
                mask_bit.clone(),
                common::bool_const(true),
            )),
            when_true: Box::new(src_bit),
            when_false: Box::new(common::bool_const(false)),
            bits: 1,
        });
        rank = common::add(rank, zext_bit(mask_bit, bits), bits);
    }
    let parts = low_to_high_parts.into_iter().rev().collect();
    SemanticExpression::Concat { parts, bits }
}

fn pext_expression(
    src: SemanticExpression,
    mask: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    let mut outputs = vec![common::bool_const(false); bits as usize];
    let mut rank = common::const_u64(0, bits);
    for src_bit_index in 0..bits {
        let mask_bit = common::extract_bit(mask.clone(), src_bit_index);
        let src_bit = common::extract_bit(src.clone(), src_bit_index);
        for out_bit in 0..bits {
            let rank_matches = common::compare(
                SemanticOperationCompare::Eq,
                rank.clone(),
                common::const_u64(out_bit as u64, bits),
            );
            let choose_bit = common::and(
                common::compare(
                    SemanticOperationCompare::Eq,
                    mask_bit.clone(),
                    common::bool_const(true),
                ),
                rank_matches,
                1,
            );
            outputs[out_bit as usize] = SemanticExpression::Select {
                condition: Box::new(choose_bit),
                when_true: Box::new(src_bit.clone()),
                when_false: Box::new(outputs[out_bit as usize].clone()),
                bits: 1,
            };
        }
        rank = common::add(rank, zext_bit(mask_bit, bits), bits);
    }
    let parts = outputs.into_iter().rev().collect();
    SemanticExpression::Concat { parts, bits }
}

fn zext_bit(bit: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(bit),
        bits,
    }
}
