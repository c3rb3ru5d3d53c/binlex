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

use crate::Architecture;
use crate::irs::lir::x86::helpers as common;
use crate::irs::lir::x86::instruction::InstructionDetailX86;
use crate::irs::lir::x86::operand::{X86OperandKind, X86OperandView};
use crate::irs::lir::{
    LirEffect, LirExpression, LirInstruction, LirLocation, LirOperationBinary, LirOperationCast,
    LirOperationCompare, LirOperationUnary, LirTerminator,
};
pub fn build(machine: Architecture, view: &InstructionDetailX86) -> Option<LirInstruction> {
    match view.mnemonic.as_str() {
        "bt" => bit_test(machine, view, false),
        "btc" => bit_complement(machine, view),
        "bts" => bit_test(machine, view, true),
        "btr" => bit_reset(machine, view),
        "bsf" => bit_scan(machine, view, false),
        "bsr" => bit_scan(machine, view, true),
        "tzcnt" => count_zeros(machine, view, false),
        "lzcnt" => count_zeros(machine, view, true),
        "blsi" => bls(machine, view, BlsKind::Isolate),
        "blsmsk" => bls(machine, view, BlsKind::Mask),
        "blsr" => bls(machine, view, BlsKind::Reset),
        "bextr" => bextr(machine, view),
        "bzhi" => bzhi(machine, view),
        "pdep" => pdep_pext(machine, view, true),
        "pext" => pdep_pext(machine, view, false),
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
    view: &InstructionDetailX86,
    update_base: bool,
) -> Option<LirInstruction> {
    let base = operand_expr(machine, view.operands().first()?)?;
    let index = operand_expr(machine, view.operands().get(1)?)?;
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let mask_bits = if bits.is_power_of_two() {
        bits.trailing_zeros() as u16
    } else {
        bits
    };
    let masked_index = if bits.is_power_of_two() {
        LirExpression::Extract {
            arg: Box::new(index.clone()),
            lsb: 0,
            bits: mask_bits,
        }
    } else {
        index.clone()
    };
    let bit_value = LirExpression::Extract {
        arg: Box::new(LirExpression::Binary {
            op: LirOperationBinary::LShr,
            left: Box::new(base.clone()),
            right: Box::new(masked_index.clone()),
            bits,
        }),
        lsb: 0,
        bits: 1,
    };
    let mut effects = vec![LirEffect::Set {
        dst: common::flag("cf"),
        expression: bit_value,
    }];
    if update_base {
        let bit_mask = LirExpression::Binary {
            op: LirOperationBinary::Shl,
            left: Box::new(common::const_u64(1, bits)),
            right: Box::new(masked_index),
            bits,
        };
        effects.push(LirEffect::Set {
            dst,
            expression: common::or(base, bit_mask, bits),
        });
    }
    Some(common::complete(LirTerminator::FallThrough, effects))
}

fn bit_reset(machine: Architecture, view: &InstructionDetailX86) -> Option<LirInstruction> {
    let base = operand_expr(machine, view.operands().first()?)?;
    let index = operand_expr(machine, view.operands().get(1)?)?;
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let mask_bits = if bits.is_power_of_two() {
        bits.trailing_zeros() as u16
    } else {
        bits
    };
    let masked_index = if bits.is_power_of_two() {
        LirExpression::Extract {
            arg: Box::new(index),
            lsb: 0,
            bits: mask_bits,
        }
    } else {
        index
    };
    let bit_mask = LirExpression::Binary {
        op: LirOperationBinary::Shl,
        left: Box::new(common::const_u64(1, bits)),
        right: Box::new(masked_index.clone()),
        bits,
    };
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: LirExpression::Extract {
                    arg: Box::new(LirExpression::Binary {
                        op: LirOperationBinary::LShr,
                        left: Box::new(base.clone()),
                        right: Box::new(masked_index),
                        bits,
                    }),
                    lsb: 0,
                    bits: 1,
                },
            },
            LirEffect::Set {
                dst,
                expression: LirExpression::Binary {
                    op: LirOperationBinary::And,
                    left: Box::new(base),
                    right: Box::new(LirExpression::Unary {
                        op: LirOperationUnary::Not,
                        arg: Box::new(bit_mask),
                        bits,
                    }),
                    bits,
                },
            },
        ],
    ))
}

fn bit_complement(machine: Architecture, view: &InstructionDetailX86) -> Option<LirInstruction> {
    let base = operand_expr(machine, view.operands().first()?)?;
    let index = operand_expr(machine, view.operands().get(1)?)?;
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let mask_bits = if bits.is_power_of_two() {
        bits.trailing_zeros() as u16
    } else {
        bits
    };
    let masked_index = if bits.is_power_of_two() {
        LirExpression::Extract {
            arg: Box::new(index),
            lsb: 0,
            bits: mask_bits,
        }
    } else {
        index
    };
    let bit_mask = LirExpression::Binary {
        op: LirOperationBinary::Shl,
        left: Box::new(common::const_u64(1, bits)),
        right: Box::new(masked_index.clone()),
        bits,
    };
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: LirExpression::Extract {
                    arg: Box::new(LirExpression::Binary {
                        op: LirOperationBinary::LShr,
                        left: Box::new(base.clone()),
                        right: Box::new(masked_index),
                        bits,
                    }),
                    lsb: 0,
                    bits: 1,
                },
            },
            LirEffect::Set {
                dst,
                expression: LirExpression::Binary {
                    op: LirOperationBinary::Xor,
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
    view: &InstructionDetailX86,
    reverse: bool,
) -> Option<LirInstruction> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_expr = LirExpression::Read(Box::new(dst.clone()));
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let src_is_zero = common::compare(
        LirOperationCompare::Eq,
        src.clone(),
        common::const_u64(0, bits),
    );
    let scan = if reverse {
        common::sub(
            common::const_u64(bits as u64 - 1, bits),
            LirExpression::Unary {
                op: LirOperationUnary::CountLeadingZeros,
                arg: Box::new(src.clone()),
                bits,
            },
            bits,
        )
    } else {
        LirExpression::Unary {
            op: LirOperationUnary::CountTrailingZeros,
            arg: Box::new(src.clone()),
            bits,
        }
    };
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: LirExpression::Select {
                    condition: Box::new(src_is_zero.clone()),
                    when_true: Box::new(dst_expr),
                    when_false: Box::new(scan),
                    bits,
                },
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: src_is_zero,
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: LirExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn count_zeros(
    machine: Architecture,
    view: &InstructionDetailX86,
    leading: bool,
) -> Option<LirInstruction> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let src_is_zero = common::compare(
        LirOperationCompare::Eq,
        src.clone(),
        common::const_u64(0, bits),
    );
    let count = LirExpression::Unary {
        op: if leading {
            LirOperationUnary::CountLeadingZeros
        } else {
            LirOperationUnary::CountTrailingZeros
        },
        arg: Box::new(src.clone()),
        bits,
    };
    let result = LirExpression::Select {
        condition: Box::new(src_is_zero.clone()),
        when_true: Box::new(common::const_u64(bits as u64, bits)),
        when_false: Box::new(count),
        bits,
    };
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: src_is_zero,
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: LirExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn bls(
    machine: Architecture,
    view: &InstructionDetailX86,
    kind: BlsKind,
) -> Option<LirInstruction> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let src_minus_one = common::sub(src.clone(), common::const_u64(1, bits), bits);
    let result = match kind {
        BlsKind::Isolate => common::and(
            src.clone(),
            LirExpression::Unary {
                op: LirOperationUnary::Neg,
                arg: Box::new(src.clone()),
                bits,
            },
            bits,
        ),
        BlsKind::Mask => common::xor(src.clone(), src_minus_one.clone(), bits),
        BlsKind::Reset => common::and(src.clone(), src_minus_one, bits),
    };
    let src_zero = common::compare(
        LirOperationCompare::Eq,
        src.clone(),
        common::const_u64(0, bits),
    );
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: src_zero,
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: LirExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn bextr(machine: Architecture, view: &InstructionDetailX86) -> Option<LirInstruction> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let control = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let start = LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(control.clone()),
            lsb: 0,
            bits: 8,
        }),
        bits,
    };
    let len = LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(control),
            lsb: 8,
            bits: 8,
        }),
        bits,
    };
    let len_is_zero = common::compare(
        LirOperationCompare::Eq,
        len.clone(),
        common::const_u64(0, bits),
    );
    let start_in_range = common::compare(
        LirOperationCompare::Ult,
        start.clone(),
        common::const_u64(bits as u64, bits),
    );
    let len_ge_bits = common::compare(
        LirOperationCompare::Uge,
        len.clone(),
        common::const_u64(bits as u64, bits),
    );
    let shifted = LirExpression::Binary {
        op: LirOperationBinary::LShr,
        left: Box::new(src),
        right: Box::new(start.clone()),
        bits,
    };
    let variable_mask = common::sub(
        LirExpression::Binary {
            op: LirOperationBinary::Shl,
            left: Box::new(common::const_u64(1, bits)),
            right: Box::new(len.clone()),
            bits,
        },
        common::const_u64(1, bits),
        bits,
    );
    let mask = LirExpression::Select {
        condition: Box::new(len_ge_bits),
        when_true: Box::new(common::const_u64(u64::MAX, bits)),
        when_false: Box::new(variable_mask),
        bits,
    };
    let extracted = common::and(shifted, mask, bits);
    let result = LirExpression::Select {
        condition: Box::new(common::and(
            start_in_range,
            common::compare(
                LirOperationCompare::Eq,
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
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result,
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: LirExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn bzhi(machine: Architecture, view: &InstructionDetailX86) -> Option<LirInstruction> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let index = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let n = LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(index),
            lsb: 0,
            bits: 8,
        }),
        bits,
    };
    let index_out_of_range = common::compare(
        LirOperationCompare::Uge,
        n.clone(),
        common::const_u64(bits as u64, bits),
    );
    let variable_mask = common::sub(
        LirExpression::Binary {
            op: LirOperationBinary::Shl,
            left: Box::new(common::const_u64(1, bits)),
            right: Box::new(n.clone()),
            bits,
        },
        common::const_u64(1, bits),
        bits,
    );
    let result = LirExpression::Select {
        condition: Box::new(index_out_of_range.clone()),
        when_true: Box::new(src.clone()),
        when_false: Box::new(common::and(src, variable_mask, bits)),
        bits,
    };
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: index_out_of_range,
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result, bits.saturating_sub(1)),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: LirExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn pdep_pext(
    machine: Architecture,
    view: &InstructionDetailX86,
    deposit: bool,
) -> Option<LirInstruction> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let mask = operand_expr(machine, view.operands().get(2)?)?;
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
        LirTerminator::FallThrough,
        vec![LirEffect::Set { dst, expression }],
    ))
}

fn pdep_expression(src: LirExpression, mask: LirExpression, bits: u16) -> LirExpression {
    let mut low_to_high_parts = Vec::with_capacity(bits as usize);
    let mut rank = common::const_u64(0, bits);
    for bit in 0..bits {
        let mask_bit = common::extract_bit(mask.clone(), bit);
        let src_bit = LirExpression::Extract {
            arg: Box::new(LirExpression::Binary {
                op: LirOperationBinary::LShr,
                left: Box::new(src.clone()),
                right: Box::new(rank.clone()),
                bits,
            }),
            lsb: 0,
            bits: 1,
        };
        low_to_high_parts.push(LirExpression::Select {
            condition: Box::new(common::compare(
                LirOperationCompare::Eq,
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
    LirExpression::Concat { parts, bits }
}

fn pext_expression(src: LirExpression, mask: LirExpression, bits: u16) -> LirExpression {
    let mut outputs = vec![common::bool_const(false); bits as usize];
    let mut rank = common::const_u64(0, bits);
    for src_bit_index in 0..bits {
        let mask_bit = common::extract_bit(mask.clone(), src_bit_index);
        let src_bit = common::extract_bit(src.clone(), src_bit_index);
        for out_bit in 0..bits {
            let rank_matches = common::compare(
                LirOperationCompare::Eq,
                rank.clone(),
                common::const_u64(out_bit as u64, bits),
            );
            let choose_bit = common::and(
                common::compare(
                    LirOperationCompare::Eq,
                    mask_bit.clone(),
                    common::bool_const(true),
                ),
                rank_matches,
                1,
            );
            outputs[out_bit as usize] = LirExpression::Select {
                condition: Box::new(choose_bit),
                when_true: Box::new(src_bit.clone()),
                when_false: Box::new(outputs[out_bit as usize].clone()),
                bits: 1,
            };
        }
        rank = common::add(rank, zext_bit(mask_bit, bits), bits);
    }
    let parts = outputs.into_iter().rev().collect();
    LirExpression::Concat { parts, bits }
}

fn zext_bit(bit: LirExpression, bits: u16) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(bit),
        bits,
    }
}

fn operand_expr(machine: Architecture, operand: &X86OperandView) -> Option<LirExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(LirExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(LirExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(LirExpression::Load {
                space: common::memory_space(mem.segment_register_name),
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(machine: Architecture, operand: &X86OperandView) -> Option<LirLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(LirLocation::Memory {
                space: common::memory_space(mem.segment_register_name),
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}
