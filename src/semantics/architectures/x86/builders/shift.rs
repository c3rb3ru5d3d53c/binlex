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
use crate::semantics::architectures::x86::helpers as common;
use crate::semantics::architectures::x86::instruction::InstructionDetailX86;
use crate::semantics::architectures::x86::operand::{X86OperandKind, X86OperandView};
use crate::semantics::{
    Semantic, SemanticAddressSpace, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare, SemanticTerminator,
};
pub fn build(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    if matches!(view.mnemonic.as_str(), "shld") {
        return double_precision_shift(machine, view, true);
    }
    if matches!(view.mnemonic.as_str(), "shrd") {
        return double_precision_shift(machine, view, false);
    }
    if let Some(semantics) = bmi_shift(machine, view) {
        return Some(semantics);
    }
    if matches!(view.mnemonic.as_str(), "rcl") {
        return rotate_through_carry(machine, view, true);
    }
    if matches!(view.mnemonic.as_str(), "rcr") {
        return rotate_through_carry(machine, view, false);
    }

    let op = match view.mnemonic.as_str() {
        "shl" | "sal" => Some(SemanticOperationBinary::Shl),
        "shr" => Some(SemanticOperationBinary::LShr),
        "sar" => Some(SemanticOperationBinary::AShr),
        "rol" => Some(SemanticOperationBinary::RotateLeft),
        "ror" => Some(SemanticOperationBinary::RotateRight),
        _ => None,
    }?;

    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let raw_count = view
        .operands()
        .get(1)
        .and_then(|operand| operand_expr(machine, operand))
        .unwrap_or_else(|| common::const_u64(1, 8));
    let bits = common::location_bits(&dst);

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
        when_false: Box::new(of_formula),
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

fn rotate_through_carry(
    machine: Architecture,
    view: &InstructionDetailX86,
    left: bool,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let value = operand_expr(machine, view.operands().first()?)?;
    let raw_count = view
        .operands()
        .get(1)
        .and_then(|operand| operand_expr(machine, operand))
        .unwrap_or_else(|| common::const_u64(1, 8));
    let bits = common::location_bits(&dst);
    let count_mask_bits = if bits == 64 { 6 } else { 5 };
    let masked_count = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(raw_count),
            lsb: 0,
            bits: count_mask_bits,
        }),
        bits,
    };
    let rotation_width = common::const_u64((bits as u64) + 1, bits);
    let effective_count = SemanticExpression::Binary {
        op: SemanticOperationBinary::URem,
        left: Box::new(masked_count),
        right: Box::new(rotation_width),
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
    let extended = SemanticExpression::Concat {
        parts: vec![common::flag_expr("cf"), value.clone()],
        bits: bits + 1,
    };
    let extended_count = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(effective_count.clone()),
        bits: bits + 1,
    };
    let rotated = SemanticExpression::Binary {
        op: if left {
            SemanticOperationBinary::RotateLeft
        } else {
            SemanticOperationBinary::RotateRight
        },
        left: Box::new(extended),
        right: Box::new(extended_count),
        bits: bits + 1,
    };
    let result = SemanticExpression::Select {
        condition: Box::new(count_is_zero.clone()),
        when_true: Box::new(value.clone()),
        when_false: Box::new(SemanticExpression::Extract {
            arg: Box::new(rotated.clone()),
            lsb: 0,
            bits,
        }),
        bits,
    };
    let cf_result = SemanticExpression::Select {
        condition: Box::new(count_is_zero.clone()),
        when_true: Box::new(common::flag_expr("cf")),
        when_false: Box::new(SemanticExpression::Extract {
            arg: Box::new(rotated.clone()),
            lsb: bits,
            bits: 1,
        }),
        bits: 1,
    };
    let msb = common::extract_bit(result.clone(), bits - 1);
    let of_formula = if left {
        common::xor(msb, cf_result.clone(), 1)
    } else {
        common::xor(msb, common::extract_bit(result.clone(), bits - 2), 1)
    };
    let of_expression = SemanticExpression::Select {
        condition: Box::new(count_is_zero),
        when_true: Box::new(common::flag_expr("of")),
        when_false: Box::new(SemanticExpression::Select {
            condition: Box::new(count_is_one),
            when_true: Box::new(of_formula),
            when_false: Box::new(SemanticExpression::Undefined { bits: 1 }),
            bits: 1,
        }),
        bits: 1,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: cf_result,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: of_expression,
            },
        ],
    ))
}

fn bmi_shift(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let op = match view.mnemonic.as_str() {
        "shlx" => SemanticOperationBinary::Shl,
        "shrx" => SemanticOperationBinary::LShr,
        "sarx" => SemanticOperationBinary::AShr,
        "rorx" => SemanticOperationBinary::RotateRight,
        _ => return None,
    };

    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let raw_count = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    if !matches!(bits, 32 | 64) {
        return None;
    }

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
    let shifted = SemanticExpression::Binary {
        op,
        left: Box::new(src.clone()),
        right: Box::new(effective_count),
        bits,
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(count_is_zero),
                when_true: Box::new(src),
                when_false: Box::new(shifted),
                bits,
            },
        }],
    ))
}

fn double_precision_shift(
    machine: Architecture,
    view: &InstructionDetailX86,
    left_shift: bool,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_expr = operand_expr(machine, view.operands().first()?)?;
    let src_expr = operand_expr(machine, view.operands().get(1)?)?;
    let raw_count = view
        .operands()
        .get(2)
        .and_then(|operand| operand_expr(machine, operand))
        .unwrap_or_else(|| common::const_u64(1, 8));
    let bits = common::location_bits(&dst);
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
    let inverse_count = common::sub(
        common::const_u64(bits as u64, bits),
        effective_count.clone(),
        bits,
    );
    let shifted = if left_shift {
        common::or(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::Shl,
                left: Box::new(dst_expr.clone()),
                right: Box::new(effective_count.clone()),
                bits,
            },
            SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(src_expr),
                right: Box::new(inverse_count),
                bits,
            },
            bits,
        )
    } else {
        common::or(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(dst_expr.clone()),
                right: Box::new(effective_count.clone()),
                bits,
            },
            SemanticExpression::Binary {
                op: SemanticOperationBinary::Shl,
                left: Box::new(src_expr),
                right: Box::new(inverse_count),
                bits,
            },
            bits,
        )
    };
    let result = SemanticExpression::Select {
        condition: Box::new(count_is_zero.clone()),
        when_true: Box::new(dst_expr.clone()),
        when_false: Box::new(shifted.clone()),
        bits,
    };
    let cf_computed = if left_shift {
        SemanticExpression::Extract {
            arg: Box::new(SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(dst_expr.clone()),
                right: Box::new(common::sub(
                    common::const_u64(bits as u64, bits),
                    effective_count.clone(),
                    bits,
                )),
                bits,
            }),
            lsb: 0,
            bits: 1,
        }
    } else {
        SemanticExpression::Extract {
            arg: Box::new(SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(dst_expr.clone()),
                right: Box::new(common::sub(
                    effective_count.clone(),
                    common::const_u64(1, bits),
                    bits,
                )),
                bits,
            }),
            lsb: 0,
            bits: 1,
        }
    };
    let of_for_one = if left_shift {
        common::xor(
            common::extract_bit(shifted.clone(), bits.saturating_sub(1)),
            cf_computed.clone(),
            1,
        )
    } else {
        common::xor(
            common::extract_bit(dst_expr.clone(), bits.saturating_sub(1)),
            common::extract_bit(shifted.clone(), bits.saturating_sub(1)),
            1,
        )
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
                expression: SemanticExpression::Select {
                    condition: Box::new(count_is_zero.clone()),
                    when_true: Box::new(common::flag_expr("cf")),
                    when_false: Box::new(cf_computed),
                    bits: 1,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: SemanticExpression::Select {
                    condition: Box::new(count_is_zero.clone()),
                    when_true: Box::new(common::flag_expr("of")),
                    when_false: Box::new(of_for_one),
                    bits: 1,
                },
            },
            SemanticEffect::Set {
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
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: SemanticExpression::Select {
                    condition: Box::new(count_is_zero.clone()),
                    when_true: Box::new(common::flag_expr("sf")),
                    when_false: Box::new(common::extract_bit(
                        result.clone(),
                        bits.saturating_sub(1),
                    )),
                    bits: 1,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Select {
                    condition: Box::new(count_is_zero.clone()),
                    when_true: Box::new(common::flag_expr("pf")),
                    when_false: Box::new(common::parity_flag(result.clone())),
                    bits: 1,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Select {
                    condition: Box::new(count_is_zero),
                    when_true: Box::new(common::flag_expr("af")),
                    when_false: Box::new(SemanticExpression::Undefined { bits: 1 }),
                    bits: 1,
                },
            },
        ],
    ))
}

fn operand_expr(machine: Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(SemanticExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(SemanticExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(machine: Architecture, operand: &X86OperandView) -> Option<SemanticLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticLocation::Memory {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}
