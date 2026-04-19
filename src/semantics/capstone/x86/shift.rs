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
    if matches!(instruction.mnemonic().unwrap_or_default(), "shld") {
        return double_precision_shift(machine, operands, true);
    }
    if matches!(instruction.mnemonic().unwrap_or_default(), "shrd") {
        return double_precision_shift(machine, operands, false);
    }
    if let Some(semantics) = bmi_shift(machine, instruction, operands) {
        return Some(semantics);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_RCL as u32) {
        return rotate_through_carry(machine, operands, true);
    }
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_RCR as u32) {
        return rotate_through_carry(machine, operands, false);
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

fn rotate_through_carry(
    machine: Architecture,
    operands: &[ArchOperand],
    left: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let value = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let raw_count = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
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

fn bmi_shift(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let op = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_SHLX as u32 => SemanticOperationBinary::Shl,
        InsnId(id) if id == X86Insn::X86_INS_SHRX as u32 => SemanticOperationBinary::LShr,
        InsnId(id) if id == X86Insn::X86_INS_SARX as u32 => SemanticOperationBinary::AShr,
        InsnId(id) if id == X86Insn::X86_INS_RORX as u32 => SemanticOperationBinary::RotateRight,
        _ => return None,
    };

    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let raw_count = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
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
    operands: &[ArchOperand],
    left_shift: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_expr = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let src_expr = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let raw_count = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))
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
    let count_is_one = common::compare(
        SemanticOperationCompare::Eq,
        effective_count.clone(),
        common::const_u64(1, bits),
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
                    when_false: Box::new(SemanticExpression::Select {
                        condition: Box::new(count_is_one),
                        when_true: Box::new(of_for_one),
                        when_false: Box::new(SemanticExpression::Undefined { bits: 1 }),
                        bits: 1,
                    }),
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
