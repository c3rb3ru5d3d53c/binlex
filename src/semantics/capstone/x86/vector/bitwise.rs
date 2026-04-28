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

use super::*;

pub(super) fn binary(
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

pub(super) fn avx_binary(
    machine: Architecture,
    operands: &[ArchOperand],
    operation: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
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

pub(super) fn pandn(
    machine: Architecture,
    operands: &[ArchOperand],
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
            expression: common::and(common::not(left, bits), right, bits),
        }],
    ))
}

pub(super) fn avx_pandn(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::and(common::not(left, bits), right, bits),
        }],
    ))
}

pub(super) fn packed_shift(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let count = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);

    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSLLDQ as u32 => shift_bytes(src, count, bits, true),
        InsnId(id) if id == X86Insn::X86_INS_PSRLDQ as u32 => shift_bytes(src, count, bits, false),
        InsnId(id)
            if [
                X86Insn::X86_INS_PSLLW as u32,
                X86Insn::X86_INS_PSLLD as u32,
                X86Insn::X86_INS_PSLLQ as u32,
                X86Insn::X86_INS_PSRLW as u32,
                X86Insn::X86_INS_PSRLD as u32,
                X86Insn::X86_INS_PSRLQ as u32,
                X86Insn::X86_INS_PSRAW as u32,
                X86Insn::X86_INS_PSRAD as u32,
            ]
            .contains(&id) =>
        {
            packed_lane_shift(instruction, bits, &src, count)?
        }
        _ => return None,
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn avx_packed_shift(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let count = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPSLLDQ as u32 => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shift_bytes(extract_range(&src, 128, 128), count.clone(), 128, true),
                        shift_bytes(extract_range(&src, 0, 128), count, 128, true),
                    ],
                    bits,
                }
            } else {
                shift_bytes(src, count, bits, true)
            }
        }
        InsnId(id) if id == X86Insn::X86_INS_VPSRLDQ as u32 => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shift_bytes(extract_range(&src, 128, 128), count.clone(), 128, false),
                        shift_bytes(extract_range(&src, 0, 128), count, 128, false),
                    ],
                    bits,
                }
            } else {
                shift_bytes(src, count, bits, false)
            }
        }
        InsnId(id)
            if [X86Insn::X86_INS_VPSLLQ as u32, X86Insn::X86_INS_VPSRLQ as u32].contains(&id) =>
        {
            packed_lane_shift(instruction, bits, &src, count)?
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn shift_bytes(
    src: SemanticExpression,
    count: SemanticExpression,
    bits: u16,
    left: bool,
) -> SemanticExpression {
    let count_bits = bits.max(count.bits());
    let count_bytes = cast_count(count, count_bits);
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(count_bytes.clone()),
        right: Box::new(common::const_u64(8, count_bits)),
        bits: count_bits,
    };
    let shifted = SemanticExpression::Binary {
        op: if left {
            SemanticOperationBinary::Shl
        } else {
            SemanticOperationBinary::LShr
        },
        left: Box::new(cast_to_bits(src, count_bits)),
        right: Box::new(shift_bits),
        bits: count_bits,
    };
    let too_large = common::compare(
        SemanticOperationCompare::Uge,
        count_bytes,
        common::const_u64((bits / 8) as u64, count_bits),
    );
    SemanticExpression::Select {
        condition: Box::new(too_large),
        when_true: Box::new(common::const_u64(0, bits)),
        when_false: Box::new(truncate_to_bits(shifted, bits)),
        bits,
    }
}

pub(super) fn packed_lane_shift(
    instruction: &Insn,
    bits: u16,
    src: &SemanticExpression,
    count: SemanticExpression,
) -> Option<SemanticExpression> {
    let (lane_bits, op) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSLLW as u32 => (16, SemanticOperationBinary::Shl),
        InsnId(id) if id == X86Insn::X86_INS_PSLLD as u32 => (32, SemanticOperationBinary::Shl),
        InsnId(id)
            if [X86Insn::X86_INS_PSLLQ as u32, X86Insn::X86_INS_VPSLLQ as u32].contains(&id) =>
        {
            (64, SemanticOperationBinary::Shl)
        }
        InsnId(id) if id == X86Insn::X86_INS_PSRLW as u32 => (16, SemanticOperationBinary::LShr),
        InsnId(id) if id == X86Insn::X86_INS_PSRLD as u32 => (32, SemanticOperationBinary::LShr),
        InsnId(id)
            if [X86Insn::X86_INS_PSRLQ as u32, X86Insn::X86_INS_VPSRLQ as u32].contains(&id) =>
        {
            (64, SemanticOperationBinary::LShr)
        }
        InsnId(id) if id == X86Insn::X86_INS_PSRAW as u32 => (16, SemanticOperationBinary::AShr),
        InsnId(id) if id == X86Insn::X86_INS_PSRAD as u32 => (32, SemanticOperationBinary::AShr),
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let count_bits = lane_bits.max(count.bits());
    let raw_count = cast_count(count, count_bits);
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lane_expr = cast_to_bits(extract_lane(src, lane_bits, lane), count_bits);
        let part = match op {
            SemanticOperationBinary::AShr => {
                let saturated = SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Uge,
                        raw_count.clone(),
                        common::const_u64(lane_bits as u64, count_bits),
                    )),
                    when_true: Box::new(common::const_u64((lane_bits - 1) as u64, count_bits)),
                    when_false: Box::new(raw_count.clone()),
                    bits: count_bits,
                };
                truncate_to_bits(
                    SemanticExpression::Binary {
                        op,
                        left: Box::new(lane_expr),
                        right: Box::new(saturated),
                        bits: count_bits,
                    },
                    lane_bits,
                )
            }
            _ => {
                let shifted = SemanticExpression::Binary {
                    op,
                    left: Box::new(lane_expr),
                    right: Box::new(raw_count.clone()),
                    bits: count_bits,
                };
                SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Uge,
                        raw_count.clone(),
                        common::const_u64(lane_bits as u64, count_bits),
                    )),
                    when_true: Box::new(common::const_u64(0, lane_bits)),
                    when_false: Box::new(truncate_to_bits(shifted, lane_bits)),
                    bits: lane_bits,
                }
            }
        };
        parts.push(part);
    }
    Some(SemanticExpression::Concat { parts, bits })
}

pub(super) fn cast_count(count: SemanticExpression, bits: u16) -> SemanticExpression {
    let arg = if count.bits() > bits {
        truncate_to_bits(count, bits)
    } else {
        count
    };
    if arg.bits() == bits {
        arg
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(arg),
            bits,
        }
    }
}

pub(super) fn cast_to_bits(expr: SemanticExpression, bits: u16) -> SemanticExpression {
    if expr.bits() == bits {
        expr
    } else if expr.bits() > bits {
        truncate_to_bits(expr, bits)
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expr),
            bits,
        }
    }
}

pub(super) fn truncate_to_bits(expr: SemanticExpression, bits: u16) -> SemanticExpression {
    if expr.bits() == bits {
        expr
    } else {
        SemanticExpression::Extract {
            arg: Box::new(expr),
            lsb: 0,
            bits,
        }
    }
}

pub(super) fn ptest(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = left.bits().max(right.bits());
    let left = cast_to_bits(left, bits);
    let right = cast_to_bits(right, bits);
    let and_value = common::and(left.clone(), right.clone(), bits);
    let andn_value = common::and(left, common::not(right, bits), bits);

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    and_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    andn_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

pub(super) fn avx_ptest(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = left.bits().max(right.bits());
    let left = cast_to_bits(left, bits);
    let right = cast_to_bits(right, bits);
    let and_value = common::and(left.clone(), right.clone(), bits);
    let andn_value = common::and(left, common::not(right, bits), bits);

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    and_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    andn_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

pub(super) fn palignr(
    machine: Architecture,
    operands: &[ArchOperand],
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
    let count = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let wide_bits = bits * 2;
    let combined = SemanticExpression::Concat {
        parts: vec![cast_to_bits(left, wide_bits), cast_to_bits(right, wide_bits)],
        bits: wide_bits,
    };
    let count_bits = wide_bits.max(count.bits());
    let count_bytes = cast_count(count, count_bits);
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(count_bytes.clone()),
        right: Box::new(common::const_u64(8, count_bits)),
        bits: count_bits,
    };
    let shifted = SemanticExpression::Binary {
        op: SemanticOperationBinary::LShr,
        left: Box::new(cast_to_bits(combined, count_bits)),
        right: Box::new(shift_bits),
        bits: count_bits,
    };
    let expression = SemanticExpression::Select {
        condition: Box::new(common::compare(
            SemanticOperationCompare::Uge,
            count_bytes,
            common::const_u64((bits / 8 * 2) as u64, count_bits),
        )),
        when_true: Box::new(common::const_u64(0, bits)),
        when_false: Box::new(truncate_to_bits(shifted, bits)),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}
