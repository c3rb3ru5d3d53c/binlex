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

pub(super) fn unpack(
    machine: Architecture,
    instruction: &Insn,
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
    let (lane_bits, high_half) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_UNPCKLPD as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKHPD as u32 => (64, true),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKLPS as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKHPS as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLBW as u32 => (8, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLWD as u32 => (16, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLDQ as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLQDQ as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHBW as u32 => (8, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHWD as u32 => (16, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHDQ as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHQDQ as u32 => (64, true),
        _ => return None,
    };
    let expression = if bits == 256 {
        SemanticExpression::Concat {
            parts: vec![
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 128, 128),
                    &extract_range(&right, 128, 128),
                    high_half,
                )?,
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 0, 128),
                    &extract_range(&right, 0, 128),
                    high_half,
                )?,
            ],
            bits,
        }
    } else {
        interleave_lanes(bits, lane_bits, &left, &right, high_half)?
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn avx_unpack(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let (lane_bits, high_half) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLBW as u32 => (8, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLWD as u32 => (16, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLDQ as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLQDQ as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHBW as u32 => (8, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHWD as u32 => (16, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHDQ as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHQDQ as u32 => (64, true),
        _ => return None,
    };
    let expression = if bits == 256 {
        SemanticExpression::Concat {
            parts: vec![
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 128, 128),
                    &extract_range(&right, 128, 128),
                    high_half,
                )?,
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 0, 128),
                    &extract_range(&right, 0, 128),
                    high_half,
                )?,
            ],
            bits,
        }
    } else {
        interleave_lanes(bits, lane_bits, &left, &right, high_half)?
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn packed_extract(
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
    let dst_bits = common::location_bits(&dst);
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PEXTRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRQ as u32 => 64,
        InsnId(id) if id == X86Insn::X86_INS_EXTRACTPS as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRQ as u32 => 64,
        _ => return None,
    };
    let lane = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(lane),
        right: Box::new(common::const_u64(lane_bits as u64, dst_bits)),
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
                    bits: lane_bits,
                }),
                bits: dst_bits,
            },
        }],
    ))
}

pub(super) fn packed_insert(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src_vec = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let inserted = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let lane = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PINSRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PINSRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PINSRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_PINSRQ as u32 => 64,
        InsnId(id) if id == X86Insn::X86_INS_VPINSRW as u32 => 16,
        _ => return None,
    };
    let shift = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(lane),
        right: Box::new(common::const_u64(lane_bits as u64, bits)),
        bits,
    };
    let cleared = common::and(
        src_vec,
        common::not(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::Shl,
                left: Box::new(SemanticExpression::Const {
                    value: lane_mask(lane_bits),
                    bits,
                }),
                right: Box::new(shift.clone()),
                bits,
            },
            bits,
        ),
        bits,
    );
    let inserted_value = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(SemanticExpression::Cast {
            op: crate::semantics::SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(inserted),
                lsb: 0,
                bits: lane_bits,
            }),
            bits,
        }),
        right: Box::new(shift),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::or(cleared, inserted_value, bits),
        }],
    ))
}

pub(super) fn movemask(
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
    let src_bits = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))
        .map(|location| common::location_bits(&location))?;
    let dst_bits = common::location_bits(&dst);
    let (lane_bits, lane_count) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPS as u32 => (32, 4),
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPD as u32 => (64, 2),
        InsnId(id) if id == X86Insn::X86_INS_PMOVMSKB as u32 => (8, 16),
        InsnId(id) if id == X86Insn::X86_INS_VPMOVMSKB as u32 => (8, src_bits / 8),
        _ => return None,
    };
    let mut value = common::const_u64(0, dst_bits);
    for lane in 0..lane_count {
        let bit = SemanticExpression::Extract {
            arg: Box::new(src.clone()),
            lsb: lane * lane_bits + (lane_bits - 1),
            bits: 1,
        };
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(bit),
                bits: dst_bits,
            }),
            right: Box::new(common::const_u64(lane as u64, dst_bits)),
            bits: dst_bits,
        };
        value = common::or(value, shifted, dst_bits);
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: value,
        }],
    ))
}

pub(super) fn shuffle(
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
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSHUFD as u32 => {
            shuffle_dwords(bits, &src, imm as u8)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFHW as u32 => {
            shuffle_words_half(bits, &src, imm as u8, true)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFLW as u32 => {
            shuffle_words_half(bits, &src, imm as u8, false)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFW as u32 => shuffle_words(bits, &src, imm as u8)?,
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn avx_shuffle(
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
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPSHUFD as u32 => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shuffle_dwords(128, &extract_range(&src, 128, 128), imm as u8)?,
                        shuffle_dwords(128, &extract_range(&src, 0, 128), imm as u8)?,
                    ],
                    bits,
                }
            } else {
                shuffle_dwords(bits, &src, imm as u8)?
            }
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn pshufb(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let mask = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if bits != 128 {
        return None;
    }
    let mut parts = Vec::with_capacity(16);
    for lane in (0..16).rev() {
        let control = extract_lane(&mask, 8, lane);
        let zero = common::extract_bit(control.clone(), 7);
        let index = SemanticExpression::Extract {
            arg: Box::new(control),
            lsb: 0,
            bits: 4,
        };
        let mut selected = extract_lane(&src, 8, 0);
        for source_lane in 1..16 {
            selected = SemanticExpression::Select {
                condition: Box::new(common::compare(
                    SemanticOperationCompare::Eq,
                    index.clone(),
                    SemanticExpression::Const {
                        value: source_lane as u128,
                        bits: 4,
                    },
                )),
                when_true: Box::new(extract_lane(&src, 8, source_lane)),
                when_false: Box::new(selected),
                bits: 8,
            };
        }
        parts.push(SemanticExpression::Select {
            condition: Box::new(zero),
            when_true: Box::new(common::const_u64(0, 8)),
            when_false: Box::new(selected),
            bits: 8,
        });
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn vextracti128(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let lane = (imm as u8 & 0x1) as u16;
    let extracted = extract_range(&src, lane * 128, 128);
    let dst_bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: if dst_bits == 128 {
                extracted
            } else {
                truncate_to_bits(extracted, dst_bits)
            },
        }],
    ))
}

pub(super) fn vinsertf128(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let base = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let inserted = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(3)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let lower = extract_range(&base, 0, 128);
    let upper = extract_range(&base, 128, 128);
    let expression = if (imm as u8 & 0x1) == 0 {
        SemanticExpression::Concat {
            parts: vec![upper, extract_range(&inserted, 0, 128)],
            bits: 256,
        }
    } else {
        SemanticExpression::Concat {
            parts: vec![extract_range(&inserted, 0, 128), lower],
            bits: 256,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn maskmovq(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mask = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let data = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.maskmovq".to_string(),
            args: vec![mask, data],
            outputs: vec![],
        }],
    ))
}

pub(super) fn vperm2i128(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(3)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let select_half = |select: u8| match select & 0x3 {
        0 => extract_range(&left, 0, 128),
        1 => extract_range(&left, 128, 128),
        2 => extract_range(&right, 0, 128),
        _ => extract_range(&right, 128, 128),
    };
    let low = if (imm as u8 & 0x08) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half(imm as u8)
    };
    let high = if (imm as u8 & 0x80) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half((imm as u8 >> 4) & 0x3)
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![high, low],
                bits: 256,
            },
        }],
    ))
}

pub(super) fn vpermq(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let mut parts = Vec::with_capacity(4);
    for lane in (0..4).rev() {
        let select = ((imm as u8 >> (lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(&src, 64, select));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits: 256 },
        }],
    ))
}

pub(super) fn vpbroadcastb(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane = extract_range(&src, 0, 8);
    let parts = vec![lane; (bits / 8) as usize];
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn vpsignw(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let mut parts = Vec::with_capacity((bits / 16) as usize);
    for lane in (0..(bits / 16)).rev() {
        let value = extract_lane(&left, 16, lane);
        let control = extract_lane(&right, 16, lane);
        let is_zero = common::compare(
            SemanticOperationCompare::Eq,
            control.clone(),
            common::const_u64(0, 16),
        );
        let is_negative = common::extract_bit(control, 15);
        parts.push(SemanticExpression::Select {
            condition: Box::new(is_zero),
            when_true: Box::new(common::const_u64(0, 16)),
            when_false: Box::new(SemanticExpression::Select {
                condition: Box::new(is_negative),
                when_true: Box::new(SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(value.clone()),
                    bits: 16,
                }),
                when_false: Box::new(value),
                bits: 16,
            }),
            bits: 16,
        });
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn vmaskmov(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    if is_memory_operand(operands.first()?) {
        let mask = operands
            .get(1)
            .and_then(|operand| common::operand_expr(machine, operand))?;
        let data = operands
            .get(2)
            .and_then(|operand| common::operand_expr(machine, operand))?;
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: format!("x86.{mnemonic}"),
                args: vec![mask, data],
                outputs: vec![dst],
            }],
        ));
    }
    let mask = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let src = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Intrinsic {
                name: format!("x86.{mnemonic}"),
                args: vec![mask, src],
                bits,
            },
        }],
    ))
}

pub(super) fn vzeroupper() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.vzeroupper".to_string(),
            args: Vec::new(),
            outputs: Vec::new(),
        }],
    )
}

fn shuffle_dwords(bits: u16, src: &SemanticExpression, imm: u8) -> Option<SemanticExpression> {
    if bits < 128 {
        return None;
    }
    let mut parts = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(src, 32, select));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn shuffle_words_half(
    bits: u16,
    src: &SemanticExpression,
    imm: u8,
    high_half: bool,
) -> Option<SemanticExpression> {
    if bits < 128 {
        return None;
    }
    let base_lane = if high_half { 4 } else { 0 };
    let other_base = if high_half { 0 } else { 4 };
    let mut shuffled_half = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        shuffled_half.push(extract_lane(src, 16, base_lane + select));
    }
    let mut parts = Vec::with_capacity(8);
    if high_half {
        parts.extend(shuffled_half);
        for lane in (0..4).rev() {
            parts.push(extract_lane(src, 16, other_base + lane));
        }
    } else {
        for lane in (0..4).rev() {
            parts.push(extract_lane(src, 16, other_base + lane));
        }
        parts.extend(shuffled_half);
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn shuffle_words(bits: u16, src: &SemanticExpression, imm: u8) -> Option<SemanticExpression> {
    if bits != 64 {
        return None;
    }
    let mut parts = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(src, 16, select));
    }
    Some(SemanticExpression::Concat { parts, bits })
}
