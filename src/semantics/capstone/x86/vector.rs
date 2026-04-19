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
    SemanticOperationCast, SemanticOperationCompare,
    SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86OperandType};

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
        InsnId(id)
            if [
                X86Insn::X86_INS_MOVHLPS as u32,
                X86Insn::X86_INS_MOVLHPS as u32,
                X86Insn::X86_INS_MOVHPD as u32,
                X86Insn::X86_INS_MOVLPD as u32,
                X86Insn::X86_INS_MOVHPS as u32,
                X86Insn::X86_INS_MOVLPS as u32,
            ]
            .contains(&id) =>
        {
            partial_lane_move(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PMOVSXBW as u32,
                X86Insn::X86_INS_PMOVSXBD as u32,
                X86Insn::X86_INS_PMOVSXBQ as u32,
                X86Insn::X86_INS_PMOVSXWD as u32,
                X86Insn::X86_INS_PMOVSXWQ as u32,
                X86Insn::X86_INS_PMOVSXDQ as u32,
                X86Insn::X86_INS_PMOVZXBW as u32,
                X86Insn::X86_INS_PMOVZXBD as u32,
                X86Insn::X86_INS_PMOVZXBQ as u32,
                X86Insn::X86_INS_PMOVZXWD as u32,
                X86Insn::X86_INS_PMOVZXWQ as u32,
                X86Insn::X86_INS_PMOVZXDQ as u32,
            ]
            .contains(&id) =>
        {
            packed_widen(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_POR as u32,
                X86Insn::X86_INS_PAND as u32,
                X86Insn::X86_INS_PXOR as u32,
                X86Insn::X86_INS_ORPS as u32,
                X86Insn::X86_INS_ORPD as u32,
                X86Insn::X86_INS_XORPD as u32,
            ]
            .contains(&id) =>
        {
            binary(
                machine,
                operands,
                match id {
                    id if id == X86Insn::X86_INS_POR as u32
                        || id == X86Insn::X86_INS_ORPS as u32
                        || id == X86Insn::X86_INS_ORPD as u32 =>
                    {
                        SemanticOperationBinary::Or
                    }
                    id if id == X86Insn::X86_INS_PAND as u32 => SemanticOperationBinary::And,
                    _ => SemanticOperationBinary::Xor,
                },
            )
        }
        InsnId(id) if id == X86Insn::X86_INS_PANDN as u32 => pandn(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_PADDB as u32,
                X86Insn::X86_INS_PADDW as u32,
                X86Insn::X86_INS_PADDD as u32,
                X86Insn::X86_INS_PSUBB as u32,
                X86Insn::X86_INS_PSUBW as u32,
                X86Insn::X86_INS_PSUBD as u32,
                X86Insn::X86_INS_PCMPEQB as u32,
                X86Insn::X86_INS_PCMPEQW as u32,
                X86Insn::X86_INS_PCMPEQD as u32,
                X86Insn::X86_INS_PCMPGTB as u32,
                X86Insn::X86_INS_PCMPGTW as u32,
                X86Insn::X86_INS_PCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            packed_lane_op(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PSHUFB as u32,
                X86Insn::X86_INS_PSHUFD as u32,
                X86Insn::X86_INS_PSHUFHW as u32,
                X86Insn::X86_INS_PSHUFLW as u32,
                X86Insn::X86_INS_UNPCKLPD as u32,
                X86Insn::X86_INS_UNPCKHPD as u32,
                X86Insn::X86_INS_UNPCKLPS as u32,
                X86Insn::X86_INS_UNPCKHPS as u32,
                X86Insn::X86_INS_PUNPCKLBW as u32,
                X86Insn::X86_INS_PUNPCKHBW as u32,
                X86Insn::X86_INS_PUNPCKLWD as u32,
                X86Insn::X86_INS_PUNPCKHWD as u32,
                X86Insn::X86_INS_PUNPCKLDQ as u32,
                X86Insn::X86_INS_PUNPCKHDQ as u32,
                X86Insn::X86_INS_PUNPCKLQDQ as u32,
                X86Insn::X86_INS_PUNPCKHQDQ as u32,
            ]
            .contains(&id) =>
        {
            if id == X86Insn::X86_INS_PSHUFB as u32 {
                pshufb(machine, operands)
            } else if [X86Insn::X86_INS_PSHUFD as u32, X86Insn::X86_INS_PSHUFHW as u32, X86Insn::X86_INS_PSHUFLW as u32]
                .contains(&id)
            {
                shuffle(machine, instruction, operands)
            } else {
                unpack(machine, instruction, operands)
            }
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PEXTRW as u32,
                X86Insn::X86_INS_PEXTRB as u32,
                X86Insn::X86_INS_PEXTRD as u32,
                X86Insn::X86_INS_PEXTRQ as u32,
                X86Insn::X86_INS_EXTRACTPS as u32,
            ]
            .contains(&id) =>
        {
            packed_extract(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PINSRB as u32,
                X86Insn::X86_INS_PINSRD as u32,
                X86Insn::X86_INS_PINSRQ as u32,
                X86Insn::X86_INS_PINSRW as u32,
            ]
            .contains(&id) =>
        {
            packed_insert(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_MOVMSKPS as u32,
                X86Insn::X86_INS_MOVMSKPD as u32,
                X86Insn::X86_INS_PMOVMSKB as u32,
            ]
            .contains(&id) =>
        {
            movemask(machine, instruction, operands)
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

fn packed_widen(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands.first().and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands.get(1).and_then(|operand| common::operand_expr(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let (src_lane_bits, dst_lane_bits, cast) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBW as u32 => (8, 16, SemanticOperationCast::SignExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBD as u32 => (8, 32, SemanticOperationCast::SignExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBQ as u32 => (8, 64, SemanticOperationCast::SignExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXWD as u32 => (16, 32, SemanticOperationCast::SignExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXWQ as u32 => (16, 64, SemanticOperationCast::SignExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXDQ as u32 => (32, 64, SemanticOperationCast::SignExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBW as u32 => (8, 16, SemanticOperationCast::ZeroExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBD as u32 => (8, 32, SemanticOperationCast::ZeroExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBQ as u32 => (8, 64, SemanticOperationCast::ZeroExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXWD as u32 => (16, 32, SemanticOperationCast::ZeroExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXWQ as u32 => (16, 64, SemanticOperationCast::ZeroExtend),
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXDQ as u32 => (32, 64, SemanticOperationCast::ZeroExtend),
        _ => return None,
    };
    let lane_count = dst_bits / dst_lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let extracted = extract_lane(&src, src_lane_bits, lane);
        parts.push(SemanticExpression::Cast {
            op: cast,
            arg: Box::new(extracted),
            bits: dst_lane_bits,
        });
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts,
                bits: dst_bits,
            },
        }],
    ))
}

fn partial_lane_move(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands.first().and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    if dst_bits < 128 {
        return None;
    }
    let left = operands.first().and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands.get(1).and_then(|operand| common::operand_expr(machine, operand))?;
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVHLPS as u32 => SemanticExpression::Concat {
            parts: vec![extract_range(&left, 64, 64), extract_range(&right, 64, 64)],
            bits: 128,
        },
        InsnId(id) if id == X86Insn::X86_INS_MOVLHPS as u32 => SemanticExpression::Concat {
            parts: vec![extract_range(&right, 0, 64), extract_range(&left, 0, 64)],
            bits: 128,
        },
        InsnId(id) if id == X86Insn::X86_INS_MOVHPD as u32 || id == X86Insn::X86_INS_MOVHPS as u32 => {
            SemanticExpression::Concat {
                parts: vec![
                    extract_range(&right, 0, 64),
                    extract_range(&left, 0, 64),
                ],
                bits: 128,
            }
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVLPD as u32 || id == X86Insn::X86_INS_MOVLPS as u32 => {
            SemanticExpression::Concat {
                parts: vec![
                    extract_range(&left, 64, 64),
                    extract_range(&right, 0, 64),
                ],
                bits: 128,
            }
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
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

fn pandn(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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

fn packed_lane_op(
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
    let lane_bits = match instruction.id() {
        InsnId(id)
            if [X86Insn::X86_INS_PADDB as u32, X86Insn::X86_INS_PSUBB as u32]
                .contains(&id) =>
        {
            8
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PADDW as u32,
                X86Insn::X86_INS_PSUBW as u32,
                X86Insn::X86_INS_PCMPEQW as u32,
                X86Insn::X86_INS_PCMPGTW as u32,
            ]
            .contains(&id) =>
        {
            16
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PADDD as u32,
                X86Insn::X86_INS_PSUBD as u32,
                X86Insn::X86_INS_PCMPEQD as u32,
                X86Insn::X86_INS_PCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            32
        }
        InsnId(id)
            if [X86Insn::X86_INS_PCMPEQB as u32, X86Insn::X86_INS_PCMPGTB as u32]
                .contains(&id) =>
        {
            8
        }
        _ => return None,
    };
    let expression = packed_lanes(
        bits,
        lane_bits,
        &left,
        &right,
        match instruction.id() {
            InsnId(id)
                if [
                    X86Insn::X86_INS_PADDB as u32,
                    X86Insn::X86_INS_PADDW as u32,
                    X86Insn::X86_INS_PADDD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Add)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PSUBB as u32,
                    X86Insn::X86_INS_PSUBW as u32,
                    X86Insn::X86_INS_PSUBD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Sub)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PCMPEQB as u32,
                    X86Insn::X86_INS_PCMPEQW as u32,
                    X86Insn::X86_INS_PCMPEQD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Compare(SemanticOperationCompare::Eq)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PCMPGTB as u32,
                    X86Insn::X86_INS_PCMPGTW as u32,
                    X86Insn::X86_INS_PCMPGTD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Compare(SemanticOperationCompare::Sgt)
            }
            _ => return None,
        },
    )?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

#[derive(Clone, Copy)]
enum PackedLaneOp {
    Binary(SemanticOperationBinary),
    Compare(SemanticOperationCompare),
}

fn packed_lanes(
    bits: u16,
    lane_bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
    op: PackedLaneOp,
) -> Option<SemanticExpression> {
    if bits == 0 || lane_bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lsb = lane * lane_bits;
        let left_lane = SemanticExpression::Extract {
            arg: Box::new(left.clone()),
            lsb,
            bits: lane_bits,
        };
        let right_lane = SemanticExpression::Extract {
            arg: Box::new(right.clone()),
            lsb,
            bits: lane_bits,
        };
        let part = match op {
            PackedLaneOp::Binary(operation) => SemanticExpression::Binary {
                op: operation,
                left: Box::new(left_lane),
                right: Box::new(right_lane),
                bits: lane_bits,
            },
            PackedLaneOp::Compare(compare) => {
                let condition = common::compare(compare, left_lane, right_lane);
                let true_lane = SemanticExpression::Const {
                    value: lane_mask(lane_bits),
                    bits: lane_bits,
                };
                SemanticExpression::Select {
                    condition: Box::new(condition),
                    when_true: Box::new(true_lane),
                    when_false: Box::new(common::const_u64(0, lane_bits)),
                    bits: lane_bits,
                }
            }
        };
        parts.push(part);
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn lane_mask(bits: u16) -> u128 {
    if bits as u32 >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

fn unpack(machine: Architecture, instruction: &Insn, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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
    let expression = interleave_lanes(bits, lane_bits, &left, &right, high_half)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn packed_extract(
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

fn packed_insert(
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

fn movemask(
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
    let (lane_bits, lane_count) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPS as u32 => (32, 4),
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPD as u32 => (64, 2),
        InsnId(id) if id == X86Insn::X86_INS_PMOVMSKB as u32 => (8, 16),
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

fn shuffle(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands.first().and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands.get(1).and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSHUFD as u32 => shuffle_dwords(bits, &src, imm as u8)?,
        InsnId(id) if id == X86Insn::X86_INS_PSHUFHW as u32 => shuffle_words_half(bits, &src, imm as u8, true)?,
        InsnId(id) if id == X86Insn::X86_INS_PSHUFLW as u32 => shuffle_words_half(bits, &src, imm as u8, false)?,
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn pshufb(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands.first().and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands.first().and_then(|operand| common::operand_expr(machine, operand))?;
    let mask = operands.get(1).and_then(|operand| common::operand_expr(machine, operand))?;
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

fn interleave_lanes(
    bits: u16,
    lane_bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
    high_half: bool,
) -> Option<SemanticExpression> {
    if bits == 0 || lane_bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    let half = lane_count / 2;
    let start = if high_half { half } else { 0 };
    let end = start + half;
    let mut parts = Vec::with_capacity((half * 2) as usize);
    for lane in (start..end).rev() {
        parts.push(extract_lane(right, lane_bits, lane));
        parts.push(extract_lane(left, lane_bits, lane));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn extract_lane(vector: &SemanticExpression, lane_bits: u16, lane: u16) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(vector.clone()),
        lsb: lane * lane_bits,
        bits: lane_bits,
    }
}

fn extract_range(vector: &SemanticExpression, lsb: u16, bits: u16) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(vector.clone()),
        lsb,
        bits,
    }
}
