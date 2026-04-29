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

pub(super) fn packed_lane_op(
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
            if [X86Insn::X86_INS_PADDB as u32, X86Insn::X86_INS_PSUBB as u32].contains(&id) =>
        {
            8
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PADDW as u32,
                X86Insn::X86_INS_PSUBW as u32,
                X86Insn::X86_INS_PMAXSW as u32,
                X86Insn::X86_INS_PMAXUW as u32,
                X86Insn::X86_INS_PMINSW as u32,
                X86Insn::X86_INS_PMINUW as u32,
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
                X86Insn::X86_INS_PMAXSD as u32,
                X86Insn::X86_INS_PMAXUD as u32,
                X86Insn::X86_INS_PMINSD as u32,
                X86Insn::X86_INS_PMINUD as u32,
                X86Insn::X86_INS_PCMPEQD as u32,
                X86Insn::X86_INS_PCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            32
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PADDQ as u32,
                X86Insn::X86_INS_PSUBQ as u32,
                X86Insn::X86_INS_PCMPGTQ as u32,
            ]
            .contains(&id) =>
        {
            64
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PMAXSB as u32,
                X86Insn::X86_INS_PMAXUB as u32,
                X86Insn::X86_INS_PMINSB as u32,
                X86Insn::X86_INS_PMINUB as u32,
                X86Insn::X86_INS_PCMPEQB as u32,
                X86Insn::X86_INS_PCMPGTB as u32,
            ]
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
                    X86Insn::X86_INS_PADDQ as u32,
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
                    X86Insn::X86_INS_PSUBQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Sub)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMAXSB as u32,
                    X86Insn::X86_INS_PMAXSW as u32,
                    X86Insn::X86_INS_PMAXSD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MaxSigned)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMAXUB as u32,
                    X86Insn::X86_INS_PMAXUW as u32,
                    X86Insn::X86_INS_PMAXUD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MaxUnsigned)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMINSB as u32,
                    X86Insn::X86_INS_PMINSW as u32,
                    X86Insn::X86_INS_PMINSD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MinSigned)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMINUB as u32,
                    X86Insn::X86_INS_PMINUW as u32,
                    X86Insn::X86_INS_PMINUD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MinUnsigned)
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
                    X86Insn::X86_INS_PCMPGTQ as u32,
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

pub(super) fn avx_packed_lane_op(
    machine: Architecture,
    instruction: &Insn,
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
    let lane_bits = match instruction.id() {
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDB as u32,
                X86Insn::X86_INS_VPSUBB as u32,
                X86Insn::X86_INS_VPCMPEQB as u32,
                X86Insn::X86_INS_VPCMPGTB as u32,
            ]
            .contains(&id) =>
        {
            8
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDW as u32,
                X86Insn::X86_INS_VPSUBW as u32,
                X86Insn::X86_INS_VPCMPEQW as u32,
                X86Insn::X86_INS_VPCMPGTW as u32,
            ]
            .contains(&id) =>
        {
            16
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDD as u32,
                X86Insn::X86_INS_VPSUBD as u32,
                X86Insn::X86_INS_VPCMPEQD as u32,
                X86Insn::X86_INS_VPCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            32
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDQ as u32,
                X86Insn::X86_INS_VPSUBQ as u32,
                X86Insn::X86_INS_VPCMPEQQ as u32,
                X86Insn::X86_INS_VPCMPGTQ as u32,
            ]
            .contains(&id) =>
        {
            64
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
                    X86Insn::X86_INS_VPADDB as u32,
                    X86Insn::X86_INS_VPADDW as u32,
                    X86Insn::X86_INS_VPADDD as u32,
                    X86Insn::X86_INS_VPADDQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Add)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_VPSUBB as u32,
                    X86Insn::X86_INS_VPSUBW as u32,
                    X86Insn::X86_INS_VPSUBD as u32,
                    X86Insn::X86_INS_VPSUBQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Sub)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_VPCMPEQB as u32,
                    X86Insn::X86_INS_VPCMPEQW as u32,
                    X86Insn::X86_INS_VPCMPEQD as u32,
                    X86Insn::X86_INS_VPCMPEQQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Compare(SemanticOperationCompare::Eq)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_VPCMPGTB as u32,
                    X86Insn::X86_INS_VPCMPGTW as u32,
                    X86Insn::X86_INS_VPCMPGTD as u32,
                    X86Insn::X86_INS_VPCMPGTQ as u32,
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

pub(super) fn packed_unsigned_saturating_add(
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
        InsnId(id) if id == X86Insn::X86_INS_PADDUSB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PADDUSW as u32 => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let ext_bits = lane_bits + 1;
    let max_lane_value = (1u64 << lane_bits) - 1;
    let max_ext = common::const_u64(max_lane_value, ext_bits);
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::compare(
                SemanticOperationCompare::Ugt,
                sum.clone(),
                max_ext.clone(),
            )),
            when_true: Box::new(common::const_u64(max_lane_value, lane_bits)),
            when_false: Box::new(truncate_to_bits(sum, lane_bits)),
            bits: lane_bits,
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

pub(super) fn packed_signed_saturating_add(
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
        InsnId(id) if id == X86Insn::X86_INS_PADDSB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PADDSW as u32 => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let ext_bits = lane_bits + 1;
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        parts.push(saturate_lane(sum, ext_bits, lane_bits, PackKind::Signed));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn avx_packed_unsigned_saturating_add(
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
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPADDUSB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_VPADDUSW as u32 => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let ext_bits = lane_bits + 1;
    let max_lane_value = (1u64 << lane_bits) - 1;
    let max_ext = common::const_u64(max_lane_value, ext_bits);
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::compare(
                SemanticOperationCompare::Ugt,
                sum.clone(),
                max_ext.clone(),
            )),
            when_true: Box::new(common::const_u64(max_lane_value, lane_bits)),
            when_false: Box::new(truncate_to_bits(sum, lane_bits)),
            bits: lane_bits,
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

pub(super) fn avx_packed_signed_saturating_add(
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
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPADDSB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_VPADDSW as u32 => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let ext_bits = lane_bits + 1;
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        parts.push(saturate_lane(sum, ext_bits, lane_bits, PackKind::Signed));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn packed_abs(
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
    let bits = common::location_bits(&dst);
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PABSB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PABSW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PABSD as u32 => 32,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let value = extract_lane(&src, lane_bits, lane);
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::extract_bit(value.clone(), lane_bits - 1)),
            when_true: Box::new(SemanticExpression::Unary {
                op: SemanticOperationUnary::Neg,
                arg: Box::new(value.clone()),
                bits: lane_bits,
            }),
            when_false: Box::new(value),
            bits: lane_bits,
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

pub(super) fn packed_average(
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
        InsnId(id) if id == X86Insn::X86_INS_PAVGB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PAVGW as u32 => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let ext_bits = lane_bits + 1;
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        let rounded = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(sum),
            right: Box::new(common::const_u64(1, ext_bits)),
            bits: ext_bits,
        };
        parts.push(truncate_to_bits(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(rounded),
                right: Box::new(common::const_u64(1, ext_bits)),
                bits: ext_bits,
            },
            lane_bits,
        ));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn packed_horizontal(
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
    let (lane_bits, op, saturating) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PHADDW as u32 => {
            (16, SemanticOperationBinary::Add, false)
        }
        InsnId(id) if id == X86Insn::X86_INS_PHADDD as u32 => {
            (32, SemanticOperationBinary::Add, false)
        }
        InsnId(id) if id == X86Insn::X86_INS_PHADDSW as u32 => {
            (16, SemanticOperationBinary::Add, true)
        }
        InsnId(id) if id == X86Insn::X86_INS_PHSUBW as u32 => {
            (16, SemanticOperationBinary::Sub, false)
        }
        InsnId(id) if id == X86Insn::X86_INS_PHSUBD as u32 => {
            (32, SemanticOperationBinary::Sub, false)
        }
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    if lane_count % 2 != 0 {
        return None;
    }
    let pair_count = lane_count / 2;
    let mut lanes = Vec::with_capacity(lane_count as usize);
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &left,
            lane_bits,
            pair * 2,
            op,
            saturating,
        ));
    }
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &right,
            lane_bits,
            pair * 2,
            op,
            saturating,
        ));
    }
    let parts = lanes.into_iter().rev().collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn avx_packed_horizontal(
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
    let (lane_bits, op, saturating) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPHADDW as u32 => {
            (16, SemanticOperationBinary::Add, false)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPHADDD as u32 => {
            (32, SemanticOperationBinary::Add, false)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPHADDSW as u32 => {
            (16, SemanticOperationBinary::Add, true)
        }
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    if lane_count % 2 != 0 {
        return None;
    }
    let pair_count = lane_count / 2;
    let mut lanes = Vec::with_capacity(lane_count as usize);
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &left,
            lane_bits,
            pair * 2,
            op,
            saturating,
        ));
    }
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &right,
            lane_bits,
            pair * 2,
            op,
            saturating,
        ));
    }
    let parts = lanes.into_iter().rev().collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(super) fn packed_sign(
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
        InsnId(id) if id == X86Insn::X86_INS_PSIGNB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PSIGNW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PSIGND as u32 => 32,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let value = extract_lane(&left, lane_bits, lane);
        let control = extract_lane(&right, lane_bits, lane);
        let is_zero = common::compare(
            SemanticOperationCompare::Eq,
            control.clone(),
            common::const_u64(0, lane_bits),
        );
        let is_negative = common::extract_bit(control, lane_bits - 1);
        parts.push(SemanticExpression::Select {
            condition: Box::new(is_zero),
            when_true: Box::new(common::const_u64(0, lane_bits)),
            when_false: Box::new(SemanticExpression::Select {
                condition: Box::new(is_negative),
                when_true: Box::new(SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(value.clone()),
                    bits: lane_bits,
                }),
                when_false: Box::new(value),
                bits: lane_bits,
            }),
            bits: lane_bits,
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

pub(super) fn packed_unsigned_saturating_sub(
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
        InsnId(id) if id == X86Insn::X86_INS_PSUBUSB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PSUBUSW as u32 => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = extract_lane(&left, lane_bits, lane);
        let rhs = extract_lane(&right, lane_bits, lane);
        let diff = SemanticExpression::Binary {
            op: SemanticOperationBinary::Sub,
            left: Box::new(lhs.clone()),
            right: Box::new(rhs.clone()),
            bits: lane_bits,
        };
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::compare(
                SemanticOperationCompare::Ult,
                lhs,
                rhs,
            )),
            when_true: Box::new(common::const_u64(0, lane_bits)),
            when_false: Box::new(diff),
            bits: lane_bits,
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

pub(super) fn packed_multiply(
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
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PMULHW as u32 => packed_mul_high(bits, &left, &right),
        InsnId(id) if id == X86Insn::X86_INS_PMULHUW as u32 => {
            packed_mul_high_unsigned(bits, &left, &right)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMULLW as u32 => {
            packed_mul_low(bits, &left, &right, 16)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMULLD as u32 => {
            packed_mul_low(bits, &left, &right, 32)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMULUDQ as u32 => packed_muludq(bits, &left, &right),
        InsnId(id) if id == X86Insn::X86_INS_PMADDWD as u32 => packed_maddwd(bits, &left, &right),
        InsnId(id) if id == X86Insn::X86_INS_PMADDUBSW as u32 => Some(
            SemanticExpression::Intrinsic {
                name: "x86.pmaddubsw".to_string(),
                args: vec![left.clone(), right.clone()],
                bits,
            },
        ),
        InsnId(id) if id == X86Insn::X86_INS_PMULHRSW as u32 => Some(
            SemanticExpression::Intrinsic {
                name: "x86.pmulhrsw".to_string(),
                args: vec![left.clone(), right.clone()],
                bits,
            },
        ),
        _ => return None,
    }?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn avx_packed_multiply(
    machine: Architecture,
    instruction: &Insn,
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
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPMULHW as u32 => packed_mul_high(bits, &left, &right),
        InsnId(id) if id == X86Insn::X86_INS_VPMULLW as u32 => {
            packed_mul_low(bits, &left, &right, 16)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMADDWD as u32 => packed_maddwd(bits, &left, &right),
        _ => return None,
    }?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn psadbw(
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
            expression: SemanticExpression::Intrinsic {
                name: "x86.psadbw".to_string(),
                args: vec![left, right],
                bits,
            },
        }],
    ))
}

fn packed_mul_high(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
) -> Option<SemanticExpression> {
    if bits == 0 || bits % 16 != 0 {
        return None;
    }
    let lane_count = bits / 16;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(left, 16, lane)),
            bits: 32,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(right, 16, lane)),
            bits: 32,
        };
        let product = SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: 32,
        };
        parts.push(SemanticExpression::Extract {
            arg: Box::new(product),
            lsb: 16,
            bits: 16,
        });
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn packed_mul_high_unsigned(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
) -> Option<SemanticExpression> {
    if bits == 0 || bits % 16 != 0 {
        return None;
    }
    let lane_count = bits / 16;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(left, 16, lane)),
            bits: 32,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(right, 16, lane)),
            bits: 32,
        };
        let product = SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: 32,
        };
        parts.push(SemanticExpression::Extract {
            arg: Box::new(product),
            lsb: 16,
            bits: 16,
        });
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn packed_mul_low(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
    lane_bits: u16,
) -> Option<SemanticExpression> {
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = extract_lane(left, lane_bits, lane);
        let rhs = extract_lane(right, lane_bits, lane);
        parts.push(truncate_to_bits(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::Mul,
                left: Box::new(lhs),
                right: Box::new(rhs),
                bits: lane_bits,
            },
            lane_bits,
        ));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn packed_muludq(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
) -> Option<SemanticExpression> {
    if bits != 64 && bits != 128 {
        return None;
    }
    let lane_count = bits / 64;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let src_lane = lane * 2;
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(left, 32, src_lane)),
            bits: 64,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(right, 32, src_lane)),
            bits: 64,
        };
        parts.push(SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: 64,
        });
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn packed_maddwd(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
) -> Option<SemanticExpression> {
    if bits == 0 || bits % 32 != 0 {
        return None;
    }
    let lane_count = bits / 32;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let base = lane * 2;
        let lhs0 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(left, 16, base)),
            bits: 32,
        };
        let rhs0 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(right, 16, base)),
            bits: 32,
        };
        let lhs1 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(left, 16, base + 1)),
            bits: 32,
        };
        let rhs1 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(right, 16, base + 1)),
            bits: 32,
        };
        let product0 = SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs0),
            right: Box::new(rhs0),
            bits: 32,
        };
        let product1 = SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs1),
            right: Box::new(rhs1),
            bits: 32,
        };
        parts.push(SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(product0),
            right: Box::new(product1),
            bits: 32,
        });
    }
    Some(SemanticExpression::Concat { parts, bits })
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

pub(super) fn lane_mask(bits: u16) -> u128 {
    if bits as u32 >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

pub(super) fn interleave_lanes(
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

pub(super) fn extract_lane(
    vector: &SemanticExpression,
    lane_bits: u16,
    lane: u16,
) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(vector.clone()),
        lsb: lane * lane_bits,
        bits: lane_bits,
    }
}

pub(super) fn extract_range(vector: &SemanticExpression, lsb: u16, bits: u16) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(vector.clone()),
        lsb,
        bits,
    }
}

fn horizontal_pair_result(
    vector: &SemanticExpression,
    lane_bits: u16,
    first_lane: u16,
    op: SemanticOperationBinary,
    saturating: bool,
) -> SemanticExpression {
    let left = extract_lane(vector, lane_bits, first_lane);
    let right = extract_lane(vector, lane_bits, first_lane + 1);
    if saturating {
        let ext_bits = lane_bits + 1;
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(left),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(right),
            bits: ext_bits,
        };
        let result = SemanticExpression::Binary {
            op,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        saturate_lane(result, ext_bits, lane_bits, PackKind::Signed)
    } else {
        SemanticExpression::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
            bits: lane_bits,
        }
    }
}

pub(super) fn is_memory_operand(operand: &ArchOperand) -> bool {
    matches!(
        operand,
        ArchOperand::X86Operand(op) if matches!(op.op_type, X86OperandType::Mem(_))
    )
}
