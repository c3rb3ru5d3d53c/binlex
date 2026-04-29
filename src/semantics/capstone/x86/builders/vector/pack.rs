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

pub(super) fn avx_packed_pack(
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
    let (src_lane_bits, dst_lane_bits, pack_kind) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPACKSSDW as u32 => (32, 16, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_VPACKSSWB as u32 => (16, 8, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_VPACKUSWB as u32 => (16, 8, PackKind::UnsignedByte),
        _ => return None,
    };
    let expression = if bits == 256 {
        let mut parts = Vec::new();
        for base_lsb in [128, 0] {
            let left_half = extract_range(&left, base_lsb, 128);
            let right_half = extract_range(&right, base_lsb, 128);
            let half_lane_count = 128 / (dst_lane_bits * 2);
            let mut lanes = Vec::with_capacity((half_lane_count * 2) as usize);
            for lane in 0..half_lane_count {
                lanes.push(saturate_lane(
                    extract_lane(&left_half, src_lane_bits, lane),
                    src_lane_bits,
                    dst_lane_bits,
                    pack_kind,
                ));
            }
            for lane in 0..half_lane_count {
                lanes.push(saturate_lane(
                    extract_lane(&right_half, src_lane_bits, lane),
                    src_lane_bits,
                    dst_lane_bits,
                    pack_kind,
                ));
            }
            let half = lanes.into_iter().rev().collect::<Vec<_>>();
            parts.push(SemanticExpression::Concat {
                parts: half,
                bits: 128,
            });
        }
        parts
    } else {
        let half_lane_count = bits / (dst_lane_bits * 2);
        let mut lanes = Vec::with_capacity((half_lane_count * 2) as usize);
        for lane in 0..half_lane_count {
            lanes.push(saturate_lane(
                extract_lane(&left, src_lane_bits, lane),
                src_lane_bits,
                dst_lane_bits,
                pack_kind,
            ));
        }
        for lane in 0..half_lane_count {
            lanes.push(saturate_lane(
                extract_lane(&right, src_lane_bits, lane),
                src_lane_bits,
                dst_lane_bits,
                pack_kind,
            ));
        }
        lanes.into_iter().rev().collect::<Vec<_>>()
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: expression,
                bits,
            },
        }],
    ))
}

pub(super) fn packed_pack(
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
    let (src_lane_bits, dst_lane_bits, pack_kind) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PACKSSDW as u32 => (32, 16, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_PACKSSWB as u32 => (16, 8, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_PACKUSWB as u32 => (16, 8, PackKind::UnsignedByte),
        _ => return None,
    };
    if bits == 0 || bits % dst_lane_bits != 0 {
        return None;
    }
    let half_lane_count = bits / (dst_lane_bits * 2);
    let mut lanes = Vec::with_capacity((half_lane_count * 2) as usize);
    for lane in 0..half_lane_count {
        lanes.push(saturate_lane(
            extract_lane(&left, src_lane_bits, lane),
            src_lane_bits,
            dst_lane_bits,
            pack_kind,
        ));
    }
    for lane in 0..half_lane_count {
        lanes.push(saturate_lane(
            extract_lane(&right, src_lane_bits, lane),
            src_lane_bits,
            dst_lane_bits,
            pack_kind,
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

#[derive(Clone, Copy)]
pub(super) enum PackKind {
    Signed,
    UnsignedByte,
}

pub(super) fn saturate_lane(
    lane: SemanticExpression,
    src_lane_bits: u16,
    dst_lane_bits: u16,
    kind: PackKind,
) -> SemanticExpression {
    match kind {
        PackKind::Signed => {
            let min_value = signed_min_value(src_lane_bits, dst_lane_bits);
            let max_value = signed_max_value(dst_lane_bits);
            let min_const = SemanticExpression::Const {
                value: min_value,
                bits: src_lane_bits,
            };
            let max_const = SemanticExpression::Const {
                value: max_value,
                bits: src_lane_bits,
            };
            let truncated = truncate_to_bits(lane.clone(), dst_lane_bits);
            SemanticExpression::Select {
                condition: Box::new(common::compare(
                    SemanticOperationCompare::Slt,
                    lane.clone(),
                    min_const,
                )),
                when_true: Box::new(SemanticExpression::Const {
                    value: signed_min_truncated(dst_lane_bits),
                    bits: dst_lane_bits,
                }),
                when_false: Box::new(SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Sgt,
                        lane.clone(),
                        max_const,
                    )),
                    when_true: Box::new(SemanticExpression::Const {
                        value: max_value,
                        bits: dst_lane_bits,
                    }),
                    when_false: Box::new(truncated),
                    bits: dst_lane_bits,
                }),
                bits: dst_lane_bits,
            }
        }
        PackKind::UnsignedByte => {
            let zero = common::const_u64(0, src_lane_bits);
            let max_const = SemanticExpression::Const {
                value: 0xff,
                bits: src_lane_bits,
            };
            let truncated = truncate_to_bits(lane.clone(), dst_lane_bits);
            SemanticExpression::Select {
                condition: Box::new(common::compare(
                    SemanticOperationCompare::Slt,
                    lane.clone(),
                    zero,
                )),
                when_true: Box::new(common::const_u64(0, dst_lane_bits)),
                when_false: Box::new(SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Sgt,
                        lane,
                        max_const,
                    )),
                    when_true: Box::new(common::const_u64(0xff, dst_lane_bits)),
                    when_false: Box::new(truncated),
                    bits: dst_lane_bits,
                }),
                bits: dst_lane_bits,
            }
        }
    }
}

pub(super) fn signed_max_value(bits: u16) -> u128 {
    (1u128 << (bits - 1)) - 1
}

pub(super) fn signed_min_truncated(bits: u16) -> u128 {
    1u128 << (bits - 1)
}

pub(super) fn signed_min_value(src_bits: u16, dst_bits: u16) -> u128 {
    (1u128 << src_bits) - (1u128 << (dst_bits - 1))
}
