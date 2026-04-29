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

use crate::semantics::architectures::arm64::Arm64InstructionView;
use crate::semantics::architectures::arm64::Arm64OperandKind;
use crate::semantics::architectures::arm64::builders::memory::{
    build_store_pair, effective_memory_address, operand_expression, register_location,
    writeback_effect,
};
use crate::semantics::architectures::arm64::helpers::{
    binary, bitmask, complete, const_u64, location_bits,
};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator,
};

pub(crate) fn build(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    match view.mnemonic.as_str() {
        "bcax" if view.operand_count >= 4 => build_bcax(view),
        "bsl" if view.operand_count >= 3 => build_bsl(view),
        "bif" if view.operand_count >= 3 => build_bit_insert(view, true),
        "bit" if view.operand_count >= 3 => build_bit_insert(view, false),
        "cmeq" if view.operand_count >= 3 => build_vector_compare(view, SemanticOperationCompare::Eq),
        "cmhi" if view.operand_count >= 3 => build_vector_compare(view, SemanticOperationCompare::Ugt),
        "addv" if view.operand_count >= 2 => build_vector_add_reduce(view),
        "uaddlv" if view.operand_count >= 2 => build_vector_add_reduce(view),
        "addp" if view.operand_count >= 3 => build_addp(view),
        "addhn" if view.operand_count >= 3 => build_addhn(view),
        "addhn2" if view.operand_count >= 3 => build_addhn2(view),
        "uzp1" if view.operand_count >= 3 => build_uzp1(view),
        "rev64" if view.operand_count >= 2 => build_rev64(view),
        "cnt" if view.operand_count >= 2 => build_cnt(view),
        "movi" if view.operand_count >= 2 => build_movi(view),
        "fmov" if view.operand_count >= 2 => build_fmov(view),
        "dup" if view.operand_count >= 2 => build_dup(view),
        "extr" if view.operand_count >= 4 => build_extr(view),
        "sshll" if view.operand_count >= 2 => build_sshll(view),
        "ld1" if view.operand_count >= 2 => build_ld1(view),
        "aesd" | "aese" if view.operand_count >= 2 => build_aes_round(view),
        "aesimc" | "aesmc" if view.operand_count >= 2 => build_aes_mix_columns(view),
        "ld2" if view.operand_count >= 3 => build_structured_load(view, 2),
        "ld3" if view.operand_count >= 4 => build_structured_load(view, 3),
        "ld4" if view.operand_count >= 5 => build_structured_load(view, 4),
        "st1" if view.operand_count >= 3 => build_store_pair(view),
        "ld3r" if view.operand_count >= 3 => build_intrinsic_with_outputs(view, 3),
        "ld4r" if view.operand_count >= 4 => build_intrinsic_with_outputs(view, 4),
        "bfcvt" | "bfcvtn" | "bfcvtn2" | "bfdot" | "bfmlalb"
        | "umov" | "frintm" | "umlsl2" | "ext"
            if view.operand_count >= 1 =>
        {
            build_intrinsic_with_outputs(view, 1)
        }
        _ => None,
    }
}

fn build_bcax(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let vn = operand_expression(view.operand(1)?)?;
    let vm = operand_expression(view.operand(2)?)?;
    let va = operand_expression(view.operand(3)?)?;
    let not_va = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(va),
        bits,
    };
    let result = binary(
        SemanticOperationBinary::Xor,
        vn,
        binary(SemanticOperationBinary::And, vm, not_va, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

fn build_bsl(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let mask = SemanticExpression::Read(Box::new(dst.clone()));
    let vn = operand_expression(view.operand(1)?)?;
    let vm = operand_expression(view.operand(2)?)?;
    let result = binary(
        SemanticOperationBinary::Or,
        binary(SemanticOperationBinary::And, mask.clone(), vn, bits),
        binary(
            SemanticOperationBinary::And,
            SemanticExpression::Unary {
                op: SemanticOperationUnary::Not,
                arg: Box::new(mask),
                bits,
            },
            vm,
            bits,
        ),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

fn build_bit_insert(view: &Arm64InstructionView, invert_mask: bool) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(view.operand(1)?)?;
    let mask_input = operand_expression(view.operand(2)?)?;
    let mask = if invert_mask {
        SemanticExpression::Unary {
            op: SemanticOperationUnary::Not,
            arg: Box::new(mask_input),
            bits,
        }
    } else {
        mask_input
    };
    let result = binary(
        SemanticOperationBinary::Xor,
        current.clone(),
        binary(
            SemanticOperationBinary::And,
            binary(SemanticOperationBinary::Xor, current, src, bits),
            mask,
            bits,
        ),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

fn build_vector_compare(
    view: &Arm64InstructionView,
    compare: SemanticOperationCompare,
) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let dst_bits = location_bits(&dst);
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    let ones = bitmask(lane_bits) as u128;
    let parts = (0..lane_count)
        .rev()
        .map(|lane| {
            let left_lane = SemanticExpression::Extract {
                arg: Box::new(left.clone()),
                lsb: lane * lane_bits,
                bits: lane_bits,
            };
            let right_lane = SemanticExpression::Extract {
                arg: Box::new(right.clone()),
                lsb: lane * lane_bits,
                bits: lane_bits,
            };
            SemanticExpression::Select {
                condition: Box::new(SemanticExpression::Compare {
                    op: compare,
                    left: Box::new(left_lane),
                    right: Box::new(right_lane),
                    bits: 1,
                }),
                when_true: Box::new(SemanticExpression::Const {
                    value: ones,
                    bits: lane_bits,
                }),
                when_false: Box::new(SemanticExpression::Const {
                    value: 0,
                    bits: lane_bits,
                }),
                bits: lane_bits,
            }
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_vector_add_reduce(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(view.operand(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    let mut sum = SemanticExpression::Const {
        value: 0,
        bits: dst_bits,
    };
    for lane in 0..lane_count {
        let lane_expr = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: lane * lane_bits,
                bits: lane_bits,
            }),
            bits: dst_bits,
        };
        sum = binary(SemanticOperationBinary::Add, sum, lane_expr, dst_bits);
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: sum,
        }],
    ))
}

fn build_addp(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let op_str = view.operand_text.as_deref()?;
    let (src_lanes, lane_bits, dst_lanes) = if op_str.contains(".16b") {
        (16u16, 8u16, 16u16)
    } else if op_str.contains(".8h") {
        (8u16, 16u16, 8u16)
    } else if op_str.contains(".4s") {
        (4u16, 32u16, 4u16)
    } else if op_str.contains(".2d") {
        (2u16, 64u16, 2u16)
    } else {
        return None;
    };
    if dst_lanes != src_lanes {
        return None;
    }
    let mut parts = Vec::new();
    for lane in (0..(src_lanes / 2)).rev() {
        let r0 = SemanticExpression::Extract {
            arg: Box::new(right.clone()),
            lsb: lane * 2 * lane_bits,
            bits: lane_bits,
        };
        let r1 = SemanticExpression::Extract {
            arg: Box::new(right.clone()),
            lsb: (lane * 2 + 1) * lane_bits,
            bits: lane_bits,
        };
        parts.push(binary(SemanticOperationBinary::Add, r0, r1, lane_bits));
    }
    for lane in (0..(src_lanes / 2)).rev() {
        let l0 = SemanticExpression::Extract {
            arg: Box::new(left.clone()),
            lsb: lane * 2 * lane_bits,
            bits: lane_bits,
        };
        let l1 = SemanticExpression::Extract {
            arg: Box::new(left.clone()),
            lsb: (lane * 2 + 1) * lane_bits,
            bits: lane_bits,
        };
        parts.push(binary(SemanticOperationBinary::Add, l0, l1, lane_bits));
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: SemanticExpression::Concat {
                parts,
                bits: dst.bits(),
            },
        }],
    ))
}

fn build_addhn(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let op_str = view.operand_text.as_deref()?;
    let (lane_count, src_lane_bits, dst_lane_bits) =
        if op_str.contains(".8b") && op_str.contains(".8h") {
            (8u16, 16u16, 8u16)
        } else if op_str.contains(".4h") && op_str.contains(".4s") {
            (4u16, 32u16, 16u16)
        } else if op_str.contains(".2s") && op_str.contains(".2d") {
            (2u16, 64u16, 32u16)
        } else {
            return None;
        };
    let mut parts = Vec::new();
    for lane in (0..lane_count).rev() {
        let sum = binary(
            SemanticOperationBinary::Add,
            SemanticExpression::Extract {
                arg: Box::new(left.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            SemanticExpression::Extract {
                arg: Box::new(right.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            src_lane_bits,
        );
        parts.push(SemanticExpression::Extract {
            arg: Box::new(sum),
            lsb: dst_lane_bits,
            bits: dst_lane_bits,
        });
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: SemanticExpression::Concat {
                parts,
                bits: dst.bits(),
            },
        }],
    ))
}

fn build_addhn2(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let current_dst = operand_expression(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let op_str = view.operand_text.as_deref()?;
    let (lane_count, src_lane_bits, dst_lane_bits, low_half_bits) =
        if op_str.contains(".16b") && op_str.contains(".8h") {
            (8u16, 16u16, 8u16, 64u16)
        } else if op_str.contains(".8h") && op_str.contains(".4s") {
            (4u16, 32u16, 16u16, 64u16)
        } else if op_str.contains(".4s") && op_str.contains(".2d") {
            (2u16, 64u16, 32u16, 64u16)
        } else {
            return None;
        };
    let mut upper_parts = Vec::new();
    for lane in (0..lane_count).rev() {
        let sum = binary(
            SemanticOperationBinary::Add,
            SemanticExpression::Extract {
                arg: Box::new(left.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            SemanticExpression::Extract {
                arg: Box::new(right.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            },
            src_lane_bits,
        );
        upper_parts.push(SemanticExpression::Extract {
            arg: Box::new(sum),
            lsb: dst_lane_bits,
            bits: dst_lane_bits,
        });
    }
    let upper = SemanticExpression::Concat {
        parts: upper_parts,
        bits: low_half_bits,
    };
    let lower = SemanticExpression::Extract {
        arg: Box::new(current_dst),
        lsb: 0,
        bits: low_half_bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![upper, lower],
                bits: 128,
            },
        }],
    ))
}

fn build_uzp1(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let dst_bits = location_bits(&dst);
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    let mut lanes_low_to_high = Vec::new();
    let half = lane_count / 2;
    for lane in 0..half {
        lanes_low_to_high.push((true, lane * 2));
    }
    for lane in 0..half {
        lanes_low_to_high.push((false, lane * 2));
    }
    let parts = lanes_low_to_high
        .into_iter()
        .rev()
        .map(|(from_left, lane)| SemanticExpression::Extract {
            arg: Box::new(if from_left {
                left.clone()
            } else {
                right.clone()
            }),
            lsb: lane * lane_bits,
            bits: lane_bits,
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_rev64(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(view.operand(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    let lanes_per_chunk = (64 / lane_bits).max(1);
    let mut output_lanes_low_to_high = Vec::new();
    let mut chunk_start = 0u16;
    while chunk_start < lane_count {
        for lane in 0..lanes_per_chunk {
            output_lanes_low_to_high.push(chunk_start + (lanes_per_chunk - 1 - lane));
        }
        chunk_start += lanes_per_chunk;
    }
    let parts = output_lanes_low_to_high
        .into_iter()
        .rev()
        .map(|lane| SemanticExpression::Extract {
            arg: Box::new(src.clone()),
            lsb: lane * lane_bits,
            bits: lane_bits,
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_cnt(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(view.operand(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    if lane_bits != 8 {
        return None;
    }
    let parts = (0..lane_count)
        .rev()
        .map(|lane| SemanticExpression::Unary {
            op: SemanticOperationUnary::PopCount,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: lane * 8,
                bits: 8,
            }),
            bits: 8,
        })
        .collect::<Vec<_>>();
    let arrangement_bits = lane_count * 8;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_movi(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst) as usize;
    let imm = view.operand(1)?.immediate_value()?;
    let op_str = view.operand_text.as_deref()?;
    let (lane_count, lane_bits) = if op_str.contains(".16b") {
        (16usize, 8usize)
    } else if op_str.contains(".8b") {
        (8usize, 8usize)
    } else if op_str.contains(".2d") {
        (2usize, 64usize)
    } else if op_str.contains(".2s") {
        (2usize, 32usize)
    } else if op_str.starts_with('d') {
        (1usize, 64usize)
    } else {
        return None;
    };
    let lane_mask = if lane_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << lane_bits) - 1
    };
    let lane_value = imm as u128 & lane_mask;
    let mut value = 0u128;
    for lane in 0..lane_count {
        value |= lane_value << (lane * lane_bits);
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Const {
                value,
                bits: bits as u16,
            },
        }],
    ))
}

fn build_fmov(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let src = match view.operand(1)? {
        operand if operand.float.is_some() => {
            let fp = operand.float?;
            match bits {
                32 => SemanticExpression::Const {
                    value: (fp as f32).to_bits() as u128,
                    bits,
                },
                64 => SemanticExpression::Const {
                    value: fp.to_bits() as u128,
                    bits,
                },
                _ => return None,
            }
        }
        _ => operand_expression(view.operand(1)?)?,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: src,
        }],
    ))
}

fn build_dup(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(view.operand(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    let lane = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: lane_bits,
    };
    let parts = (0..lane_count).map(|_| lane.clone()).collect::<Vec<_>>();
    let arrangement_bits = lane_count * lane_bits;
    let expression = zero_extend_if_needed(
        SemanticExpression::Concat {
            parts,
            bits: arrangement_bits,
        },
        arrangement_bits,
        dst_bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_extr(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let shift = view.operand(3)?.immediate_value()? as u16;
    let concat = SemanticExpression::Concat {
        parts: vec![left, right],
        bits: bits * 2,
    };
    let shifted = binary(
        SemanticOperationBinary::LShr,
        concat,
        crate::semantics::architectures::arm64::helpers::const_u64(shift as u64, bits * 2),
        bits * 2,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Extract {
                arg: Box::new(shifted),
                lsb: 0,
                bits,
            },
        }],
    ))
}

fn build_sshll(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let shift = view
        .operand(2)
        .and_then(|operand| operand.immediate_value())
        .unwrap_or(0);
    let op_str = view.operand_text.as_deref()?;
    let (lane_count, src_lane_bits, dst_lane_bits) =
        if op_str.contains(".8h") && op_str.contains(".8b") {
            (8u16, 8u16, 16u16)
        } else if op_str.contains(".4s") && op_str.contains(".4h") {
            (4u16, 16u16, 32u16)
        } else if op_str.contains(".2d") && op_str.contains(".2s") {
            (2u16, 32u16, 64u16)
        } else {
            return None;
        };
    if shift != 0 {
        return None;
    }
    let mut parts = Vec::new();
    for lane in (0..lane_count).rev() {
        parts.push(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: lane * src_lane_bits,
                bits: src_lane_bits,
            }),
            bits: dst_lane_bits,
        });
    }
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits: 128 },
        }],
    ))
}

fn build_ld1(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    build_ld1_lane(view)
        .or_else(|| build_ld1_full_register(view))
        .or_else(|| build_intrinsic_with_outputs(view, 1))
}

fn build_ld1_lane(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst_operand = view
        .operands()
        .iter()
        .find(|operand| operand.kind == Arm64OperandKind::Register)?;
    let dst = register_location(dst_operand)?;
    let dst_bits = location_bits(&dst);
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let memory_operand = view
        .operands()
        .iter()
        .find(|operand| operand.kind == Arm64OperandKind::Memory)?;
    let addr = effective_memory_address(view, memory_operand, None)?;
    let lane_index = dst_operand.vector_index? as u16;
    let lane_bits = parse_ld1_lane_bits(view.operand_text.as_deref()?)?;
    let lane_count = dst_bits / lane_bits;
    let load = SemanticExpression::Load {
        space: crate::semantics::SemanticAddressSpace::Default,
        addr: Box::new(addr),
        bits: lane_bits,
    };
    let parts = (0..lane_count)
        .rev()
        .map(|lane| {
            if lane == lane_index {
                load.clone()
            } else {
                SemanticExpression::Extract {
                    arg: Box::new(current.clone()),
                    lsb: lane * lane_bits,
                    bits: lane_bits,
                }
            }
        })
        .collect::<Vec<_>>();
    Some(complete(
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

fn build_ld1_full_register(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = view
        .operands()
        .iter()
        .find_map(register_location)?;
    let memory_operand = view
        .operands()
        .iter()
        .find(|operand| operand.kind == Arm64OperandKind::Memory)?;
    let base_addr = effective_memory_address(view, memory_operand, None)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    let lane_bytes = (lane_bits / 8) as u64;
    let parts = (0..lane_count)
        .rev()
        .map(|lane| {
            let addr = binary(
                SemanticOperationBinary::Add,
                base_addr.clone(),
                const_u64(lane as u64 * lane_bytes, 64),
                64,
            );
            SemanticExpression::Load {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: lane_bits,
            }
        })
        .collect::<Vec<_>>();
    let effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: SemanticExpression::Concat {
            parts,
            bits: lane_count * lane_bits,
        },
    }];
    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_aes_round(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let round_key = operand_expression(view.operand(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", view.mnemonic),
            args: vec![SemanticExpression::Read(Box::new(dst.clone())), round_key],
            outputs: vec![dst],
        }],
    ))
}

fn build_aes_mix_columns(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", view.mnemonic),
            args: vec![src],
            outputs: vec![dst],
        }],
    ))
}

fn build_structured_load(
    view: &Arm64InstructionView,
    register_count: usize,
) -> Option<InstructionSemantics> {
    let destinations = view
        .operands()
        .iter()
        .take(register_count)
        .map(register_location)
        .collect::<Option<Vec<_>>>()?;
    let memory_operand = view.operand(register_count)?;
    let writeback_operand = view.operand(register_count + 1);
    let base_addr = effective_memory_address(view, memory_operand, writeback_operand)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(view.operand_text.as_deref()?)?;
    let lane_bytes = (lane_bits / 8) as u64;

    let mut effects = Vec::with_capacity(register_count + 1);
    for (register_index, dst) in destinations.into_iter().enumerate() {
        let dst_bits = location_bits(&dst);
        let parts = (0..lane_count)
            .rev()
            .map(|lane| {
                let offset =
                    ((lane as usize * register_count) + register_index) as u64 * lane_bytes;
                let addr = binary(
                    SemanticOperationBinary::Add,
                    base_addr.clone(),
                    const_u64(offset, 64),
                    64,
                );
                SemanticExpression::Load {
                    space: crate::semantics::SemanticAddressSpace::Default,
                    addr: Box::new(addr),
                    bits: lane_bits,
                }
            })
            .collect::<Vec<_>>();
        let arrangement_bits = lane_count * lane_bits;
        effects.push(SemanticEffect::Set {
            dst,
            expression: zero_extend_if_needed(
                SemanticExpression::Concat {
                    parts,
                    bits: arrangement_bits,
                },
                arrangement_bits,
                dst_bits,
            ),
        });
    }

    if let Some(writeback) = writeback_effect(view, memory_operand, writeback_operand) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_intrinsic_with_outputs(
    view: &Arm64InstructionView,
    output_count: usize,
) -> Option<InstructionSemantics> {
    let outputs = view
        .operands()
        .iter()
        .take(output_count)
        .map(register_location)
        .collect::<Option<Vec<_>>>()?;
    let args = view
        .operands()
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", view.mnemonic),
            args,
            outputs,
        }],
    ))
}

fn parse_ld1_lane_bits(op_str: &str) -> Option<u16> {
    let normalized = op_str.to_ascii_lowercase().replace(' ', "");
    if normalized.contains(".b}[") {
        Some(8)
    } else if normalized.contains(".h}[") {
        Some(16)
    } else if normalized.contains(".s}[") {
        Some(32)
    } else if normalized.contains(".d}[") {
        Some(64)
    } else {
        None
    }
}

fn parse_vector_arrangement(op_str: &str) -> Option<(u16, u16)> {
    if op_str.contains(".16b") {
        Some((16, 8))
    } else if op_str.contains(".8b") {
        Some((8, 8))
    } else if op_str.contains(".8h") {
        Some((8, 16))
    } else if op_str.contains(".4h") {
        Some((4, 16))
    } else if op_str.contains(".4s") {
        Some((4, 32))
    } else if op_str.contains(".2s") {
        Some((2, 32))
    } else if op_str.contains(".2d") {
        Some((2, 64))
    } else {
        None
    }
}

fn zero_extend_if_needed(
    expression: SemanticExpression,
    src_bits: u16,
    dst_bits: u16,
) -> SemanticExpression {
    if src_bits == dst_bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits: dst_bits,
        }
    }
}
