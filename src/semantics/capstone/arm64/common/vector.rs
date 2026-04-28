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

pub(in crate::semantics::capstone::arm64) fn build_intrinsic_fallthrough(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    outputs: Option<Vec<SemanticLocation>>,
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("intrinsic")),
            args,
            outputs: outputs.unwrap_or_default(),
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_movi(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let Some(imm) = operands.get(1).and_then(operand_immediate) else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
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
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
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
            expression: SemanticExpression::Const { value, bits },
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_fmov(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let Some(dst) = operands
        .first()
        .and_then(|operand| operand_location(machine, operand))
    else {
        return build_intrinsic_fallthrough(machine, instruction, operands, None);
    };
    let bits = location_bits(&dst);
    let src = match operands.get(1) {
        Some(ArchOperand::Arm64Operand(op)) => match op.op_type {
            Arm64OperandType::Fp(fp) => SemanticExpression::Const {
                value: if bits == 32 {
                    (fp as f32).to_bits() as u128
                } else {
                    fp.to_bits() as u128
                },
                bits,
            },
            _ => operand_expression(operands.get(1)?)?,
        },
        _ => {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
        }
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: src,
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn parse_vector_arrangement(
    op_str: &str,
) -> Option<(u16, u16)> {
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

pub(in crate::semantics::capstone::arm64) fn zero_extend_if_needed(
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

pub(in crate::semantics::capstone::arm64) fn build_vector_compare(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    compare: SemanticOperationCompare,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
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

pub(in crate::semantics::capstone::arm64) fn build_uzp1(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
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

fn build_vector_add_reduce(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
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

pub(in crate::semantics::capstone::arm64) fn build_addv(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_vector_add_reduce(machine, instruction, operands)
}

pub(in crate::semantics::capstone::arm64) fn build_uaddlv(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_vector_add_reduce(machine, instruction, operands)
}

fn lane_bits_from_vas(vas: Arm64Vas) -> Option<u16> {
    match vas {
        Arm64Vas::ARM64_VAS_16B
        | Arm64Vas::ARM64_VAS_8B
        | Arm64Vas::ARM64_VAS_4B
        | Arm64Vas::ARM64_VAS_1B => Some(8),
        Arm64Vas::ARM64_VAS_8H
        | Arm64Vas::ARM64_VAS_4H
        | Arm64Vas::ARM64_VAS_2H
        | Arm64Vas::ARM64_VAS_1H => Some(16),
        Arm64Vas::ARM64_VAS_4S | Arm64Vas::ARM64_VAS_2S | Arm64Vas::ARM64_VAS_1S => Some(32),
        Arm64Vas::ARM64_VAS_2D | Arm64Vas::ARM64_VAS_1D => Some(64),
        Arm64Vas::ARM64_VAS_1Q => Some(128),
        _ => None,
    }
}

pub(in crate::semantics::capstone::arm64) fn build_ld1_lane(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let addr = memory_address(operands.get(1)?)?;
    let ArchOperand::Arm64Operand(op) = operands.first()? else {
        return None;
    };
    let lane_index = op.vector_index? as u16;
    let lane_bits = lane_bits_from_vas(op.vas)?;
    let lane_count = dst_bits / lane_bits;
    let load = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
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

pub(in crate::semantics::capstone::arm64) fn build_dup(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
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

pub(in crate::semantics::capstone::arm64) fn build_addp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (src_lanes, lane_bits, dst_lanes) = if op_str.contains(".16b") {
        (16u16, 8u16, 16u16)
    } else if op_str.contains(".8h") {
        (8u16, 16u16, 8u16)
    } else if op_str.contains(".4s") {
        (4u16, 32u16, 4u16)
    } else if op_str.contains(".2d") {
        (2u16, 64u16, 2u16)
    } else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    if dst_lanes != src_lanes {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
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

pub(in crate::semantics::capstone::arm64) fn build_addhn(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (lane_count, src_lane_bits, dst_lane_bits) =
        if op_str.contains(".8b") && op_str.contains(".8h") {
            (8u16, 16u16, 8u16)
        } else if op_str.contains(".4h") && op_str.contains(".4s") {
            (4u16, 32u16, 16u16)
        } else if op_str.contains(".2s") && op_str.contains(".2d") {
            (2u16, 64u16, 32u16)
        } else {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
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

pub(in crate::semantics::capstone::arm64) fn build_addhn2(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let current_dst = operand_expression(operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (lane_count, src_lane_bits, dst_lane_bits, low_half_bits) =
        if op_str.contains(".16b") && op_str.contains(".8h") {
            (8u16, 16u16, 8u16, 64u16)
        } else if op_str.contains(".8h") && op_str.contains(".4s") {
            (4u16, 32u16, 16u16, 64u16)
        } else if op_str.contains(".4s") && op_str.contains(".2d") {
            (2u16, 64u16, 32u16, 64u16)
        } else {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
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

pub(in crate::semantics::capstone::arm64) fn build_rev64(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
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

pub(in crate::semantics::capstone::arm64) fn build_cnt(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let dst_bits = location_bits(&dst);
    let src = operand_expression(operands.get(1)?)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    if lane_bits != 8 {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
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

pub(in crate::semantics::capstone::arm64) fn build_extr(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let shift = operand_immediate(operands.get(3)?)? as u16;
    let concat = SemanticExpression::Concat {
        parts: vec![left, right],
        bits: bits * 2,
    };
    let shifted = binary(
        SemanticOperationBinary::LShr,
        concat,
        const_u64(shift as u64, bits * 2),
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
