use super::*;
use crate::semantics::SemanticOperationCast;
use capstone::arch::arm64::Arm64OperandType;

pub(crate) fn build_movi(
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

pub(crate) fn build_fmov(
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

pub(crate) fn build_ld1_lane(
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

pub(crate) fn build_dup(
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

pub(crate) fn build_extr(
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

pub(crate) fn build_sshll(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let shift = operands.get(2).and_then(operand_immediate).unwrap_or(0);
    let Some(op_str) = instruction.op_str() else {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
    };
    let (lane_count, src_lane_bits, dst_lane_bits) =
        if op_str.contains(".8h") && op_str.contains(".8b") {
            (8u16, 8u16, 16u16)
        } else if op_str.contains(".4s") && op_str.contains(".4h") {
            (4u16, 16u16, 32u16)
        } else if op_str.contains(".2d") && op_str.contains(".2s") {
            (2u16, 32u16, 64u16)
        } else {
            return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
        };
    if shift != 0 {
        return build_intrinsic_fallthrough(machine, instruction, operands, Some(vec![dst]));
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
