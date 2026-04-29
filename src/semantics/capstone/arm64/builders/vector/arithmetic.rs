use super::*;
use crate::semantics::SemanticOperationCast;

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

pub(crate) fn build_addv(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_vector_add_reduce(machine, instruction, operands)
}

pub(crate) fn build_uaddlv(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_vector_add_reduce(machine, instruction, operands)
}

pub(crate) fn build_addp(
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

pub(crate) fn build_addhn(
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

pub(crate) fn build_addhn2(
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
