use super::*;
use crate::semantics::SemanticOperationUnary;

pub(crate) fn build_uzp1(
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

pub(crate) fn build_rev64(
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

pub(crate) fn build_cnt(
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
