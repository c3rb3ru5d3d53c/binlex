use super::*;

pub(crate) fn build_vector_compare(
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
