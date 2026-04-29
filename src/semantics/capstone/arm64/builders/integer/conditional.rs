use super::*;
use crate::semantics::SemanticOperationUnary;

pub(crate) fn build_conditional_select(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let when_false = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_cset(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(1)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(const_u64(1, bits)),
                when_false: Box::new(const_u64(0, bits)),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_csetm(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(1)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(const_u64(bitmask(bits), bits)),
                when_false: Box::new(const_u64(0, bits)),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_conditional_select_increment(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let base_false = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let when_false = binary(
        SemanticOperationBinary::Add,
        base_false,
        const_u64(1, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_conditional_increment(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let base = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(2)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let incremented = binary(
        SemanticOperationBinary::Add,
        base.clone(),
        const_u64(1, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(incremented),
                when_false: Box::new(base),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_conditional_invert(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let base = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(2)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let inverted = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(base.clone()),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(inverted),
                when_false: Box::new(base),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_conditional_select_invert(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let false_src = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let when_false = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(false_src),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_conditional_negate(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(2)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let negated = binary(
        SemanticOperationBinary::Sub,
        const_u64(0, bits),
        src.clone(),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(negated),
                when_false: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_conditional_select_negate(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let when_true = operand_expression(operands.get(1)?)?;
    let false_src = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let when_false = binary(
        SemanticOperationBinary::Sub,
        const_u64(0, bits),
        false_src,
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_conditional_compare(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let fallback_nzcv = operand_immediate(operands.get(2)?)?;
    let condition = condition_from_cc(
        operands
            .get(3)
            .and_then(operand_immediate)
            .or(condition_code)?,
    )?;
    let result = binary(op, left.clone(), right.clone(), left.bits());
    let compare_flags = arithmetic_flag_values(op, left, right, result);
    let fallback_flags = [
        ((fallback_nzcv >> 3) & 1) != 0,
        ((fallback_nzcv >> 2) & 1) != 0,
        ((fallback_nzcv >> 1) & 1) != 0,
        (fallback_nzcv & 1) != 0,
    ];
    let flag_names = ["n", "z", "c", "v"];
    let effects = flag_names
        .into_iter()
        .zip(compare_flags)
        .zip(fallback_flags)
        .map(
            |((name, compare_value), fallback_value)| SemanticEffect::Set {
                dst: flag(name),
                expression: SemanticExpression::Select {
                    condition: Box::new(condition.clone()),
                    when_true: Box::new(compare_value),
                    when_false: Box::new(bool_const(fallback_value)),
                    bits: 1,
                },
            },
        )
        .collect();
    let _ = machine;
    Some(complete(SemanticTerminator::FallThrough, effects))
}
