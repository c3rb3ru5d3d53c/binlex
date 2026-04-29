use super::*;
use crate::semantics::{SemanticOperationCast, SemanticOperationUnary};

pub(crate) fn build_adc(
    machine: Architecture,
    operands: &[ArchOperand],
    update_flags: bool,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let carry = zero_extend_to_bits(flag_expr("c"), bits);
    let right_with_carry = binary(SemanticOperationBinary::Add, right, carry, bits);
    let expression = binary(
        SemanticOperationBinary::Add,
        left.clone(),
        right_with_carry.clone(),
        bits,
    );
    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: expression.clone(),
    }];
    if update_flags {
        effects.extend(arithmetic_flag_effects(
            SemanticOperationBinary::Add,
            left,
            right_with_carry,
            expression,
        ));
    }
    let _ = machine;
    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(crate) fn build_sbc(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let borrow = binary(
        SemanticOperationBinary::Sub,
        const_u64(1, bits),
        zero_extend_to_bits(flag_expr("c"), bits),
        bits,
    );
    let expression = binary(
        SemanticOperationBinary::Sub,
        binary(SemanticOperationBinary::Sub, left, right, bits),
        borrow,
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(crate) fn build_clz(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::CountLeadingZeros,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_eon(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Xor,
                left,
                binary(
                    SemanticOperationBinary::Xor,
                    right,
                    const_u64(bitmask(bits), bits),
                    bits,
                ),
                bits,
            ),
        }],
    ))
}

pub(crate) fn build_binary_assign(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
    update_flags: bool,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = dst.bits();
    let result = binary(op, left.clone(), right.clone(), bits);

    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: result.clone(),
    }];

    if update_flags {
        effects.extend(arithmetic_flag_effects(op, left, right, result));
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(crate) fn build_compare_flags(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let result = binary(
        SemanticOperationBinary::Sub,
        left.clone(),
        right.clone(),
        left.bits(),
    );
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        arithmetic_flag_effects(SemanticOperationBinary::Sub, left, right, result),
    ))
}

pub(crate) fn build_compare_add_flags(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let result = binary(
        SemanticOperationBinary::Add,
        left.clone(),
        right.clone(),
        left.bits(),
    );
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        arithmetic_flag_effects(SemanticOperationBinary::Add, left, right, result),
    ))
}

pub(crate) fn build_shift_assign(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let amount = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(op, src, amount, bits),
        }],
    ))
}

pub(crate) fn build_abs(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let zero = const_u64(0, bits);
    let negative = binary(
        SemanticOperationBinary::Sub,
        zero.clone(),
        src.clone(),
        bits,
    );
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(sign_bit(src.clone())),
                when_true: Box::new(negative),
                when_false: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_sign_extend_word(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 32)),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_sign_extend_byte(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 8)),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_sign_extend_halfword(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 16)),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_bics(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };
    let result = binary(SemanticOperationBinary::And, left, not_right, bits);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            set_flag("n", sign_bit(result.clone())),
            set_flag(
                "z",
                compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
            ),
            set_flag("c", bool_const(false)),
            set_flag("v", bool_const(false)),
        ],
    ))
}

pub(crate) fn build_bic(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::And, left, not_right, bits),
        }],
    ))
}

pub(crate) fn build_orn(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, left, not_right, bits),
        }],
    ))
}

pub(crate) fn build_mvn(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::Not,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_neg(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, const_u64(0, bits), src, bits),
        }],
    ))
}

pub(crate) fn build_rbit(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::BitReverse,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_rev(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::ByteSwap,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_rev16(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let expression = reverse_bytes_in_chunks(src, bits, 16)?;
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(crate) fn build_rev32(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    let expression = reverse_bytes_in_chunks(src, bits, 32)?;
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(crate) fn build_zero_extend_byte(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: zero_extend_to_bits(truncate_to_bits(src, 8), bits),
        }],
    ))
}

pub(crate) fn build_zero_extend_halfword(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: zero_extend_to_bits(truncate_to_bits(src, 16), bits),
        }],
    ))
}

pub(crate) fn build_test_flags(
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = operand_expression(operands.get(1)?)?;
    let bits = left.bits();
    let result = binary(SemanticOperationBinary::And, left, right, bits);
    let _ = instruction;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            set_flag("n", sign_bit(result.clone())),
            set_flag(
                "z",
                compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
            ),
            set_flag("c", bool_const(false)),
            set_flag("v", bool_const(false)),
        ],
    ))
}
