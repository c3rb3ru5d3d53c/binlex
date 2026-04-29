use super::*;

pub(super) fn binary(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
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
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let carry = if op == SemanticOperationBinary::Add {
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
    } else {
        common::compare(SemanticOperationCompare::Ult, left.clone(), right.clone())
    };
    let overflow = if op == SemanticOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

pub(super) fn adc(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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
    let carry_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(common::flag_expr("cf")),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in.clone(), bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            common::flag_expr("cf"),
            common::compare(SemanticOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry_out,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    left.clone(),
                    right_with_carry.clone(),
                    result.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(left, right_with_carry, result, bits),
            },
        ],
    ))
}

pub(super) fn sbb(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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
    let borrow_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(common::flag_expr("cf")),
        bits,
    };
    let right_with_borrow = common::add(right.clone(), borrow_in.clone(), bits);
    let result = common::sub(left.clone(), right_with_borrow.clone(), bits);
    let carry_out = common::or(
        common::compare(
            SemanticOperationCompare::Ult,
            left.clone(),
            right_with_borrow.clone(),
        ),
        common::and(
            common::flag_expr("cf"),
            common::compare(
                SemanticOperationCompare::Eq,
                left.clone(),
                right_with_borrow.clone(),
            ),
            1,
        ),
        1,
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry_out,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(
                    left.clone(),
                    right_with_borrow.clone(),
                    result.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(left, right_with_borrow, result, bits),
            },
        ],
    ))
}

pub(super) fn adcx_adox(
    machine: Architecture,
    operands: &[ArchOperand],
    use_cf: bool,
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
    let carry_flag = if use_cf { "cf" } else { "of" };
    let carry_in_flag = common::flag_expr(carry_flag);
    let carry_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(carry_in_flag.clone()),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in, bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            carry_in_flag.clone(),
            common::compare(SemanticOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    let overflow_out =
        common::add_overflow(left.clone(), right_with_carry.clone(), result.clone(), bits);

    let mut effects = vec![SemanticEffect::Set {
        dst,
        expression: result,
    }];
    if use_cf {
        effects.push(SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: carry_out,
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("of"),
            expression: common::flag_expr("of"),
        });
    } else {
        effects.push(SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: common::flag_expr("cf"),
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("of"),
            expression: overflow_out,
        });
    }
    for flag in ["zf", "sf", "pf", "af"] {
        effects.push(SemanticEffect::Set {
            dst: common::flag(flag),
            expression: common::flag_expr(flag),
        });
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn unary(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let right = common::const_u64(1, bits);
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let overflow = if op == SemanticOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

pub(super) fn unary_op(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    op: SemanticOperationUnary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let expression = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    if matches!(instruction.id(), InsnId(id) if id == X86Insn::X86_INS_NEG as u32) {
        let zero = common::const_u64(0, bits);
        let result = SemanticExpression::Unary {
            op,
            arg: Box::new(expression.clone()),
            bits,
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![
                SemanticEffect::Set {
                    dst,
                    expression: result.clone(),
                },
                SemanticEffect::Set {
                    dst: common::flag("cf"),
                    expression: common::compare(
                        SemanticOperationCompare::Ne,
                        expression.clone(),
                        zero.clone(),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("zf"),
                    expression: common::compare(SemanticOperationCompare::Eq, result.clone(), zero),
                },
                SemanticEffect::Set {
                    dst: common::flag("sf"),
                    expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
                },
                SemanticEffect::Set {
                    dst: common::flag("of"),
                    expression: common::compare(
                        SemanticOperationCompare::Eq,
                        expression.clone(),
                        common::const_u64(1u64 << (bits.saturating_sub(1)), bits),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("pf"),
                    expression: common::parity_flag(result.clone()),
                },
                SemanticEffect::Set {
                    dst: common::flag("af"),
                    expression: common::auxiliary_flag(
                        common::const_u64(0, bits),
                        expression,
                        result,
                        bits,
                    ),
                },
            ],
        ));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

pub(super) fn popcnt(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let result = SemanticExpression::Unary {
        op: SemanticOperationUnary::PopCount,
        arg: Box::new(src.clone()),
        bits,
    };
    let src_is_zero = common::compare(
        SemanticOperationCompare::Eq,
        src,
        common::const_u64(0, bits),
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result,
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: src_is_zero,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

pub(super) fn cmp_like(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))
        .map(|location| common::location_bits(&location))
        .unwrap_or_else(|| common::pointer_bits(machine));
    let diff = common::sub(left.clone(), right.clone(), bits);
    let sign_bit = bits.saturating_sub(1);
    let zf = common::compare(SemanticOperationCompare::Eq, left.clone(), right.clone());
    let cf = common::compare(SemanticOperationCompare::Ult, left.clone(), right.clone());
    let sf = common::extract_bit(diff.clone(), sign_bit);
    let of = common::sub_overflow(left.clone(), right.clone(), diff.clone(), bits);
    let af = common::auxiliary_flag(left.clone(), right.clone(), diff.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: zf,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: cf,
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: sf,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: of,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: af,
            },
        ],
    ))
}
