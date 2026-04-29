use super::*;

pub(crate) fn build_fcmp_intrinsic(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operand_expression(operands.first()?)?;
    let right = match operands.get(1) {
        Some(ArchOperand::Arm64Operand(op)) => match op.op_type {
            Arm64OperandType::Fp(fp) => SemanticExpression::Const {
                value: fp.to_bits() as u128,
                bits: left.bits(),
            },
            _ => operand_expression(operands.get(1)?)?,
        },
        Some(_) => operand_expression(operands.get(1)?)?,
        None => SemanticExpression::Const {
            value: 0,
            bits: left.bits(),
        },
    };
    let compare_flags = fp_compare_flag_values(left, right);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            set_flag("n", compare_flags[0].clone()),
            set_flag("z", compare_flags[1].clone()),
            set_flag("c", compare_flags[2].clone()),
            set_flag("v", compare_flags[3].clone()),
        ],
    ))
}

pub(crate) fn build_fccmp(
    machine: Architecture,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
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
    let compare_flags = fp_compare_flag_values(left, right);
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

pub(crate) fn build_fp_binary(
    machine: Architecture,
    operands: &[ArchOperand],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fp_minmax(
    machine: Architecture,
    operands: &[ArchOperand],
    compare_op: SemanticOperationCompare,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(SemanticExpression::Compare {
                    op: compare_op,
                    left: Box::new(left.clone()),
                    right: Box::new(right.clone()),
                    bits: 1,
                }),
                when_true: Box::new(left),
                when_false: Box::new(right),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fnmul(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let bits = location_bits(&dst);
    let zero = match bits {
        32 => const_u64(f32::to_bits(0.0) as u64, 32),
        64 => const_u64(f64::to_bits(0.0), 64),
        _ => return None,
    };
    let product = SemanticExpression::Binary {
        op: SemanticOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::FSub,
                left: Box::new(zero),
                right: Box::new(product),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fmadd(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let addend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = SemanticExpression::Binary {
        op: SemanticOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::FAdd,
                left: Box::new(product),
                right: Box::new(addend),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fmsub(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expression(operands.get(1)?)?;
    let right = operand_expression(operands.get(2)?)?;
    let addend = operand_expression(operands.get(3)?)?;
    let bits = location_bits(&dst);
    let product = SemanticExpression::Binary {
        op: SemanticOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: SemanticOperationBinary::FSub,
                left: Box::new(addend),
                right: Box::new(product),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_scvtf(
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
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::IntToFloat,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_ucvtf(
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
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::UIntToFloat,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fcvtzs(
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
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::FloatToInt,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fcvtzu(
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
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::FloatToUInt,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fabs(
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
                op: SemanticOperationUnary::Abs,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_fneg(
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
                op: SemanticOperationUnary::Neg,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}
