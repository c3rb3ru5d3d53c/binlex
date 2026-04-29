use super::*;

pub(super) fn movsd(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let expression = if dst_bits > 64 {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
            })?;
        let lower = SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: 64,
        };
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: dst_bits,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn vmovsd(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    if operands.len() == 2 {
        return movsd(machine, operands);
    }
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let upper_src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let low_src = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let expression = if dst_bits > 64 {
        SemanticExpression::Concat {
            parts: vec![
                SemanticExpression::Extract {
                    arg: Box::new(upper_src),
                    lsb: 64,
                    bits: dst_bits - 64,
                },
                SemanticExpression::Extract {
                    arg: Box::new(low_src),
                    lsb: 0,
                    bits: 64,
                },
            ],
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Extract {
            arg: Box::new(low_src),
            lsb: 0,
            bits: dst_bits,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn compare_fp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let (left, right) = match instruction.id() {
        InsnId(id)
            if [X86Insn::X86_INS_COMISS as u32, X86Insn::X86_INS_UCOMISS as u32].contains(&id) =>
        {
            (low_32(left), low_32(right))
        }
        _ => (low_64(left), low_64(right)),
    };
    let unordered = common::compare(
        SemanticOperationCompare::Unordered,
        left.clone(),
        right.clone(),
    );
    let equal = common::compare(SemanticOperationCompare::Oeq, left.clone(), right.clone());
    let less = common::compare(SemanticOperationCompare::Olt, left.clone(), right.clone());
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::or(equal, unordered.clone(), 1),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: unordered.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::or(less, unordered, 1),
            },
        ],
    ))
}

pub(super) fn pcmpistri(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.pcmpistri".to_string(),
            args,
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
                common::flag("cf"),
                common::flag("of"),
                common::flag("sf"),
                common::flag("zf"),
                common::flag("af"),
                common::flag("pf"),
            ],
        }],
    ))
}

pub(super) fn scalar_convert(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_CVTTSD2SI as u32 => SemanticExpression::Cast {
            op: SemanticOperationCast::FloatToInt,
            arg: Box::new(low_64(src)),
            bits,
        },
        _ => common::operation_intrinsic(instruction, bits, vec![src]),
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn packed_convert(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_CVTDQ2PD as u32 => {
            let lane0 = SemanticExpression::Cast {
                op: SemanticOperationCast::IntToFloat,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src.clone()),
                    lsb: 0,
                    bits: 32,
                }),
                bits: 64,
            };
            let lane1 = SemanticExpression::Cast {
                op: SemanticOperationCast::IntToFloat,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb: 32,
                    bits: 32,
                }),
                bits: 64,
            };
            SemanticExpression::Concat {
                parts: vec![lane1, lane0],
                bits: 128,
            }
        }
        _ => common::operation_intrinsic(instruction, dst_bits, vec![src]),
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn scalar_fp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    let dst_bits = common::location_bits(&dst);
    let lower = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_ADDSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FAdd,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_SUBSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FSub,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_MULSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FMul,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_DIVSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FDiv,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_SQRTSD as u32 => {
            common::operation_intrinsic(instruction, 64, vec![low_64(args.get(1)?.clone())])
        }
        InsnId(id) if id == X86Insn::X86_INS_MINSD as u32 => {
            let left = low_64(args.first()?.clone());
            let right = low_64(args.get(1)?.clone());
            let unordered = common::compare(
                SemanticOperationCompare::Unordered,
                left.clone(),
                right.clone(),
            );
            let left_is_min =
                common::compare(SemanticOperationCompare::Olt, left.clone(), right.clone());
            SemanticExpression::Select {
                condition: Box::new(unordered),
                when_true: Box::new(right.clone()),
                when_false: Box::new(SemanticExpression::Select {
                    condition: Box::new(left_is_min),
                    when_true: Box::new(left),
                    when_false: Box::new(right),
                    bits: 64,
                }),
                bits: 64,
            }
        }
        InsnId(id) if id == X86Insn::X86_INS_MAXSD as u32 => {
            common::operation_intrinsic(
                instruction,
                64,
                vec![low_64(args.first()?.clone()), low_64(args.get(1)?.clone())],
            )
        }
        _ => return None,
    };
    let expression = if dst_bits > 64 {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
            })?;
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        lower
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn packed_fp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::operation_intrinsic(instruction, dst_bits, args),
        }],
    ))
}

pub(super) fn scalar_ss(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    let lower = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_ADDSS as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FAdd,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        InsnId(id) if id == X86Insn::X86_INS_SUBSS as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FSub,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        InsnId(id) if id == X86Insn::X86_INS_MULSS as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FMul,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        InsnId(id) if id == X86Insn::X86_INS_DIVSS as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FDiv,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        _ => common::operation_intrinsic(instruction, 32, args),
    };
    let expression = if dst_bits > 32 {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 32,
                bits: dst_bits - 32,
            })?;
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        lower
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn scalar_vfma(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let src1 = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let src2 = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let src3 = operands
        .get(3)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let lower = common::operation_intrinsic(
        instruction,
        64,
        vec![low_64(src1.clone()), low_64(src2), low_64(src3)],
    );
    let expression = if dst_bits > 64 {
        let preserved = SemanticExpression::Extract {
            arg: Box::new(src1),
            lsb: 64,
            bits: dst_bits - 64,
        };
        SemanticExpression::Concat {
            parts: vec![preserved, lower],
            bits: dst_bits,
        }
    } else {
        lower
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}
