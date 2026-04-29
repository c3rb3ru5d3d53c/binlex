use super::*;

pub(in crate::semantics::capstone::x86::builders::vector) fn movemask(
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
    let src_bits = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))
        .map(|location| common::location_bits(&location))?;
    let dst_bits = common::location_bits(&dst);
    let (lane_bits, lane_count) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPS as u32 => (32, 4),
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPD as u32 => (64, 2),
        InsnId(id) if id == X86Insn::X86_INS_PMOVMSKB as u32 => (8, 16),
        InsnId(id) if id == X86Insn::X86_INS_VPMOVMSKB as u32 => (8, src_bits / 8),
        _ => return None,
    };
    let mut value = common::const_u64(0, dst_bits);
    for lane in 0..lane_count {
        let bit = SemanticExpression::Extract {
            arg: Box::new(src.clone()),
            lsb: lane * lane_bits + (lane_bits - 1),
            bits: 1,
        };
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(bit),
                bits: dst_bits,
            }),
            right: Box::new(common::const_u64(lane as u64, dst_bits)),
            bits: dst_bits,
        };
        value = common::or(value, shifted, dst_bits);
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: value,
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn maskmovq(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mask = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let data = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let _ = machine;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.maskmovq".to_string(),
            args: vec![mask, data],
            outputs: vec![],
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn vpbroadcastb(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane = extract_range(&src, 0, 8);
    let parts = vec![lane; (bits / 8) as usize];
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn vpsignw(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let mut parts = Vec::with_capacity((bits / 16) as usize);
    for lane in (0..(bits / 16)).rev() {
        let value = extract_lane(&left, 16, lane);
        let control = extract_lane(&right, 16, lane);
        let is_zero = common::compare(
            SemanticOperationCompare::Eq,
            control.clone(),
            common::const_u64(0, 16),
        );
        let is_negative = common::extract_bit(control, 15);
        parts.push(SemanticExpression::Select {
            condition: Box::new(is_zero),
            when_true: Box::new(common::const_u64(0, 16)),
            when_false: Box::new(SemanticExpression::Select {
                condition: Box::new(is_negative),
                when_true: Box::new(SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(value.clone()),
                    bits: 16,
                }),
                when_false: Box::new(value),
                bits: 16,
            }),
            bits: 16,
        });
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn vmaskmov(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    if is_memory_operand(operands.first()?) {
        let mask = operands
            .get(1)
            .and_then(|operand| common::operand_expr(machine, operand))?;
        let data = operands
            .get(2)
            .and_then(|operand| common::operand_expr(machine, operand))?;
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: format!("x86.{mnemonic}"),
                args: vec![mask, data],
                outputs: vec![dst],
            }],
        ));
    }
    let mask = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let src = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Intrinsic {
                name: format!("x86.{mnemonic}"),
                args: vec![mask, src],
                bits,
            },
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn vzeroupper() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.vzeroupper".to_string(),
            args: Vec::new(),
            outputs: Vec::new(),
        }],
    )
}
