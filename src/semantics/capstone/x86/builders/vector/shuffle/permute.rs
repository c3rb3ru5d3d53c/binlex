use super::*;

pub(in crate::semantics::capstone::x86::builders::vector) fn shuffle(
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
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSHUFD as u32 => {
            shuffle_dwords(bits, &src, imm as u8)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFHW as u32 => {
            shuffle_words_half(bits, &src, imm as u8, true)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFLW as u32 => {
            shuffle_words_half(bits, &src, imm as u8, false)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFW as u32 => shuffle_words(bits, &src, imm as u8)?,
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn avx_shuffle(
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
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPSHUFD as u32 => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shuffle_dwords(128, &extract_range(&src, 128, 128), imm as u8)?,
                        shuffle_dwords(128, &extract_range(&src, 0, 128), imm as u8)?,
                    ],
                    bits,
                }
            } else {
                shuffle_dwords(bits, &src, imm as u8)?
            }
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn pshufb(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let mask = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if bits != 128 {
        return None;
    }
    let mut parts = Vec::with_capacity(16);
    for lane in (0..16).rev() {
        let control = extract_lane(&mask, 8, lane);
        let zero = common::extract_bit(control.clone(), 7);
        let index = SemanticExpression::Extract {
            arg: Box::new(control),
            lsb: 0,
            bits: 4,
        };
        let mut selected = extract_lane(&src, 8, 0);
        for source_lane in 1..16 {
            selected = SemanticExpression::Select {
                condition: Box::new(common::compare(
                    SemanticOperationCompare::Eq,
                    index.clone(),
                    SemanticExpression::Const {
                        value: source_lane as u128,
                        bits: 4,
                    },
                )),
                when_true: Box::new(extract_lane(&src, 8, source_lane)),
                when_false: Box::new(selected),
                bits: 8,
            };
        }
        parts.push(SemanticExpression::Select {
            condition: Box::new(zero),
            when_true: Box::new(common::const_u64(0, 8)),
            when_false: Box::new(selected),
            bits: 8,
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

pub(in crate::semantics::capstone::x86::builders::vector) fn vperm2i128(
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
    let control = operands.get(3)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let select_half = |select: u8| match select & 0x3 {
        0 => extract_range(&left, 0, 128),
        1 => extract_range(&left, 128, 128),
        2 => extract_range(&right, 0, 128),
        _ => extract_range(&right, 128, 128),
    };
    let low = if (imm as u8 & 0x08) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half(imm as u8)
    };
    let high = if (imm as u8 & 0x80) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half((imm as u8 >> 4) & 0x3)
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![high, low],
                bits: 256,
            },
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn vpermq(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let mut parts = Vec::with_capacity(4);
    for lane in (0..4).rev() {
        let select = ((imm as u8 >> (lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(&src, 64, select));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits: 256 },
        }],
    ))
}
