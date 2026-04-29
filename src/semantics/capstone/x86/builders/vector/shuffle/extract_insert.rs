use super::*;

pub(in crate::semantics::capstone::x86::builders::vector) fn packed_extract(
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
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PEXTRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRQ as u32 => 64,
        InsnId(id) if id == X86Insn::X86_INS_EXTRACTPS as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRQ as u32 => 64,
        _ => return None,
    };
    let lane = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(lane),
        right: Box::new(common::const_u64(lane_bits as u64, dst_bits)),
        bits: dst_bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Binary {
                        op: SemanticOperationBinary::LShr,
                        left: Box::new(src),
                        right: Box::new(shift_bits),
                        bits: 128,
                    }),
                    lsb: 0,
                    bits: lane_bits,
                }),
                bits: dst_bits,
            },
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn packed_insert(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src_vec = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let inserted = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let lane = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PINSRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PINSRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PINSRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_PINSRQ as u32 => 64,
        InsnId(id) if id == X86Insn::X86_INS_VPINSRW as u32 => 16,
        _ => return None,
    };
    let shift = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(lane),
        right: Box::new(common::const_u64(lane_bits as u64, bits)),
        bits,
    };
    let cleared = common::and(
        src_vec,
        common::not(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::Shl,
                left: Box::new(SemanticExpression::Const {
                    value: lane_mask(lane_bits),
                    bits,
                }),
                right: Box::new(shift.clone()),
                bits,
            },
            bits,
        ),
        bits,
    );
    let inserted_value = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(SemanticExpression::Cast {
            op: crate::semantics::SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(inserted),
                lsb: 0,
                bits: lane_bits,
            }),
            bits,
        }),
        right: Box::new(shift),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::or(cleared, inserted_value, bits),
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn vextracti128(
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
    let lane = (imm as u8 & 0x1) as u16;
    let extracted = extract_range(&src, lane * 128, 128);
    let dst_bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: if dst_bits == 128 {
                extracted
            } else {
                truncate_to_bits(extracted, dst_bits)
            },
        }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn vinsertf128(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let base = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let inserted = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(3)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let lower = extract_range(&base, 0, 128);
    let upper = extract_range(&base, 128, 128);
    let expression = if (imm as u8 & 0x1) == 0 {
        SemanticExpression::Concat {
            parts: vec![upper, extract_range(&inserted, 0, 128)],
            bits: 256,
        }
    } else {
        SemanticExpression::Concat {
            parts: vec![extract_range(&inserted, 0, 128), lower],
            bits: 256,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}
