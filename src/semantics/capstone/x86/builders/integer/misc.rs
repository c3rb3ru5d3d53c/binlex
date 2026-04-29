use super::*;

pub(super) fn ascii_adjust(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let al_reg = common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8);
    let ah_reg = common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8);
    let al = SemanticExpression::Read(Box::new(al_reg.clone()));
    let ah = SemanticExpression::Read(Box::new(ah_reg.clone()));

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_AAA as u32 || id == X86Insn::X86_INS_AAS as u32 => {
            let low_nibble = SemanticExpression::Extract {
                arg: Box::new(al.clone()),
                lsb: 0,
                bits: 4,
            };
            let decimal_adjust = common::or(
                common::compare(
                    SemanticOperationCompare::Ugt,
                    low_nibble,
                    SemanticExpression::Const { value: 9, bits: 4 },
                ),
                common::flag_expr("af"),
                1,
            );
            let adjusted_al = if id == X86Insn::X86_INS_AAA as u32 {
                common::add(al.clone(), common::const_u64(6, 8), 8)
            } else {
                common::sub(al.clone(), common::const_u64(6, 8), 8)
            };
            let adjusted_ah = if id == X86Insn::X86_INS_AAA as u32 {
                common::add(ah.clone(), common::const_u64(1, 8), 8)
            } else {
                common::sub(ah.clone(), common::const_u64(1, 8), 8)
            };
            let masked_al = common::and(adjusted_al, common::const_u64(0x0f, 8), 8);
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: al_reg,
                        expression: SemanticExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(masked_al),
                            when_false: Box::new(common::and(al, common::const_u64(0x0f, 8), 8)),
                            bits: 8,
                        },
                    },
                    SemanticEffect::Set {
                        dst: ah_reg,
                        expression: SemanticExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(adjusted_ah),
                            when_false: Box::new(ah),
                            bits: 8,
                        },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: decimal_adjust.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: decimal_adjust,
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        InsnId(id) if id == X86Insn::X86_INS_AAD as u32 => {
            let base = operands
                .first()
                .and_then(|operand| common::operand_expr(machine, operand))
                .unwrap_or_else(|| common::const_u64(10, 8));
            let ah_term = SemanticExpression::Binary {
                op: SemanticOperationBinary::Mul,
                left: Box::new(ah),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let result = common::add(ah_term, al, 8);
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8),
                        expression: result.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8),
                        expression: common::const_u64(0, 8),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            SemanticOperationCompare::Eq,
                            result.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(result.clone(), 7),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(result),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        InsnId(id) if id == X86Insn::X86_INS_AAM as u32 => {
            let base = operands
                .first()
                .and_then(|operand| common::operand_expr(machine, operand))
                .unwrap_or_else(|| common::const_u64(10, 8));
            let quotient = SemanticExpression::Binary {
                op: SemanticOperationBinary::UDiv,
                left: Box::new(al.clone()),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let remainder = SemanticExpression::Binary {
                op: SemanticOperationBinary::URem,
                left: Box::new(al),
                right: Box::new(base),
                bits: 8,
            };
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8),
                        expression: quotient,
                    },
                    SemanticEffect::Set {
                        dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8),
                        expression: remainder.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            SemanticOperationCompare::Eq,
                            remainder.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(remainder.clone(), 7),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(remainder),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        InsnId(id) if id == X86Insn::X86_INS_DAA as u32 => {
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Intrinsic {
                    name: "x86.daa".to_string(),
                    args: Vec::new(),
                    outputs: vec![
                        common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8),
                        common::flag("af"),
                        common::flag("cf"),
                        common::flag("of"),
                        common::flag("sf"),
                        common::flag("zf"),
                        common::flag("pf"),
                    ],
                }],
            ));
        }
        _ => {}
    }
    None
}

pub(super) fn crc32(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.crc32".to_string(),
            args: vec![src],
            outputs: vec![dst],
        }],
    ))
}

pub(super) fn xlat(machine: Architecture) -> Option<InstructionSemantics> {
    let pointer_bits = common::pointer_bits(machine);
    let base_reg = if matches!(machine, Architecture::AMD64) {
        X86Reg::X86_REG_RBX
    } else {
        X86Reg::X86_REG_EBX
    };
    let base = common::reg_expr(base_reg as u16, pointer_bits);
    let index = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(common::reg_expr(X86Reg::X86_REG_AL as u16, 8)),
        bits: pointer_bits,
    };
    let addr = common::add(base, index, pointer_bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AL as u16), 8),
            expression: SemanticExpression::Load {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: 8,
            },
        }],
    ))
}

pub(super) fn sign_extension(instruction: &Insn) -> Option<InstructionSemantics> {
    let (src_reg, src_bits, dst_reg, dst_bits, high_only) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_CBW as u32 => (
            X86Reg::X86_REG_AL as u16,
            8,
            X86Reg::X86_REG_AX as u16,
            16,
            false,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CWDE as u32 => (
            X86Reg::X86_REG_AX as u16,
            16,
            X86Reg::X86_REG_EAX as u16,
            32,
            false,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CDQE as u32 => (
            X86Reg::X86_REG_EAX as u16,
            32,
            X86Reg::X86_REG_RAX as u16,
            64,
            false,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CWD as u32 => (
            X86Reg::X86_REG_AX as u16,
            16,
            X86Reg::X86_REG_DX as u16,
            16,
            true,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CDQ as u32 => (
            X86Reg::X86_REG_EAX as u16,
            32,
            X86Reg::X86_REG_EDX as u16,
            32,
            true,
        ),
        InsnId(id) if id == X86Insn::X86_INS_CQO as u32 => (
            X86Reg::X86_REG_RAX as u16,
            64,
            X86Reg::X86_REG_RDX as u16,
            64,
            true,
        ),
        _ => return None,
    };

    let src = common::reg_expr(src_reg, src_bits);
    let expression = if high_only {
        SemanticExpression::Select {
            condition: Box::new(common::extract_bit(src, src_bits - 1)),
            when_true: Box::new(common::const_u64(u64::MAX, dst_bits)),
            when_false: Box::new(common::const_u64(0, dst_bits)),
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(src),
            bits: dst_bits,
        }
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(dst_reg), dst_bits),
            expression,
        }],
    ))
}
