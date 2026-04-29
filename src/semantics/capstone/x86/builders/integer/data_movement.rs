use super::*;

pub(super) fn lock_cmpxchg8b(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let addr = match dst {
        crate::semantics::SemanticLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    let eax = common::reg_expr(X86Reg::X86_REG_EAX as u16, 32);
    let edx = common::reg_expr(X86Reg::X86_REG_EDX as u16, 32);
    let ebx = common::reg_expr(X86Reg::X86_REG_EBX as u16, 32);
    let ecx = common::reg_expr(X86Reg::X86_REG_ECX as u16, 32);
    let accumulator = SemanticExpression::Concat {
        parts: vec![edx.clone(), eax.clone()],
        bits: 64,
    };
    let replacement = SemanticExpression::Concat {
        parts: vec![ecx, ebx],
        bits: 64,
    };
    let observed_tmp = crate::semantics::SemanticLocation::Temporary { id: 0, bits: 64 };
    let observed_expr = SemanticExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 32,
    };
    let observed_high = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 32,
        bits: 32,
    };
    Some(InstructionSemantics {
        version: 1,
        status: crate::semantics::SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: vec![SemanticTemporary {
            id: 0,
            bits: 64,
            name: Some("lock_cmpxchg8b_observed".to_string()),
        }],
        effects: vec![
            SemanticEffect::AtomicCmpXchg {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr,
                expected: accumulator.clone(),
                desired: replacement,
                bits: 64,
                observed: observed_tmp,
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(eax),
                    when_false: Box::new(observed_low),
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(edx),
                    when_false: Box::new(observed_high),
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

pub(super) fn lock_cmpxchg16b(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let addr = match dst {
        crate::semantics::SemanticLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    let rax = common::reg_expr(X86Reg::X86_REG_RAX as u16, 64);
    let rdx = common::reg_expr(X86Reg::X86_REG_RDX as u16, 64);
    let rbx = common::reg_expr(X86Reg::X86_REG_RBX as u16, 64);
    let rcx = common::reg_expr(X86Reg::X86_REG_RCX as u16, 64);
    let accumulator = SemanticExpression::Concat {
        parts: vec![rdx.clone(), rax.clone()],
        bits: 128,
    };
    let replacement = SemanticExpression::Concat {
        parts: vec![rcx, rbx],
        bits: 128,
    };
    let observed_tmp = crate::semantics::SemanticLocation::Temporary { id: 1, bits: 128 };
    let observed_expr = SemanticExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 64,
    };
    let observed_high = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 64,
        bits: 64,
    };
    Some(InstructionSemantics {
        version: 1,
        status: crate::semantics::SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: vec![SemanticTemporary {
            id: 1,
            bits: 128,
            name: Some("lock_cmpxchg16b_observed".to_string()),
        }],
        effects: vec![
            SemanticEffect::AtomicCmpXchg {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr,
                expected: accumulator.clone(),
                desired: replacement,
                bits: 128,
                observed: observed_tmp,
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_RAX as u16), 64),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rax),
                    when_false: Box::new(observed_low),
                    bits: 64,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_RDX as u16), 64),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rdx),
                    when_false: Box::new(observed_high),
                    bits: 64,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

pub(super) fn assign(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let expression = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn movbe(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let expression = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if !matches!(bits, 16 | 32 | 64) {
        return None;
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::ByteSwap,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

pub(super) fn exchange(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let left_dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let right_dst = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left_expr = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right_expr = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: left_dst,
                expression: right_expr,
            },
            SemanticEffect::Set {
                dst: right_dst,
                expression: left_expr,
            },
        ],
    ))
}

pub(super) fn exchange_add(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src_dst = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_expr = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let src_expr = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let result = common::add(dst_expr.clone(), src_expr.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: src_dst,
                expression: dst_expr.clone(),
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
                expression: common::compare(
                    SemanticOperationCompare::Ult,
                    result.clone(),
                    dst_expr.clone(),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    dst_expr.clone(),
                    src_expr.clone(),
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
                expression: common::auxiliary_flag(dst_expr, src_expr, result, bits),
            },
        ],
    ))
}

pub(super) fn compare_exchange(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let observed = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let accumulator_reg = match bits {
        8 => X86Reg::X86_REG_AL as u16,
        16 => X86Reg::X86_REG_AX as u16,
        32 => X86Reg::X86_REG_EAX as u16,
        64 => X86Reg::X86_REG_RAX as u16,
        _ => return None,
    };
    let accumulator_location = common::reg(common::reg_id_name(accumulator_reg), bits);
    let accumulator = common::reg_expr(accumulator_reg, bits);
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed.clone(),
    );
    let diff = common::sub(accumulator.clone(), observed.clone(), bits);
    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: SemanticExpression::Select {
            condition: Box::new(equal.clone()),
            when_true: Box::new(src),
            when_false: Box::new(observed.clone()),
            bits,
        },
    }];
    if dst != accumulator_location {
        effects.push(SemanticEffect::Set {
            dst: accumulator_location,
            expression: SemanticExpression::Select {
                condition: Box::new(equal.clone()),
                when_true: Box::new(accumulator.clone()),
                when_false: Box::new(observed.clone()),
                bits,
            },
        });
    }
    effects.extend([
        SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: equal.clone(),
        },
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: common::compare(
                SemanticOperationCompare::Ult,
                accumulator.clone(),
                observed.clone(),
            ),
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: common::extract_bit(diff.clone(), bits.saturating_sub(1)),
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: common::sub_overflow(
                accumulator.clone(),
                observed.clone(),
                diff.clone(),
                bits,
            ),
        },
        SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(diff.clone()),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: common::auxiliary_flag(accumulator, observed, diff, bits),
        },
    ]);
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn movx(
    machine: Architecture,
    operands: &[ArchOperand],
    sign_extend: bool,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst_bits = match &dst {
        crate::semantics::SemanticLocation::Register { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        crate::semantics::SemanticLocation::Flag { bits, .. } => *bits,
        crate::semantics::SemanticLocation::ProgramCounter { bits } => *bits,
        crate::semantics::SemanticLocation::Temporary { bits, .. } => *bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: if sign_extend {
                    SemanticOperationCast::SignExtend
                } else {
                    SemanticOperationCast::ZeroExtend
                },
                arg: Box::new(src),
                bits: dst_bits,
            },
        }],
    ))
}

pub(super) fn lea(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands.get(1)?;
    let capstone::arch::ArchOperand::X86Operand(op) = src else {
        return None;
    };
    let capstone::arch::x86::X86OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    let base = if mem.base().0 == 0 {
        None
    } else {
        Some(common::reg_expr(
            mem.base().0,
            common::pointer_bits(machine),
        ))
    };
    let index = if mem.index().0 == 0 {
        None
    } else {
        Some((
            common::reg_expr(mem.index().0, common::pointer_bits(machine)),
            mem.scale(),
        ))
    };
    let addr = common::memory_addr(machine, base, index, mem.disp());
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: addr,
        }],
    ))
}
