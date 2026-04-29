use super::*;

pub(in crate::semantics::capstone::arm64) fn memory_address(
    operand: &ArchOperand,
) -> Option<SemanticExpression> {
    let ArchOperand::Arm64Operand(op) = operand else {
        return None;
    };
    let Arm64OperandType::Mem(mem) = op.op_type else {
        return None;
    };

    let mut address = if mem.base() != RegId(Arm64Reg::ARM64_REG_INVALID as u16) {
        Some(reg_expr(mem.base(), register_bits(mem.base())))
    } else {
        None
    };

    if mem.index() != RegId(Arm64Reg::ARM64_REG_INVALID as u16) {
        let index = reg_expr(mem.index(), register_bits(mem.index()));
        address = Some(match address {
            Some(base) => binary(SemanticOperationBinary::Add, base, index, 64),
            None => index,
        });
    }

    let address = address.unwrap_or_else(|| const_u64(0, 64));
    if mem.disp() == 0 {
        Some(address)
    } else {
        Some(binary(
            SemanticOperationBinary::Add,
            address,
            const_u64(mem.disp() as i64 as u64, 64),
            64,
        ))
    }
}

pub(in crate::semantics::capstone::arm64) fn base_register_expression(
    operand: &ArchOperand,
) -> Option<SemanticExpression> {
    let ArchOperand::Arm64Operand(op) = operand else {
        return None;
    };
    let Arm64OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    Some(reg_expr(mem.base(), register_bits(mem.base())))
}

pub(in crate::semantics::capstone::arm64) fn effective_memory_address(
    instruction: &Insn,
    mem_operand: &ArchOperand,
    writeback_operand: Option<&ArchOperand>,
) -> Option<SemanticExpression> {
    if is_post_indexed(instruction, writeback_operand) {
        return base_register_expression(mem_operand);
    }
    memory_address(mem_operand)
}

pub(in crate::semantics::capstone::arm64) fn effective_base_plus_immediate(
    base_operand: &ArchOperand,
    displacement_operand: Option<&ArchOperand>,
) -> Option<SemanticExpression> {
    let base = operand_expression(base_operand)?;
    let displacement = displacement_operand.and_then(operand_immediate).unwrap_or(0);
    if displacement == 0 {
        Some(base)
    } else {
        Some(binary(
            SemanticOperationBinary::Add,
            base,
            const_u64(displacement, 64),
            64,
        ))
    }
}

pub(in crate::semantics::capstone::arm64) fn base_immediate_load_address(
    base_operand: &ArchOperand,
    displacement_operand: Option<&ArchOperand>,
) -> Option<SemanticExpression> {
    memory_address(base_operand)
        .or_else(|| effective_base_plus_immediate(base_operand, displacement_operand))
}

pub(in crate::semantics::capstone::arm64) fn writeback_effect(
    instruction: &Insn,
    mem_operand: &ArchOperand,
    writeback_operand: Option<&ArchOperand>,
) -> Option<SemanticEffect> {
    let ArchOperand::Arm64Operand(op) = mem_operand else {
        return None;
    };
    let Arm64OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    if !instruction
        .op_str()
        .is_some_and(|op_str| op_str.contains("],") || op_str.contains("]!"))
        && writeback_operand.and_then(operand_immediate).is_none()
    {
        return None;
    }
    let delta = writeback_operand
        .and_then(operand_immediate)
        .unwrap_or(mem.disp() as i64 as u64);
    if delta == 0 {
        return None;
    }
    let base = reg_location(mem.base(), register_bits(mem.base()));
    Some(SemanticEffect::Set {
        dst: base.clone(),
        expression: binary(
            SemanticOperationBinary::Add,
            SemanticExpression::Read(Box::new(base)),
            const_u64(delta, 64),
            64,
        ),
    })
}

pub(in crate::semantics::capstone::arm64) fn is_post_indexed(
    instruction: &Insn,
    writeback_operand: Option<&ArchOperand>,
) -> bool {
    writeback_operand.is_some()
        || instruction.op_str().is_some_and(|op_str| op_str.contains("],"))
}
