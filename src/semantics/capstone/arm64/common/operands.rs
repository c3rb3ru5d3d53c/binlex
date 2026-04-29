use super::*;

pub(in crate::semantics::capstone::arm64) fn operand_expression(
    operand: &ArchOperand,
) -> Option<SemanticExpression> {
    match operand {
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Reg(reg) => Some(reg_expr(reg, register_bits(reg))),
            Arm64OperandType::Imm(imm) => Some(const_u64(imm as u64, 64)),
            Arm64OperandType::Mem(_) => Some(SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(memory_address(operand)?),
                bits: 64,
            }),
            _ => None,
        },
        _ => None,
    }
}

pub(in crate::semantics::capstone::arm64) fn operand_location(
    machine: Architecture,
    operand: &ArchOperand,
) -> Option<SemanticLocation> {
    match operand {
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Reg(reg_id) => Some(reg_location(reg_id, register_bits(reg_id))),
            Arm64OperandType::Mem(_) => Some(SemanticLocation::Memory {
                space: SemanticAddressSpace::Default,
                addr: Box::new(memory_address(operand)?),
                bits: pointer_bits(machine),
            }),
            _ => None,
        },
        _ => None,
    }
}

pub(in crate::semantics::capstone::arm64) fn operand_immediate(
    operand: &ArchOperand,
) -> Option<u64> {
    match operand {
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => Some(imm as u64),
            _ => None,
        },
        _ => None,
    }
}
