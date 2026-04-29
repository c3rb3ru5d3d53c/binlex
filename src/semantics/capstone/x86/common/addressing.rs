use super::*;

pub fn memory_addr(
    machine: Architecture,
    base: Option<SemanticExpression>,
    index: Option<(SemanticExpression, i32)>,
    disp: i64,
) -> SemanticExpression {
    let bits = pointer_bits(machine);
    let mut result = base.unwrap_or_else(|| const_u64(0, bits));
    if let Some((index_expr, scale)) = index {
        let scaled = if scale > 1 {
            mul(index_expr, const_u64(scale as u64, bits), bits)
        } else {
            index_expr
        };
        result = add(result, scaled, bits);
    }
    if disp != 0 {
        let disp_expr = SemanticExpression::Const {
            value: disp as i128 as u128,
            bits,
        };
        result = add(result, disp_expr, bits);
    }
    result
}

pub fn operand_expr(machine: Architecture, operand: &ArchOperand) -> Option<SemanticExpression> {
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    let bits = bits_from_operand_size(op.size, machine);
    match op.op_type {
        X86OperandType::Reg(reg_id) => Some(reg_expr(reg_id.0, bits)),
        X86OperandType::Imm(imm) => Some(SemanticExpression::Const {
            value: imm as i128 as u128,
            bits,
        }),
        X86OperandType::Mem(mem) => {
            let base = if mem.base().0 == 0 {
                None
            } else {
                Some(reg_expr(mem.base().0, pointer_bits(machine)))
            };
            let index = if mem.index().0 == 0 {
                None
            } else {
                Some((reg_expr(mem.index().0, pointer_bits(machine)), mem.scale()))
            };
            let addr = memory_addr(machine, base, index, mem.disp());
            Some(SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits,
            })
        }
        _ => None,
    }
}

pub fn operand_location(machine: Architecture, operand: &ArchOperand) -> Option<SemanticLocation> {
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    let bits = bits_from_operand_size(op.size, machine);
    match op.op_type {
        X86OperandType::Reg(reg_id) => Some(reg(reg_id_name(reg_id.0), bits)),
        X86OperandType::Mem(mem) => {
            let base = if mem.base().0 == 0 {
                None
            } else {
                Some(reg_expr(mem.base().0, pointer_bits(machine)))
            };
            let index = if mem.index().0 == 0 {
                None
            } else {
                Some((reg_expr(mem.index().0, pointer_bits(machine)), mem.scale()))
            };
            let addr = memory_addr(machine, base, index, mem.disp());
            Some(SemanticLocation::Memory {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits,
            })
        }
        _ => None,
    }
}
