use super::*;

#[derive(Clone, Copy)]
pub(in crate::semantics::capstone::arm64) enum LoadKind {
    FullWidth,
    ZeroExtend(u16),
}

pub(in crate::semantics::capstone::arm64) fn build_load_pair(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let first_dst = operand_location(machine, operands.first()?)?;
    let second_dst = operand_location(machine, operands.get(1)?)?;
    let base_addr = effective_memory_address(instruction, operands.get(2)?, operands.get(3))?;
    let stride = (first_dst.bits() / 8) as u64;
    let second_addr = binary(
        SemanticOperationBinary::Add,
        base_addr.clone(),
        const_u64(stride, 64),
        64,
    );

    let mut effects = vec![
        SemanticEffect::Set {
            dst: first_dst.clone(),
            expression: SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(base_addr),
                bits: first_dst.bits(),
            },
        },
        SemanticEffect::Set {
            dst: second_dst.clone(),
            expression: SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(second_addr),
                bits: second_dst.bits(),
            },
        },
    ];

    if let Some(writeback) = writeback_effect(instruction, operands.get(2)?, operands.get(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(in crate::semantics::capstone::arm64) fn build_store_pair(
    _machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let first_src = operand_expression(operands.first()?)?;
    let second_src = operand_expression(operands.get(1)?)?;
    let base_addr = effective_memory_address(instruction, operands.get(2)?, operands.get(3))?;
    let stride = (first_src.bits() / 8) as u64;
    let second_addr = binary(
        SemanticOperationBinary::Add,
        base_addr.clone(),
        const_u64(stride, 64),
        64,
    );

    let mut effects = vec![
        SemanticEffect::Store {
            space: SemanticAddressSpace::Default,
            addr: base_addr,
            expression: first_src.clone(),
            bits: first_src.bits(),
        },
        SemanticEffect::Store {
            space: SemanticAddressSpace::Default,
            addr: second_addr,
            expression: second_src.clone(),
            bits: second_src.bits(),
        },
    ];

    if let Some(writeback) = writeback_effect(instruction, operands.get(2)?, operands.get(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(in crate::semantics::capstone::arm64) fn build_load_pair_signed_word(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let first_dst = operand_location(machine, operands.first()?)?;
    let second_dst = operand_location(machine, operands.get(1)?)?;
    let base_addr = effective_memory_address(instruction, operands.get(2)?, operands.get(3))?;
    let second_addr = binary(
        SemanticOperationBinary::Add,
        base_addr.clone(),
        const_u64(4, 64),
        64,
    );

    let mut effects = vec![
        SemanticEffect::Set {
            dst: first_dst.clone(),
            expression: sign_extend_load(base_addr, 32, first_dst.bits()),
        },
        SemanticEffect::Set {
            dst: second_dst.clone(),
            expression: sign_extend_load(second_addr, 32, second_dst.bits()),
        },
    ];

    if let Some(writeback) = writeback_effect(instruction, operands.get(2)?, operands.get(3)) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(in crate::semantics::capstone::arm64) fn build_plain_load_base_immediate(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: dst.bits(),
            },
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_zero_extend_load(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    load_bits: u16,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: zero_extend_load(addr, load_bits, dst.bits()),
    }];
    if let Some(writeback) = writeback_effect(instruction, operands.get(1)?, operands.get(2)) {
        effects.push(writeback);
    }
    Some(complete(SemanticTerminator::FallThrough, effects))
}

pub(in crate::semantics::capstone::arm64) fn build_zero_extend_load_base_immediate(
    machine: Architecture,
    operands: &[ArchOperand],
    load_bits: u16,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: zero_extend_load(addr, load_bits, dst.bits()),
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_sign_extend_load_base_immediate(
    machine: Architecture,
    operands: &[ArchOperand],
    load_bits: u16,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: dst.clone(),
            expression: sign_extend_load(addr, load_bits, dst.bits()),
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_exclusive_load(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    kind: LoadKind,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
    let expression = match kind {
        LoadKind::FullWidth => SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(addr.clone()),
            bits: dst.bits(),
        },
        LoadKind::ZeroExtend(load_bits) => zero_extend_load(addr.clone(), load_bits, dst.bits()),
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set { dst, expression },
            SemanticEffect::Intrinsic {
                name: format!(
                    "arm64.{}.monitor",
                    instruction.mnemonic().unwrap_or("exclusive_load")
                ),
                args: vec![addr],
                outputs: Vec::new(),
            },
        ],
    ))
}

pub(in crate::semantics::capstone::arm64) fn build_ldr(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = match operands.get(1) {
        Some(operand) if memory_address(operand).is_some() => {
            effective_memory_address(instruction, operand, operands.get(2))?
        }
        Some(operand) => operand_expression(operand)?,
        None => return None,
    };

    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: SemanticExpression::Load {
            space: SemanticAddressSpace::Default,
            addr: Box::new(addr),
            bits: dst.bits(),
        },
    }];

    if let Some(mem_operand) = operands.get(1) {
        if memory_address(mem_operand).is_some() {
            if let Some(writeback) = writeback_effect(instruction, mem_operand, operands.get(2)) {
                effects.push(writeback);
            }
        }
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}
