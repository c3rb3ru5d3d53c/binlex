// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::*;

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

#[derive(Clone, Copy)]
pub(in crate::semantics::capstone::arm64) enum LoadKind {
    FullWidth,
    ZeroExtend(u16),
}

pub(in crate::semantics::capstone::arm64) fn build_effect_intrinsic(
    _instruction: &Insn,
    operands: &[ArchOperand],
    outputs: Vec<SemanticLocation>,
    name: String,
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name,
            args,
            outputs,
        }],
    ))
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

pub(in crate::semantics::capstone::arm64) fn operand_immediate(operand: &ArchOperand) -> Option<u64> {
    match operand {
        ArchOperand::Arm64Operand(op) => match op.op_type {
            Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => Some(imm as u64),
            _ => None,
        },
        _ => None,
    }
}

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
