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

extern crate capstone;

use crate::Architecture;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticTemporary, SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86Insn;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg;

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PUSH as u32 => push(machine, instruction, operands),
        InsnId(id) if id == X86Insn::X86_INS_POP as u32 => pop(machine, instruction, operands),
        InsnId(id) if id == X86Insn::X86_INS_PUSHAL as u32 => pushal(machine),
        InsnId(id) if id == X86Insn::X86_INS_POPAL as u32 => popal(machine),
        InsnId(id) if id == X86Insn::X86_INS_LEAVE as u32 => leave(machine, instruction),
        InsnId(id) if id == X86Insn::X86_INS_ENTER as u32 => enter(machine, instruction, operands),
        _ => None,
    }
}

fn pushal(machine: Architecture) -> Option<InstructionSemantics> {
    if !matches!(machine, Architecture::I386) {
        return None;
    }
    let sp = stack_pointer_location(machine);
    let old_sp = SemanticExpression::Read(Box::new(sp.clone()));
    let esp = common::reg_expr(X86Reg::X86_REG_ESP as u16, 32);
    let regs = [
        common::reg_expr(X86Reg::X86_REG_EAX as u16, 32),
        common::reg_expr(X86Reg::X86_REG_ECX as u16, 32),
        common::reg_expr(X86Reg::X86_REG_EDX as u16, 32),
        common::reg_expr(X86Reg::X86_REG_EBX as u16, 32),
        esp,
        common::reg_expr(X86Reg::X86_REG_EBP as u16, 32),
        common::reg_expr(X86Reg::X86_REG_ESI as u16, 32),
        common::reg_expr(X86Reg::X86_REG_EDI as u16, 32),
    ];
    let mut effects = Vec::new();
    for (index, reg) in regs.into_iter().enumerate() {
        effects.push(SemanticEffect::Store {
            space: SemanticAddressSpace::Stack,
            addr: common::sub(
                old_sp.clone(),
                common::const_u64(((index + 1) * 4) as u64, 32),
                32,
            ),
            expression: reg,
            bits: 32,
        });
    }
    effects.push(SemanticEffect::Set {
        dst: sp,
        expression: common::sub(old_sp, common::const_u64(32, 32), 32),
    });
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn popal(machine: Architecture) -> Option<InstructionSemantics> {
    if !matches!(machine, Architecture::I386) {
        return None;
    }
    let sp = stack_pointer_location(machine);
    let old_sp = SemanticExpression::Read(Box::new(sp.clone()));
    let loads = |offset: u64| SemanticExpression::Load {
        space: SemanticAddressSpace::Stack,
        addr: Box::new(common::add(
            old_sp.clone(),
            common::const_u64(offset, 32),
            32,
        )),
        bits: 32,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EDI as u16), 32),
                expression: loads(0),
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_ESI as u16), 32),
                expression: loads(4),
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EBP as u16), 32),
                expression: loads(8),
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EBX as u16), 32),
                expression: loads(16),
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
                expression: loads(20),
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
                expression: loads(24),
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                expression: loads(28),
            },
            SemanticEffect::Set {
                dst: sp,
                expression: common::add(old_sp, common::const_u64(32, 32), 32),
            },
        ],
    ))
}

fn enter(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let Some(ArchOperand::X86Operand(size_op)) = operands.first() else {
        return None;
    };
    let Some(ArchOperand::X86Operand(level_op)) = operands.get(1) else {
        return None;
    };
    let X86OperandType::Imm(frame_size) = size_op.op_type else {
        return None;
    };
    let X86OperandType::Imm(nesting_level) = level_op.op_type else {
        return None;
    };

    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let stack_pointer = stack_pointer_location(machine);
    let base_pointer = base_pointer_location(machine);
    let old_sp = SemanticExpression::Read(Box::new(stack_pointer.clone()));
    let pushed_sp = common::sub(
        old_sp.clone(),
        common::const_u64(slot_bytes, pointer_bits),
        pointer_bits,
    );
    let old_bp = SemanticExpression::Read(Box::new(base_pointer.clone()));
    let mut effects = vec![SemanticEffect::Store {
        space: SemanticAddressSpace::Stack,
        addr: pushed_sp.clone(),
        expression: old_bp.clone(),
        bits: pointer_bits,
    }];

    let mut current_sp = pushed_sp.clone();
    if nesting_level != 0 {
        for level in 1..nesting_level {
            let display_entry = common::sub(
                old_bp.clone(),
                common::const_u64(level as u64 * slot_bytes, pointer_bits),
                pointer_bits,
            );
            current_sp = common::sub(
                current_sp,
                common::const_u64(slot_bytes, pointer_bits),
                pointer_bits,
            );
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Stack,
                addr: current_sp.clone(),
                expression: display_entry,
                bits: pointer_bits,
            });
        }
        current_sp = common::sub(
            current_sp,
            common::const_u64(slot_bytes, pointer_bits),
            pointer_bits,
        );
        effects.push(SemanticEffect::Store {
            space: SemanticAddressSpace::Stack,
            addr: current_sp.clone(),
            expression: pushed_sp.clone(),
            bits: pointer_bits,
        });
    }

    let final_sp = common::sub(
        current_sp,
        common::const_u64(frame_size as u64, pointer_bits),
        pointer_bits,
    );
    effects.push(SemanticEffect::Set {
        dst: base_pointer,
        expression: pushed_sp,
    });
    effects.push(SemanticEffect::Set {
        dst: stack_pointer,
        expression: final_sp,
    });

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn push(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let expression = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let new_sp = common::sub(
        SemanticExpression::Read(Box::new(stack_pointer.clone())),
        common::const_u64(slot_bytes, pointer_bits),
        pointer_bits,
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: stack_pointer.clone(),
                expression: new_sp.clone(),
            },
            SemanticEffect::Store {
                space: SemanticAddressSpace::Stack,
                addr: new_sp,
                expression,
                bits: pointer_bits,
            },
        ],
    ))
}

fn pop(
    machine: Architecture,
    _instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let old_sp = SemanticExpression::Read(Box::new(stack_pointer.clone()));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Stack,
                    addr: Box::new(old_sp.clone()),
                    bits: common::location_bits(&stack_pointer),
                },
            },
            SemanticEffect::Set {
                dst: stack_pointer,
                expression: common::add(
                    old_sp,
                    common::const_u64(slot_bytes, pointer_bits),
                    pointer_bits,
                ),
            },
        ],
    ))
}

fn leave(machine: Architecture, _instruction: &Insn) -> Option<InstructionSemantics> {
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let base_pointer = base_pointer_location(machine);
    let stack_pointer = stack_pointer_location(machine);
    let saved_bp = SemanticLocation::Temporary {
        id: 0,
        bits: pointer_bits,
    };
    Some(InstructionSemantics {
        version: 1,
        status: crate::semantics::SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: vec![SemanticTemporary {
            id: 0,
            bits: pointer_bits,
            name: Some("saved_base_pointer".to_string()),
        }],
        effects: vec![
            SemanticEffect::Set {
                dst: saved_bp.clone(),
                expression: SemanticExpression::Read(Box::new(base_pointer.clone())),
            },
            SemanticEffect::Set {
                dst: base_pointer,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Stack,
                    addr: Box::new(SemanticExpression::Read(Box::new(saved_bp.clone()))),
                    bits: pointer_bits,
                },
            },
            SemanticEffect::Set {
                dst: stack_pointer,
                expression: common::add(
                    SemanticExpression::Read(Box::new(saved_bp)),
                    common::const_u64(slot_bytes, pointer_bits),
                    pointer_bits,
                ),
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn stack_pointer_location(machine: Architecture) -> SemanticLocation {
    let register = match machine {
        Architecture::AMD64 => X86Reg::X86_REG_RSP as u16,
        Architecture::I386 => X86Reg::X86_REG_ESP as u16,
        _ => X86Reg::X86_REG_RSP as u16,
    };
    common::reg(common::reg_id_name(register), common::pointer_bits(machine))
}

fn base_pointer_location(machine: Architecture) -> SemanticLocation {
    let register = match machine {
        Architecture::AMD64 => X86Reg::X86_REG_RBP as u16,
        Architecture::I386 => X86Reg::X86_REG_EBP as u16,
        _ => X86Reg::X86_REG_RBP as u16,
    };
    common::reg(common::reg_id_name(register), common::pointer_bits(machine))
}
