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

use crate::Architecture;
use crate::ir::lir::x86::InstructionDetailX86;
use crate::ir::lir::x86::helpers as common;
use crate::ir::lir::x86::{X86OperandKind, X86OperandView};
use crate::ir::lir::{
    Lir, LirAddressSpace, LirEffect, LirExpression, LirLocation, LirStatus, LirTemporary,
    LirTerminator,
};

pub(crate) fn build(view: &InstructionDetailX86) -> Option<Lir> {
    match view.mnemonic.as_str() {
        "push" => push(view.machine, view.operands()),
        "pop" => pop(view.machine, view.operands()),
        "pushal" => pushal(view.machine),
        "popal" => popal(view.machine),
        "leave" => leave(view.machine),
        "enter" => enter(view.machine, view.operands()),
        _ => None,
    }
}

fn pushal(machine: Architecture) -> Option<Lir> {
    if !matches!(machine, Architecture::I386) {
        return None;
    }
    let sp = stack_pointer_location(machine);
    let old_sp = LirExpression::Read(Box::new(sp.clone()));
    let regs = [
        LirExpression::Read(Box::new(common::reg("eax", 32))),
        LirExpression::Read(Box::new(common::reg("ecx", 32))),
        LirExpression::Read(Box::new(common::reg("edx", 32))),
        LirExpression::Read(Box::new(common::reg("ebx", 32))),
        LirExpression::Read(Box::new(common::reg("esp", 32))),
        LirExpression::Read(Box::new(common::reg("ebp", 32))),
        LirExpression::Read(Box::new(common::reg("esi", 32))),
        LirExpression::Read(Box::new(common::reg("edi", 32))),
    ];
    let mut effects = Vec::new();
    for (index, reg) in regs.into_iter().enumerate() {
        effects.push(LirEffect::Store {
            space: LirAddressSpace::Stack,
            addr: common::sub(
                old_sp.clone(),
                common::const_u64(((index + 1) * 4) as u64, 32),
                32,
            ),
            expression: reg,
            bits: 32,
        });
    }
    effects.push(LirEffect::Set {
        dst: sp,
        expression: common::sub(old_sp, common::const_u64(32, 32), 32),
    });
    Some(common::complete(LirTerminator::FallThrough, effects))
}

fn popal(machine: Architecture) -> Option<Lir> {
    if !matches!(machine, Architecture::I386) {
        return None;
    }
    let sp = stack_pointer_location(machine);
    let old_sp = LirExpression::Read(Box::new(sp.clone()));
    let loads = |offset: u64| LirExpression::Load {
        space: LirAddressSpace::Stack,
        addr: Box::new(common::add(
            old_sp.clone(),
            common::const_u64(offset, 32),
            32,
        )),
        bits: 32,
    };
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: common::reg("edi", 32),
                expression: loads(0),
            },
            LirEffect::Set {
                dst: common::reg("esi", 32),
                expression: loads(4),
            },
            LirEffect::Set {
                dst: common::reg("ebp", 32),
                expression: loads(8),
            },
            LirEffect::Set {
                dst: common::reg("ebx", 32),
                expression: loads(16),
            },
            LirEffect::Set {
                dst: common::reg("edx", 32),
                expression: loads(20),
            },
            LirEffect::Set {
                dst: common::reg("ecx", 32),
                expression: loads(24),
            },
            LirEffect::Set {
                dst: common::reg("eax", 32),
                expression: loads(28),
            },
            LirEffect::Set {
                dst: sp,
                expression: common::add(old_sp, common::const_u64(32, 32), 32),
            },
        ],
    ))
}

fn enter(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let frame_size = operands.first()?.immediate_value()?;
    let nesting_level = operands.get(1)?.immediate_value()?;

    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let stack_pointer = stack_pointer_location(machine);
    let base_pointer = base_pointer_location(machine);
    let old_sp = LirExpression::Read(Box::new(stack_pointer.clone()));
    let pushed_sp = common::sub(
        old_sp.clone(),
        common::const_u64(slot_bytes, pointer_bits),
        pointer_bits,
    );
    let old_bp = LirExpression::Read(Box::new(base_pointer.clone()));
    let mut effects = vec![LirEffect::Store {
        space: LirAddressSpace::Stack,
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
            effects.push(LirEffect::Store {
                space: LirAddressSpace::Stack,
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
        effects.push(LirEffect::Store {
            space: LirAddressSpace::Stack,
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
    effects.push(LirEffect::Set {
        dst: base_pointer,
        expression: pushed_sp,
    });
    effects.push(LirEffect::Set {
        dst: stack_pointer,
        expression: final_sp,
    });

    Some(common::complete(LirTerminator::FallThrough, effects))
}

fn push(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let expression = operand_expr(machine, operands.first()?)?;
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let new_sp = common::sub(
        LirExpression::Read(Box::new(stack_pointer.clone())),
        common::const_u64(slot_bytes, pointer_bits),
        pointer_bits,
    );
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: stack_pointer.clone(),
                expression: new_sp.clone(),
            },
            LirEffect::Store {
                space: LirAddressSpace::Stack,
                addr: new_sp,
                expression,
                bits: pointer_bits,
            },
        ],
    ))
}

fn pop(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let old_sp = LirExpression::Read(Box::new(stack_pointer.clone()));
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: LirExpression::Load {
                    space: LirAddressSpace::Stack,
                    addr: Box::new(old_sp.clone()),
                    bits: common::location_bits(&stack_pointer),
                },
            },
            LirEffect::Set {
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

fn leave(machine: Architecture) -> Option<Lir> {
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (pointer_bits / 8) as u64;
    let base_pointer = base_pointer_location(machine);
    let stack_pointer = stack_pointer_location(machine);
    let saved_bp = LirLocation::Temporary {
        id: 0,
        bits: pointer_bits,
    };
    Some(Lir {
        version: 1,
        status: LirStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: vec![LirTemporary {
            id: 0,
            bits: pointer_bits,
            name: Some("saved_base_pointer".to_string()),
        }],
        effects: vec![
            LirEffect::Set {
                dst: saved_bp.clone(),
                expression: LirExpression::Read(Box::new(base_pointer.clone())),
            },
            LirEffect::Set {
                dst: base_pointer,
                expression: LirExpression::Load {
                    space: LirAddressSpace::Stack,
                    addr: Box::new(LirExpression::Read(Box::new(saved_bp.clone()))),
                    bits: pointer_bits,
                },
            },
            LirEffect::Set {
                dst: stack_pointer,
                expression: common::add(
                    LirExpression::Read(Box::new(saved_bp)),
                    common::const_u64(slot_bytes, pointer_bits),
                    pointer_bits,
                ),
            },
        ],
        terminator: LirTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn stack_pointer_location(machine: Architecture) -> LirLocation {
    let (name, bits) = match machine {
        Architecture::AMD64 => ("rsp", 64),
        Architecture::I386 => ("esp", 32),
        _ => ("rsp", 64),
    };
    common::reg(name, bits)
}

fn base_pointer_location(machine: Architecture) -> LirLocation {
    let (name, bits) = match machine {
        Architecture::AMD64 => ("rbp", 64),
        Architecture::I386 => ("ebp", 32),
        _ => ("rbp", 64),
    };
    common::reg(name, bits)
}

fn operand_expr(machine: Architecture, operand: &X86OperandView) -> Option<LirExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(LirExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(LirExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(LirExpression::Load {
                space: LirAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(machine: Architecture, operand: &X86OperandView) -> Option<LirLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(LirLocation::Memory {
                space: LirAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}
