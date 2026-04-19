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
    SemanticOperationCompare, SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86Reg};

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    _operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    if matches!(mnemonic, "rep stosd" | "rep stosw" | "rep movsb") {
        return match mnemonic {
            "rep stosd" => rep_stos(machine, 32),
            "rep stosw" => rep_stos(machine, 16),
            "rep movsb" => rep_movsb(machine),
            _ => None,
        };
    }

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_STOSB as u32 => stos(machine, 8),
        InsnId(id) if id == X86Insn::X86_INS_STOSW as u32 => stos(machine, 16),
        InsnId(id) if id == X86Insn::X86_INS_STOSD as u32 => stos(machine, 32),
        InsnId(id) if id == X86Insn::X86_INS_MOVSW as u32 => movsw(machine),
        InsnId(id) if id == X86Insn::X86_INS_SCASD as u32 => scasd(machine),
        _ => None,
    }
}

fn rep_stos(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let di = index_reg(machine, true);
    let cx = counter_reg(machine);
    let count = SemanticExpression::Read(Box::new(cx.clone()));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::MemorySet {
                space: SemanticAddressSpace::Default,
                addr: SemanticExpression::Read(Box::new(di.clone())),
                value: SemanticExpression::Read(Box::new(accumulator_reg(machine, bits)?)),
                count: count.clone(),
                element_bits: bits,
                decrement: common::flag_expr("df"),
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: repeated_index_value(di, count.clone(), bits / 8, machine),
            },
            SemanticEffect::Set {
                dst: cx,
                expression: common::const_u64(0, common::pointer_bits(machine)),
            },
        ],
    ))
}

fn rep_movsb(machine: Architecture) -> Option<InstructionSemantics> {
    let si = index_reg(machine, false);
    let di = index_reg(machine, true);
    let cx = counter_reg(machine);
    let count = SemanticExpression::Read(Box::new(cx.clone()));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::MemoryCopy {
                src_space: SemanticAddressSpace::Default,
                src_addr: SemanticExpression::Read(Box::new(si.clone())),
                dst_space: SemanticAddressSpace::Default,
                dst_addr: SemanticExpression::Read(Box::new(di.clone())),
                count: count.clone(),
                element_bits: 8,
                decrement: common::flag_expr("df"),
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: repeated_index_value(si, count.clone(), 1, machine),
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: repeated_index_value(di, count.clone(), 1, machine),
            },
            SemanticEffect::Set {
                dst: cx,
                expression: common::const_u64(0, common::pointer_bits(machine)),
            },
        ],
    ))
}

fn stos(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let di = index_reg(machine, true);
    let acc = accumulator_reg(machine, bits)?;
    let addr = SemanticExpression::Read(Box::new(di.clone()));
    let step = next_index_value(di.clone(), bits / 8, machine);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: SemanticExpression::Read(Box::new(acc)),
                bits,
            },
            SemanticEffect::Set {
                dst: di,
                expression: step,
            },
        ],
    ))
}

fn movsw(machine: Architecture) -> Option<InstructionSemantics> {
    let si = index_reg(machine, false);
    let di = index_reg(machine, true);
    let src_addr = SemanticExpression::Read(Box::new(si.clone()));
    let dst_addr = SemanticExpression::Read(Box::new(di.clone()));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: dst_addr,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(src_addr),
                    bits: 16,
                },
                bits: 16,
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, 2, machine),
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, 2, machine),
            },
        ],
    ))
}

fn scasd(machine: Architecture) -> Option<InstructionSemantics> {
    let di = index_reg(machine, true);
    let acc = accumulator_reg(machine, 32)?;
    let mem = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(SemanticExpression::Read(Box::new(di.clone()))),
        bits: 32,
    };
    let acc_expr = SemanticExpression::Read(Box::new(acc));
    let diff = common::sub(acc_expr.clone(), mem.clone(), 32);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    diff.clone(),
                    common::const_u64(0, 32),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(diff.clone(), 31),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Ult,
                    acc_expr.clone(),
                    mem.clone(),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(acc_expr.clone(), mem.clone(), diff.clone(), 32),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(acc_expr, mem, diff, 32),
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, 4, machine),
            },
        ],
    ))
}

fn next_index_value(
    index: crate::semantics::SemanticLocation,
    bytes: u16,
    machine: Architecture,
) -> SemanticExpression {
    let pointer_bits = common::pointer_bits(machine);
    let current = SemanticExpression::Read(Box::new(index));
    SemanticExpression::Select {
        condition: Box::new(common::flag_expr("df")),
        when_true: Box::new(common::sub(
            current.clone(),
            common::const_u64(bytes as u64, pointer_bits),
            pointer_bits,
        )),
        when_false: Box::new(common::add(
            current,
            common::const_u64(bytes as u64, pointer_bits),
            pointer_bits,
        )),
        bits: pointer_bits,
    }
}

fn repeated_index_value(
    index: crate::semantics::SemanticLocation,
    count: SemanticExpression,
    bytes: u16,
    machine: Architecture,
) -> SemanticExpression {
    let pointer_bits = common::pointer_bits(machine);
    let step = common::mul(count, common::const_u64(bytes as u64, pointer_bits), pointer_bits);
    let current = SemanticExpression::Read(Box::new(index));
    SemanticExpression::Select {
        condition: Box::new(common::flag_expr("df")),
        when_true: Box::new(common::sub(current.clone(), step.clone(), pointer_bits)),
        when_false: Box::new(common::add(current, step, pointer_bits)),
        bits: pointer_bits,
    }
}

fn index_reg(machine: Architecture, destination: bool) -> crate::semantics::SemanticLocation {
    let register = match (machine, destination) {
        (Architecture::AMD64, true) => X86Reg::X86_REG_RDI as u16,
        (Architecture::AMD64, false) => X86Reg::X86_REG_RSI as u16,
        (Architecture::I386, true) => X86Reg::X86_REG_EDI as u16,
        (Architecture::I386, false) => X86Reg::X86_REG_ESI as u16,
        (_, true) => X86Reg::X86_REG_RDI as u16,
        (_, false) => X86Reg::X86_REG_RSI as u16,
    };
    common::reg(common::reg_id_name(register), common::pointer_bits(machine))
}

fn accumulator_reg(machine: Architecture, bits: u16) -> Option<crate::semantics::SemanticLocation> {
    let register = match (machine, bits) {
        (Architecture::AMD64, 8) | (Architecture::I386, 8) => X86Reg::X86_REG_AL as u16,
        (Architecture::AMD64, 16) | (Architecture::I386, 16) => X86Reg::X86_REG_AX as u16,
        (Architecture::AMD64, 32) | (Architecture::I386, 32) => X86Reg::X86_REG_EAX as u16,
        _ => return None,
    };
    Some(common::reg(common::reg_id_name(register), bits))
}

fn counter_reg(machine: Architecture) -> crate::semantics::SemanticLocation {
    let register = match machine {
        Architecture::AMD64 => X86Reg::X86_REG_RCX as u16,
        Architecture::I386 => X86Reg::X86_REG_ECX as u16,
        _ => X86Reg::X86_REG_RCX as u16,
    };
    common::reg(common::reg_id_name(register), common::pointer_bits(machine))
}
