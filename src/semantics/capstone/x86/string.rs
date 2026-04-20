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
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    if matches!(
        mnemonic,
        "rep stosd" | "rep stosw" | "rep movsb" | "rep movsw" | "rep movsd" | "rep movsq"
    ) {
        return match mnemonic {
            "rep stosd" => rep_stos(machine, 32),
            "rep stosw" => rep_stos(machine, 16),
            "rep movsb" => rep_movsb(machine),
            "rep movsw" => rep_movs(machine, 16),
            "rep movsd" => rep_movs(machine, 32),
            "rep movsq" => rep_movs(machine, 64),
            _ => None,
        };
    }

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_STOSB as u32 => stos(machine, 8),
        InsnId(id) if id == X86Insn::X86_INS_STOSW as u32 => stos(machine, 16),
        InsnId(id) if id == X86Insn::X86_INS_STOSD as u32 => stos(machine, 32),
        InsnId(id) if id == X86Insn::X86_INS_STOSQ as u32 => stos(machine, 64),
        InsnId(id) if id == X86Insn::X86_INS_MOVSB as u32 => movs(machine, 8),
        InsnId(id) if id == X86Insn::X86_INS_MOVSW as u32 => movs(machine, 16),
        InsnId(id) if id == X86Insn::X86_INS_MOVSD as u32 && operands.is_empty() => movs(machine, 32),
        InsnId(id) if id == X86Insn::X86_INS_MOVSQ as u32 => movs(machine, 64),
        InsnId(id) if id == X86Insn::X86_INS_LODSB as u32 => lods(machine, 8),
        InsnId(id) if id == X86Insn::X86_INS_LODSW as u32 => lods(machine, 16),
        InsnId(id) if id == X86Insn::X86_INS_LODSD as u32 => lods(machine, 32),
        InsnId(id) if id == X86Insn::X86_INS_LODSQ as u32 => lods(machine, 64),
        InsnId(id) if id == X86Insn::X86_INS_SCASB as u32 => scas(machine, 8),
        InsnId(id) if id == X86Insn::X86_INS_SCASD as u32 => scas(machine, 32),
        InsnId(id) if id == X86Insn::X86_INS_SCASQ as u32 => scas(machine, 64),
        InsnId(id) if id == X86Insn::X86_INS_SCASW as u32 => scas(machine, 16),
        InsnId(id) if id == X86Insn::X86_INS_CMPSB as u32 => cmps(machine, 8),
        InsnId(id) if id == X86Insn::X86_INS_CMPSW as u32 => cmps(machine, 16),
        InsnId(id) if id == X86Insn::X86_INS_CMPSD as u32 => cmps(machine, 32),
        InsnId(id) if id == X86Insn::X86_INS_CMPSQ as u32 => cmps(machine, 64),
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
    rep_movs(machine, 8)
}

fn rep_movs(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
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
                element_bits: bits,
                decrement: common::flag_expr("df"),
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: repeated_index_value(si, count.clone(), bits / 8, machine),
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

fn movs(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
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
                    bits,
                },
                bits,
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, bits / 8, machine),
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, bits / 8, machine),
            },
        ],
    ))
}

fn lods(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let si = index_reg(machine, false);
    let acc = accumulator_reg(machine, bits)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: acc,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(SemanticExpression::Read(Box::new(si.clone()))),
                    bits,
                },
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, bits / 8, machine),
            },
        ],
    ))
}

fn scas(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let di = index_reg(machine, true);
    let acc = accumulator_reg(machine, bits)?;
    let mem = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(SemanticExpression::Read(Box::new(di.clone()))),
        bits,
    };
    let acc_expr = SemanticExpression::Read(Box::new(acc));
    let diff = common::sub(acc_expr.clone(), mem.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    diff.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(diff.clone(), bits - 1),
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
                expression: common::sub_overflow(acc_expr.clone(), mem.clone(), diff.clone(), bits),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(acc_expr, mem, diff, bits),
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, bits / 8, machine),
            },
        ],
    ))
}

fn cmps(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let si = index_reg(machine, false);
    let di = index_reg(machine, true);
    let lhs = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(SemanticExpression::Read(Box::new(si.clone()))),
        bits,
    };
    let rhs = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(SemanticExpression::Read(Box::new(di.clone()))),
        bits,
    };
    let diff = common::sub(lhs.clone(), rhs.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    diff.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(diff.clone(), bits - 1),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Ult,
                    lhs.clone(),
                    rhs.clone(),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(lhs.clone(), rhs.clone(), diff.clone(), bits),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(lhs, rhs, diff, bits),
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, bits / 8, machine),
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, bits / 8, machine),
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
    let step = common::mul(
        count,
        common::const_u64(bytes as u64, pointer_bits),
        pointer_bits,
    );
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
        (Architecture::AMD64, 64) => X86Reg::X86_REG_RAX as u16,
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
