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
use crate::ir::lir::{
    Lir, LirAddressSpace, LirEffect, LirExpression, LirOperationCompare, LirTerminator,
};

pub(crate) fn build(machine: Architecture, view: &InstructionDetailX86) -> Option<Lir> {
    let mnemonic = view.mnemonic.as_str();
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

    match mnemonic {
        "stosb" => stos(machine, 8),
        "stosw" => stos(machine, 16),
        "stosd" => stos(machine, 32),
        "stosq" => stos(machine, 64),
        "movsb" => movs(machine, 8),
        "movsw" => movs(machine, 16),
        "movsd" if view.operand_count == 0 => movs(machine, 32),
        "movsq" => movs(machine, 64),
        "lodsb" => lods(machine, 8),
        "lodsw" => lods(machine, 16),
        "lodsd" => lods(machine, 32),
        "lodsq" => lods(machine, 64),
        "scasb" => scas(machine, 8),
        "scasd" => scas(machine, 32),
        "scasq" => scas(machine, 64),
        "scasw" => scas(machine, 16),
        "cmpsb" => cmps(machine, 8),
        "cmpsw" => cmps(machine, 16),
        "cmpsd" => cmps(machine, 32),
        "cmpsq" => cmps(machine, 64),
        _ => None,
    }
}

fn rep_stos(machine: Architecture, bits: u16) -> Option<Lir> {
    let di = index_reg(machine, true);
    let cx = counter_reg(machine);
    let count = LirExpression::Read(Box::new(cx.clone()));
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::MemorySet {
                space: LirAddressSpace::Default,
                addr: LirExpression::Read(Box::new(di.clone())),
                value: LirExpression::Read(Box::new(accumulator_reg(machine, bits)?)),
                count: count.clone(),
                element_bits: bits,
                decrement: common::flag_expr("df"),
            },
            LirEffect::Set {
                dst: di.clone(),
                expression: repeated_index_value(di, count.clone(), bits / 8, machine),
            },
            LirEffect::Set {
                dst: cx,
                expression: common::const_u64(0, common::pointer_bits(machine)),
            },
        ],
    ))
}

fn rep_movsb(machine: Architecture) -> Option<Lir> {
    rep_movs(machine, 8)
}

fn rep_movs(machine: Architecture, bits: u16) -> Option<Lir> {
    let si = index_reg(machine, false);
    let di = index_reg(machine, true);
    let cx = counter_reg(machine);
    let count = LirExpression::Read(Box::new(cx.clone()));
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::MemoryCopy {
                src_space: LirAddressSpace::Default,
                src_addr: LirExpression::Read(Box::new(si.clone())),
                dst_space: LirAddressSpace::Default,
                dst_addr: LirExpression::Read(Box::new(di.clone())),
                count: count.clone(),
                element_bits: bits,
                decrement: common::flag_expr("df"),
            },
            LirEffect::Set {
                dst: si.clone(),
                expression: repeated_index_value(si, count.clone(), bits / 8, machine),
            },
            LirEffect::Set {
                dst: di.clone(),
                expression: repeated_index_value(di, count.clone(), bits / 8, machine),
            },
            LirEffect::Set {
                dst: cx,
                expression: common::const_u64(0, common::pointer_bits(machine)),
            },
        ],
    ))
}

fn stos(machine: Architecture, bits: u16) -> Option<Lir> {
    let di = index_reg(machine, true);
    let acc = accumulator_reg(machine, bits)?;
    let addr = LirExpression::Read(Box::new(di.clone()));
    let step = next_index_value(di.clone(), bits / 8, machine);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Store {
                space: LirAddressSpace::Default,
                addr,
                expression: LirExpression::Read(Box::new(acc)),
                bits,
            },
            LirEffect::Set {
                dst: di,
                expression: step,
            },
        ],
    ))
}

fn movs(machine: Architecture, bits: u16) -> Option<Lir> {
    let si = index_reg(machine, false);
    let di = index_reg(machine, true);
    let src_addr = LirExpression::Read(Box::new(si.clone()));
    let dst_addr = LirExpression::Read(Box::new(di.clone()));
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Store {
                space: LirAddressSpace::Default,
                addr: dst_addr,
                expression: LirExpression::Load {
                    space: LirAddressSpace::Default,
                    addr: Box::new(src_addr),
                    bits,
                },
                bits,
            },
            LirEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, bits / 8, machine),
            },
            LirEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, bits / 8, machine),
            },
        ],
    ))
}

fn lods(machine: Architecture, bits: u16) -> Option<Lir> {
    let si = index_reg(machine, false);
    let acc = accumulator_reg(machine, bits)?;
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: acc,
                expression: LirExpression::Load {
                    space: LirAddressSpace::Default,
                    addr: Box::new(LirExpression::Read(Box::new(si.clone()))),
                    bits,
                },
            },
            LirEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, bits / 8, machine),
            },
        ],
    ))
}

fn scas(machine: Architecture, bits: u16) -> Option<Lir> {
    let di = index_reg(machine, true);
    let acc = accumulator_reg(machine, bits)?;
    let mem = LirExpression::Load {
        space: LirAddressSpace::Default,
        addr: Box::new(LirExpression::Read(Box::new(di.clone()))),
        bits,
    };
    let acc_expr = LirExpression::Read(Box::new(acc));
    let diff = common::sub(acc_expr.clone(), mem.clone(), bits);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    diff.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(diff.clone(), bits - 1),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    LirOperationCompare::Ult,
                    acc_expr.clone(),
                    mem.clone(),
                ),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(acc_expr.clone(), mem.clone(), diff.clone(), bits),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff.clone()),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(acc_expr, mem, diff, bits),
            },
            LirEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, bits / 8, machine),
            },
        ],
    ))
}

fn cmps(machine: Architecture, bits: u16) -> Option<Lir> {
    let si = index_reg(machine, false);
    let di = index_reg(machine, true);
    let lhs = LirExpression::Load {
        space: LirAddressSpace::Default,
        addr: Box::new(LirExpression::Read(Box::new(si.clone()))),
        bits,
    };
    let rhs = LirExpression::Load {
        space: LirAddressSpace::Default,
        addr: Box::new(LirExpression::Read(Box::new(di.clone()))),
        bits,
    };
    let diff = common::sub(lhs.clone(), rhs.clone(), bits);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    diff.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(diff.clone(), bits - 1),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(LirOperationCompare::Ult, lhs.clone(), rhs.clone()),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(lhs.clone(), rhs.clone(), diff.clone(), bits),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff.clone()),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(lhs, rhs, diff, bits),
            },
            LirEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, bits / 8, machine),
            },
            LirEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, bits / 8, machine),
            },
        ],
    ))
}

fn next_index_value(
    index: crate::ir::lir::LirLocation,
    bytes: u16,
    machine: Architecture,
) -> LirExpression {
    let pointer_bits = common::pointer_bits(machine);
    let current = LirExpression::Read(Box::new(index));
    LirExpression::Select {
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
    index: crate::ir::lir::LirLocation,
    count: LirExpression,
    bytes: u16,
    machine: Architecture,
) -> LirExpression {
    let pointer_bits = common::pointer_bits(machine);
    let step = common::mul(
        count,
        common::const_u64(bytes as u64, pointer_bits),
        pointer_bits,
    );
    let current = LirExpression::Read(Box::new(index));
    LirExpression::Select {
        condition: Box::new(common::flag_expr("df")),
        when_true: Box::new(common::sub(current.clone(), step.clone(), pointer_bits)),
        when_false: Box::new(common::add(current, step, pointer_bits)),
        bits: pointer_bits,
    }
}

fn index_reg(machine: Architecture, destination: bool) -> crate::ir::lir::LirLocation {
    let (name, bits) = match (machine, destination) {
        (Architecture::AMD64, true) => ("rdi", 64),
        (Architecture::AMD64, false) => ("rsi", 64),
        (Architecture::I386, true) => ("edi", 32),
        (Architecture::I386, false) => ("esi", 32),
        (_, true) => ("rdi", 64),
        (_, false) => ("rsi", 64),
    };
    common::reg(name.to_string(), bits)
}

fn accumulator_reg(machine: Architecture, bits: u16) -> Option<crate::ir::lir::LirLocation> {
    let name = match (machine, bits) {
        (Architecture::AMD64, 8) | (Architecture::I386, 8) => "al",
        (Architecture::AMD64, 16) | (Architecture::I386, 16) => "ax",
        (Architecture::AMD64, 32) | (Architecture::I386, 32) => "eax",
        (Architecture::AMD64, 64) => "rax",
        _ => return None,
    };
    Some(common::reg(name.to_string(), bits))
}

fn counter_reg(machine: Architecture) -> crate::ir::lir::LirLocation {
    let (name, bits) = match machine {
        Architecture::AMD64 => ("rcx", 64),
        Architecture::I386 => ("ecx", 32),
        _ => ("rcx", 64),
    };
    common::reg(name.to_string(), bits)
}
