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

use std::collections::BTreeSet;

use ::capstone::{Insn, RegId, arch::ArchOperand, arch::x86::X86OpMem, arch::x86::X86OperandType};

use crate::{
    controlflow::graph::Graph,
    disassemblers::x86::{
        backends::capstone as x86_capstone,
        decoded::{canonical_register_name, X86DecodedInstruction, X86DecodedMemoryOperand, X86DecodedOperand},
        flow as x86_flow,
        targets as x86_targets,
    },
};

pub fn is_register_jump_table_load(
    instruction: &X86DecodedInstruction,
    register: &str,
) -> bool {
    if instruction.operands.len() < 2 {
        return false;
    }
    if !instruction.mnemonic_is("mov") && !instruction.mnemonic_is("movsxd") {
        return false;
    }

    matches!(
        (&instruction.operands[0], &instruction.operands[1]),
        (X86DecodedOperand::Register(dst), X86DecodedOperand::Memory(src))
            if dst == register && src.index.is_some()
    )
}

pub fn get_memory_source(
    instruction: &X86DecodedInstruction,
) -> Option<(&X86DecodedMemoryOperand, usize)> {
    if instruction.operands.len() < 2 {
        return None;
    }
    match (&instruction.operands[0], &instruction.operands[1]) {
        (_, X86DecodedOperand::Memory(src)) => Some((src, src.operand_size)),
        _ => None,
    }
}

pub fn is_add_same_register(instruction: &X86DecodedInstruction, register: &str) -> bool {
    if !instruction.mnemonic_is("add") || instruction.operands.len() < 2 {
        return false;
    }
    matches!(
        &instruction.operands[0],
        X86DecodedOperand::Register(dst) if dst == register
    )
}

pub fn get_add_rhs_register(
    instruction: &X86DecodedInstruction,
    lhs: &str,
) -> Option<String> {
    if !is_add_same_register(instruction, lhs) {
        return None;
    }
    match &instruction.operands[1] {
        X86DecodedOperand::Register(reg) => Some(reg.clone()),
        _ => None,
    }
}

pub fn find_jump_table_case_count(
    index_register: &str,
    history: &[X86DecodedInstruction],
) -> Option<usize> {
    for instruction in history.iter().rev() {
        if !instruction.mnemonic_is("cmp") || instruction.operands.len() < 2 {
            continue;
        }
        let lhs_matches = matches!(
            &instruction.operands[0],
            X86DecodedOperand::Register(reg) if reg == index_register
        );
        if !lhs_matches {
            continue;
        }
        if let X86DecodedOperand::Immediate(imm) = &instruction.operands[1] {
            let count = (*imm + 1).max(0) as usize;
            if (1..=256).contains(&count) {
                return Some(count);
            }
        }
    }
    None
}

pub fn resolve_jump_table_base_from_history(
    mem: &X86DecodedMemoryOperand,
    history: &[X86DecodedInstruction],
    resolve_register_value: impl Fn(&str, &[X86DecodedInstruction]) -> Option<u64>,
) -> Option<u64> {
    if mem.base.is_none() {
        return Some(mem.displacement as u64);
    }
    resolve_register_value(mem.base.as_deref()?, history)
        .and_then(|base| base.checked_add(mem.displacement as u64))
}

pub fn recent_decoded_instructions(
    disassembler: &x86_capstone::Disassembler<'_>,
    address: u64,
    cfg: &Graph,
    max_count: usize,
) -> Vec<X86DecodedInstruction> {
    let mut addresses = Vec::new();
    for entry in cfg.listing.range(..address) {
        addresses.push(*entry.key());
    }
    let start = addresses.len().saturating_sub(max_count);
    let mut decoded = Vec::new();
    for address in &addresses[start..] {
        let Ok(insns) = disassembler.disassemble_instructions(*address, 1) else {
            continue;
        };
        let Some(insn) = insns.iter().next() else {
            continue;
        };
        let Ok(operands) = disassembler.get_instruction_operands(insn) else {
            continue;
        };
        decoded.push(X86DecodedInstruction {
            address: insn.address(),
            bytes: insn.bytes().to_vec(),
            mnemonic: insn.mnemonic().unwrap_or("").to_lowercase(),
            operands: operands
                .iter()
                .filter_map(|operand| disassembler.decode_history_operand(operand))
                .collect(),
        });
    }
    decoded
}

pub fn resolve_register_value_from_history(
    register: &str,
    history: &[X86DecodedInstruction],
) -> Option<u64> {
    for instruction in history.iter().rev() {
        if !instruction.mnemonic_is("lea") || instruction.operands.len() < 2 {
            continue;
        }
        let dst_matches = matches!(
            &instruction.operands[0],
            X86DecodedOperand::Register(dst) if dst == register
        );
        if !dst_matches {
            continue;
        }
        if let X86DecodedOperand::Memory(mem) = &instruction.operands[1] {
            if mem.base.as_deref() == Some("rip") {
                return Some(
                    (instruction.address as i64 + mem.displacement + instruction.bytes.len() as i64)
                        as u64,
                );
            }
            if mem.base.is_none() {
                return Some(mem.displacement as u64);
            }
        }
    }
    None
}

pub fn has_indirect_controlflow_target(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> bool {
    let operand_is_register_or_memory = matches!(
        disassembler.decode_instruction_operand(instruction, 0),
        Some(X86DecodedOperand::Register(_)) | Some(X86DecodedOperand::Memory(_))
    );
    x86_flow::has_indirect_controlflow_target(
        x86_capstone::Disassembler::is_call_instruction(instruction),
        x86_capstone::Disassembler::is_jump_instruction(instruction),
        operand_is_register_or_memory,
    )
}

fn indirect_controlflow_target(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    if !has_indirect_controlflow_target(disassembler, instruction) {
        return None;
    }
    let operand = disassembler.get_instruction_operand(instruction, 0).ok()?;
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    let X86OperandType::Mem(mem) = op.op_type else {
        return None;
    };
    disassembler.resolve_memory_operand_target(instruction, mem)
}

pub fn indirect_controlflow_targets(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
    cfg: &Graph,
) -> BTreeSet<u64> {
    let mut targets = BTreeSet::new();

    if let Some(target) = indirect_controlflow_target(disassembler, instruction) {
        targets.insert(target);
    }

    if !x86_flow::should_expand_jump_table(
        x86_capstone::Disassembler::is_unconditional_jump_instruction(instruction),
    ) {
        return targets;
    }

    let history = recent_decoded_instructions(disassembler, instruction.address(), cfg, 6);
    let Some(decoded) = disassembler.decode_instruction_operand(instruction, 0) else {
        return targets;
    };
    let Ok(raw_operand) = disassembler.get_instruction_operand(instruction, 0) else {
        return targets;
    };

    match (decoded, raw_operand) {
        (X86DecodedOperand::Memory(decoded_mem), ArchOperand::X86Operand(op))
            if decoded_mem.index.is_some() =>
        {
            if let X86OperandType::Mem(mem) = op.op_type {
                targets.extend(resolve_jump_table_memory_targets(
                    disassembler,
                    instruction,
                    mem,
                    op.size as usize,
                    &history,
                ));
            }
        }
        (X86DecodedOperand::Register(_reg_name), ArchOperand::X86Operand(op)) => {
            if let X86OperandType::Reg(reg) = op.op_type {
                targets.extend(resolve_register_jump_table_targets(disassembler, reg, &history));
            }
        }
        _ => {}
    }

    targets
}

fn resolve_jump_table_memory_targets(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
    mem: X86OpMem,
    operand_size: usize,
    history: &[X86DecodedInstruction],
) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    let Some(table_base) = x86_targets::resolve_jump_table_base(
        disassembler,
        instruction,
        mem.base(),
        mem.disp(),
        history,
        resolve_register_value_from_history,
    ) else {
        return result;
    };
    let Some(index_register) = disassembler
        .register_name(mem.index())
        .map(|name| canonical_register_name(&name).to_string())
    else {
        return result;
    };
    let Some(case_count) = find_jump_table_case_count(&index_register, history) else {
        return result;
    };

    let entry_size = x86_targets::jump_table_entry_size(disassembler.machine, mem.scale() as usize, operand_size);
    if entry_size == 0 {
        return result;
    }

    for i in 0..case_count {
        let Some(entry_address) = table_base.checked_add((i * entry_size) as u64) else {
            break;
        };
        let Some(target) = disassembler.read_pointer_sized(entry_address, entry_size) else {
            break;
        };
        if !disassembler.is_executable_address(target) {
            break;
        }
        result.insert(target);
    }

    result
}

fn resolve_register_jump_table_targets(
    disassembler: &x86_capstone::Disassembler<'_>,
    jump_register: RegId,
    history: &[X86DecodedInstruction],
) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    if history.is_empty() {
        return result;
    }
    let Some(jump_register_name) = disassembler
        .register_name(jump_register)
        .map(|name| canonical_register_name(&name).to_string())
    else {
        return result;
    };

    let Some(load_index) = history
        .iter()
        .rposition(|insn| is_register_jump_table_load(insn, &jump_register_name))
    else {
        return result;
    };

    let load = &history[load_index];
    let Some((mem, operand_size)) = get_memory_source(load) else {
        return result;
    };
    let Some(index_register) = mem.index.as_deref() else {
        return result;
    };
    let Some(case_count) = find_jump_table_case_count(index_register, history) else {
        return result;
    };

    if load.mnemonic_is("mov") {
        let Some(table_base) =
            resolve_jump_table_base_from_history(mem, history, resolve_register_value_from_history)
        else {
            return result;
        };
        let entry_size = x86_targets::jump_table_entry_size(disassembler.machine, mem.scale as usize, operand_size);
        if entry_size == 0 {
            return result;
        }
        for i in 0..case_count {
            let Some(entry_address) = table_base.checked_add((i * entry_size) as u64) else {
                break;
            };
            let Some(target) = disassembler.read_pointer_sized(entry_address, entry_size) else {
                break;
            };
            if !disassembler.is_executable_address(target) {
                break;
            }
            result.insert(target);
        }
        return result;
    }

    if !load.mnemonic_is("movsxd") {
        return result;
    }

    let Some(add_index) = history
        .iter()
        .rposition(|insn| is_add_same_register(insn, &jump_register_name) && insn.address > load.address)
    else {
        return result;
    };

    let Some(base_register) = get_add_rhs_register(&history[add_index], &jump_register_name) else {
        return result;
    };
    let Some(table_base) = resolve_register_value_from_history(&base_register, history) else {
        return result;
    };

    for i in 0..case_count {
        let Some(entry_address) = table_base.checked_add((i * 4) as u64) else {
            break;
        };
        let Some(offset) = disassembler.read_i32(entry_address) else {
            break;
        };
        let target = (table_base as i64 + offset as i64) as u64;
        if !disassembler.is_executable_address(target) {
            break;
        }
        result.insert(target);
    }

    result
}
