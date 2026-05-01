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

use crate::disassemblers::arm64::decoded::{
    Arm64DecodedInstruction, Arm64DecodedOperand, canonical_register_family,
};
use std::collections::{BTreeSet, VecDeque};

use ::capstone::Insn;

use crate::{
    controlflow::graph::Graph,
    disassemblers::arm64::{
        backends::capstone as arm64_capstone, classify as arm64_classify, flow as arm64_flow,
    },
};

pub fn resolve_register_value_from_history_by_family(
    register: &str,
    history: &[Arm64DecodedInstruction],
) -> Option<u64> {
    let mut visited = std::collections::BTreeSet::<String>::new();
    resolve_register_value_from_history_inner(register, history, &mut visited)
}

fn resolve_register_value_from_history_inner(
    register: &str,
    history: &[Arm64DecodedInstruction],
    visited: &mut std::collections::BTreeSet<String>,
) -> Option<u64> {
    if !visited.insert(register.to_string()) {
        return None;
    }

    for instruction in history.iter().rev() {
        let Some(dst) = get_defined_register(instruction) else {
            continue;
        };
        if dst != register {
            continue;
        }

        if instruction.mnemonic_is("adr") || instruction.mnemonic_is("adrp") {
            if let Some(Arm64DecodedOperand::Immediate(value)) = instruction.operands.get(1) {
                return Some(*value as u64);
            }
        }

        if instruction.mnemonic_is("mov") {
            let operand = instruction.operands.get(1)?;
            match operand {
                Arm64DecodedOperand::Immediate(imm) => return Some(*imm as u64),
                Arm64DecodedOperand::Register(src) => {
                    return resolve_register_value_from_history_inner(src, history, visited);
                }
                _ => continue,
            }
        }

        if instruction.mnemonic_is("add") {
            let src = match instruction.operands.get(1) {
                Some(Arm64DecodedOperand::Register(reg)) => reg,
                _ => continue,
            };
            let imm = match instruction.operands.get(2) {
                Some(Arm64DecodedOperand::Immediate(imm)) => *imm as u64,
                _ => continue,
            };
            let base = resolve_register_value_from_history_inner(src, history, visited)?;
            return base.checked_add(imm);
        }
    }
    None
}

pub fn is_register_jump_table_load(
    instruction: &Arm64DecodedInstruction,
    register_family: &str,
) -> bool {
    if instruction.operands.len() < 2 {
        return false;
    }
    if !instruction.mnemonic_is("ldr") && !instruction.mnemonic_is("ldrsw") {
        return false;
    }

    matches!(
        (&instruction.operands[0], &instruction.operands[1]),
        (Arm64DecodedOperand::Register(dst), Arm64DecodedOperand::Memory(src))
            if dst == register_family && src.index.is_some()
    )
}

pub fn get_memory_source(instruction: &Arm64DecodedInstruction) -> Option<(String, String, usize)> {
    if instruction.operands.len() < 2 {
        return None;
    }
    let (load_op, mem_op) = match (&instruction.operands[0], &instruction.operands[1]) {
        (Arm64DecodedOperand::Register(load), Arm64DecodedOperand::Memory(mem)) => (load, mem),
        _ => return None,
    };
    let (Some(base), Some(index)) = (mem_op.base.clone(), mem_op.index.clone()) else {
        return None;
    };

    let entry_size = match instruction.mnemonic.as_str() {
        "ldrsw" => 4,
        "ldr" => {
            if load_op.starts_with('w') {
                4
            } else {
                8
            }
        }
        _ => return None,
    };

    let scale = mem_op
        .shift_amount
        .and_then(|value| 1usize.checked_shl(value))
        .unwrap_or(entry_size);

    let final_entry_size = if matches!(
        mem_op.extender.as_deref(),
        Some("uxtw") | Some("sxtw") | Some("uxtx") | Some("sxtx")
    ) {
        scale
    } else {
        entry_size.max(scale)
    };

    Some((base, index, final_entry_size))
}

pub fn is_add_same_register(instruction: &Arm64DecodedInstruction, register_family: &str) -> bool {
    if !instruction.mnemonic_is("add") || instruction.operands.len() < 3 {
        return false;
    }
    matches!(
        &instruction.operands[0],
        Arm64DecodedOperand::Register(dst) if dst == register_family
    )
}

pub fn get_add_rhs_register(
    instruction: &Arm64DecodedInstruction,
    lhs_family: &str,
) -> Option<String> {
    if !is_add_same_register(instruction, lhs_family) {
        return None;
    }
    let src1 = match &instruction.operands[1] {
        Arm64DecodedOperand::Register(reg) => reg,
        _ => return None,
    };
    let src2 = match &instruction.operands[2] {
        Arm64DecodedOperand::Register(reg) => reg,
        _ => return None,
    };

    if src1 == lhs_family && src2 != lhs_family {
        return Some(src2.clone());
    }
    if src2 == lhs_family && src1 != lhs_family {
        return Some(src1.clone());
    }
    None
}

pub fn find_jump_table_case_count(
    index_register_family: &str,
    history: &[Arm64DecodedInstruction],
) -> Option<usize> {
    for instruction in history.iter().rev() {
        if !instruction.mnemonic_is("cmp") || instruction.operands.len() < 2 {
            continue;
        }
        let lhs_matches = matches!(
            &instruction.operands[0],
            Arm64DecodedOperand::Register(reg) if reg == index_register_family
        );
        if !lhs_matches {
            continue;
        }
        if let Arm64DecodedOperand::Immediate(imm) = &instruction.operands[1] {
            let count = (*imm + 1).max(0) as usize;
            if (1..=4096).contains(&count) {
                return Some(count);
            }
        }
    }
    None
}

pub fn register_family_for_name(name: &str) -> String {
    canonical_register_family(name)
}

fn get_defined_register(instruction: &Arm64DecodedInstruction) -> Option<String> {
    match instruction.operands.first() {
        Some(Arm64DecodedOperand::Register(reg)) => Some(reg.clone()),
        _ => None,
    }
}

pub fn has_indirect_controlflow_target(instruction: &Insn) -> bool {
    arm64_classify::has_indirect_controlflow_target_mnemonic(instruction.mnemonic().unwrap_or(""))
}

pub fn recent_decoded_instructions(
    disassembler: &arm64_capstone::Disassembler<'_>,
    address: u64,
    cfg: &Graph,
    max_count: usize,
) -> Vec<Arm64DecodedInstruction> {
    let mut addresses = VecDeque::with_capacity(max_count);
    for entry in cfg.listing.range(..address) {
        if addresses.len() == max_count {
            addresses.pop_front();
        }
        addresses.push_back(*entry.key());
    }
    let mut decoded = Vec::new();
    for address in addresses {
        if let Some(instruction) = decoded_instruction(disassembler, address) {
            decoded.push(instruction);
        }
    }
    decoded
}

fn decoded_instruction(
    disassembler: &arm64_capstone::Disassembler<'_>,
    address: u64,
) -> Option<Arm64DecodedInstruction> {
    disassembler.get_decoded_instruction(address)
}

fn indirect_controlflow_target(
    disassembler: &arm64_capstone::Disassembler<'_>,
    instruction: &Insn,
    cfg: &Graph,
) -> Option<u64> {
    let operand_index =
        arm64_flow::indirect_target_operand_index(has_indirect_controlflow_target(instruction))?;
    let Arm64DecodedOperand::Register(reg) =
        disassembler.decode_instruction_operand(instruction, operand_index)?
    else {
        return None;
    };
    let history = recent_decoded_instructions(disassembler, instruction.address(), cfg, 8);
    let target = resolve_register_value_from_history_by_family(&reg, &history)?;
    disassembler.is_executable_address(target).then_some(target)
}

pub fn indirect_controlflow_targets(
    disassembler: &arm64_capstone::Disassembler<'_>,
    instruction: &Insn,
    cfg: &Graph,
) -> BTreeSet<u64> {
    let indirect_started_at = std::time::Instant::now();
    disassembler.metric_inc(&disassembler.metrics.indirect_target_calls, 1);
    let mut targets = BTreeSet::new();
    let history = recent_decoded_instructions(disassembler, instruction.address(), cfg, 12);
    if let Some(Arm64DecodedOperand::Register(reg_name)) =
        disassembler.decode_instruction_operand(instruction, 0)
    {
        targets.extend(resolve_register_jump_table_targets(
            disassembler,
            &reg_name,
            &history,
        ));
    }
    if targets.is_empty()
        && let Some(target) = indirect_controlflow_target(disassembler, instruction, cfg)
    {
        targets.insert(target);
    }
    disassembler.metric_inc(
        &disassembler.metrics.indirect_targets_found,
        targets.len() as u64,
    );
    disassembler.metric_elapsed(
        &disassembler.metrics.indirect_target_time_us,
        indirect_started_at,
    );
    targets
}

fn resolve_register_jump_table_targets(
    disassembler: &arm64_capstone::Disassembler<'_>,
    jump_register: &str,
    history: &[Arm64DecodedInstruction],
) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    if history.is_empty() {
        return result;
    }

    let Some(load_index) = history
        .iter()
        .rposition(|insn| is_register_jump_table_load(insn, jump_register))
    else {
        return result;
    };

    let load = &history[load_index];
    let Some((base_reg, index_reg, entry_size)) = get_memory_source(load) else {
        return result;
    };
    let Some(case_count) = find_jump_table_case_count(&index_reg, &history[..=load_index]) else {
        return result;
    };
    let Some(table_base) =
        resolve_register_value_from_history_by_family(&base_reg, &history[..=load_index])
    else {
        return result;
    };

    if load.mnemonic_is("ldr") {
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

    if !load.mnemonic_is("ldrsw") {
        return result;
    }

    let Some(add_index) = history
        .iter()
        .rposition(|insn| insn.address > load.address && is_add_same_register(insn, jump_register))
    else {
        return result;
    };
    let Some(base_register) = get_add_rhs_register(&history[add_index], jump_register) else {
        return result;
    };
    let Some(code_base) =
        resolve_register_value_from_history_by_family(&base_register, &history[..=add_index])
    else {
        return result;
    };

    for i in 0..case_count {
        let Some(entry_address) = table_base.checked_add((i * 4) as u64) else {
            break;
        };
        let Some(offset) = disassembler.read_i32(entry_address) else {
            break;
        };
        let target = (code_base as i64 + offset as i64) as u64;
        if !disassembler.is_executable_address(target) {
            break;
        }
        result.insert(target);
    }
    result
}
