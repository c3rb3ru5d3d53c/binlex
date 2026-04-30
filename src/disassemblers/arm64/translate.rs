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
use std::io::Error;

use ::capstone::{
    Insn, RegId, arch::ArchOperand,
    arch::arm64::{Arm64Extender, Arm64OperandType, Arm64Reg, Arm64Shift},
};

use crate::{
    Architecture,
    controlflow::graph::Graph,
    controlflow::{Instruction, InstructionSemanticsInput, Operand, OperandKind},
    disassemblers::arm64::{
        backends::capstone as arm64_capstone, flow as arm64_flow,
        indirect as arm64_indirect, targets as arm64_targets,
    },
    genetics::Chromosome,
    semantics::architectures::arm64::{
        Arm64InstructionView, Arm64MemoryOperandView, Arm64OperandKind, Arm64OperandView,
    },
    semantics::architectures::arm64::operand::Arm64ShiftKind,
};

fn semantic_register_bits(reg_id: u16) -> u16 {
    match RegId(reg_id).0 as u32 {
        id if id == Arm64Reg::ARM64_REG_WSP || id == Arm64Reg::ARM64_REG_WZR => 32,
        id if (Arm64Reg::ARM64_REG_W0..=Arm64Reg::ARM64_REG_W30).contains(&id) => 32,
        id if id == Arm64Reg::ARM64_REG_SP
            || id == Arm64Reg::ARM64_REG_FP
            || id == Arm64Reg::ARM64_REG_LR
            || id == Arm64Reg::ARM64_REG_XZR =>
        {
            64
        }
        id if (Arm64Reg::ARM64_REG_X0..=Arm64Reg::ARM64_REG_X28).contains(&id) => 64,
        id if (Arm64Reg::ARM64_REG_B0..=Arm64Reg::ARM64_REG_B31).contains(&id) => 8,
        id if (Arm64Reg::ARM64_REG_H0..=Arm64Reg::ARM64_REG_H31).contains(&id) => 16,
        id if (Arm64Reg::ARM64_REG_S0..=Arm64Reg::ARM64_REG_S31).contains(&id) => 32,
        id if (Arm64Reg::ARM64_REG_D0..=Arm64Reg::ARM64_REG_D31).contains(&id) => 64,
        id if (Arm64Reg::ARM64_REG_Q0..=Arm64Reg::ARM64_REG_Q31).contains(&id) => 128,
        id if (Arm64Reg::ARM64_REG_V0..=Arm64Reg::ARM64_REG_V31).contains(&id) => 128,
        _ => 64,
    }
}

fn canonical_semantic_register_id(reg_id: u16) -> u16 {
    match RegId(reg_id).0 as u32 {
        id if id == Arm64Reg::ARM64_REG_FP => Arm64Reg::ARM64_REG_X29 as u16,
        id if id == Arm64Reg::ARM64_REG_LR => Arm64Reg::ARM64_REG_X30 as u16,
        id if id == Arm64Reg::ARM64_REG_WSP => Arm64Reg::ARM64_REG_SP as u16,
        _ => reg_id,
    }
}

fn semantic_register_name_from_id(reg_id: u16) -> String {
    format!("reg_{}", canonical_semantic_register_id(reg_id))
}

fn semantic_register_id_from_text(token: &str) -> Option<u16> {
    let normalized = token.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "sp" => Some(Arm64Reg::ARM64_REG_SP as u16),
        "wsp" => Some(Arm64Reg::ARM64_REG_SP as u16),
        "fp" => Some(Arm64Reg::ARM64_REG_X29 as u16),
        "lr" => Some(Arm64Reg::ARM64_REG_X30 as u16),
        "xzr" => Some(Arm64Reg::ARM64_REG_XZR as u16),
        "wzr" => Some(Arm64Reg::ARM64_REG_WZR as u16),
        _ => {
            let (prefix, number) = semantic_parse_indexed_register(&normalized)?;
            let id = match prefix {
                'x' if number <= 28 => Arm64Reg::ARM64_REG_X0 as u32 + number as u32,
                'x' if number == 29 => Arm64Reg::ARM64_REG_X29 as u32,
                'x' if number == 30 => Arm64Reg::ARM64_REG_X30 as u32,
                'w' if number <= 30 => Arm64Reg::ARM64_REG_W0 as u32 + number as u32,
                'v' if number <= 31 => Arm64Reg::ARM64_REG_V0 as u32 + number as u32,
                'q' if number <= 31 => Arm64Reg::ARM64_REG_Q0 as u32 + number as u32,
                'd' if number <= 31 => Arm64Reg::ARM64_REG_D0 as u32 + number as u32,
                's' if number <= 31 => Arm64Reg::ARM64_REG_S0 as u32 + number as u32,
                'h' if number <= 31 => Arm64Reg::ARM64_REG_H0 as u32 + number as u32,
                'b' if number <= 31 => Arm64Reg::ARM64_REG_B0 as u32 + number as u32,
                _ => return None,
            };
            Some(id as u16)
        }
    }
}

fn semantic_named_register(
    register_id: u16,
    size_bits: u16,
    vector_index: Option<u32>,
) -> Arm64OperandView {
    Arm64OperandView {
        kind: Arm64OperandKind::Register,
        size_bits,
        register_name: Some(semantic_register_name_from_id(register_id)),
        immediate: None,
        float: None,
        memory: None,
        vector_index,
        vas: None,
        shift: None,
        extender: None,
    }
}

fn semantic_parse_indexed_register(token: &str) -> Option<(char, u16)> {
    let normalized = token.trim().to_ascii_lowercase();
    let mut chars = normalized.chars();
    let prefix = chars.next()?;
    let number = chars.as_str().parse::<u16>().ok()?;
    Some((prefix, number))
}

fn semantic_register_from_text(token: &str) -> Option<Arm64OperandView> {
    let normalized = token.trim().to_ascii_lowercase();
    let lane_index = normalized
        .split_once('[')
        .and_then(|(_, suffix)| suffix.strip_suffix(']'))
        .and_then(|index| index.parse::<u32>().ok());
    let base = normalized
        .split_once('[')
        .map(|(base, _)| base)
        .unwrap_or(&normalized)
        .split_once('.')
        .map(|(base, _)| base)
        .unwrap_or_else(|| normalized.as_str())
        .trim();
    let register_id = semantic_register_id_from_text(base)?;
    let size_bits = match base.chars().next()? {
        'w' => 32,
        'x' => 64,
        'v' | 'q' => 128,
        'd' => 64,
        's' => 32,
        'h' => 16,
        'b' => 8,
        _ => 64,
    };
    Some(semantic_named_register(register_id, size_bits, lane_index))
}

fn semantic_memory_from_text(token: &str) -> Option<Arm64OperandView> {
    let inner = token.trim().strip_prefix('[')?.strip_suffix(']')?.trim();
    let mut parts = inner.split(',').map(str::trim);
    let base_register_name = parts.next().and_then(semantic_register_from_text)?.register_name;
    let mut index_register_name = None;
    let mut displacement = 0;
    if let Some(second) = parts.next() {
        if second.starts_with('#') {
            let immediate = second.trim_start_matches('#');
            displacement = if let Some(hex) = immediate.strip_prefix("0x") {
                i32::from_str_radix(hex, 16).ok()?
            } else if let Some(hex) = immediate.strip_prefix("-0x") {
                -i32::from_str_radix(hex, 16).ok()?
            } else {
                immediate.parse::<i32>().ok()?
            };
        } else {
            index_register_name = semantic_register_from_text(second)?.register_name;
        }
    }
    Some(Arm64OperandView {
        kind: Arm64OperandKind::Memory,
        size_bits: 64,
        register_name: None,
        immediate: None,
        float: None,
        memory: Some(Arm64MemoryOperandView {
            base_register_name,
            index_register_name,
            displacement,
        }),
        vector_index: None,
        vas: None,
        shift: None,
        extender: None,
    })
}

fn semantic_operand_view(
    _disassembler: &arm64_capstone::Disassembler<'_>,
    operand: &ArchOperand,
) -> Arm64OperandView {
    let ArchOperand::Arm64Operand(op) = operand else {
        return Arm64OperandView {
            kind: Arm64OperandKind::Unsupported,
            size_bits: 0,
            register_name: None,
            immediate: None,
            float: None,
            memory: None,
            vector_index: None,
            vas: None,
            shift: None,
            extender: None,
        };
    };
    let shift = match op.shift {
        Arm64Shift::Lsl(value) => Some((Arm64ShiftKind::Lsl, value)),
        Arm64Shift::Msl(value) => Some((Arm64ShiftKind::Msl, value)),
        Arm64Shift::Lsr(value) => Some((Arm64ShiftKind::Lsr, value)),
        Arm64Shift::Asr(value) => Some((Arm64ShiftKind::Asr, value)),
        Arm64Shift::Ror(value) => Some((Arm64ShiftKind::Ror, value)),
        _ => None,
    };
    let extender = match op.ext {
        Arm64Extender::ARM64_EXT_INVALID => None,
        ext => Some(ext as u32),
    };
    let common = |kind: Arm64OperandKind| Arm64OperandView {
        kind,
        size_bits: 64,
        register_name: None,
        immediate: None,
        float: None,
        memory: None,
        vector_index: op.vector_index,
        vas: Some(op.vas as u32),
        shift,
        extender,
    };
    match op.op_type {
        Arm64OperandType::Reg(reg) => Arm64OperandView {
            size_bits: semantic_register_bits(reg.0),
            register_name: Some(semantic_register_name_from_id(reg.0)),
            ..common(Arm64OperandKind::Register)
        },
        Arm64OperandType::Imm(value) | Arm64OperandType::Cimm(value) => Arm64OperandView {
            size_bits: 64,
            immediate: Some(value),
            ..common(Arm64OperandKind::Immediate)
        },
        Arm64OperandType::Mem(mem) => Arm64OperandView {
            memory: Some(Arm64MemoryOperandView {
                base_register_name: if mem.base().0 == 0 {
                    None
                } else {
                    Some(semantic_register_name_from_id(mem.base().0))
                },
                index_register_name: if mem.index().0 == 0 {
                    None
                } else {
                    Some(semantic_register_name_from_id(mem.index().0))
                },
                displacement: mem.disp(),
            }),
            ..common(Arm64OperandKind::Memory)
        },
        Arm64OperandType::Fp(value) => Arm64OperandView {
            size_bits: 64,
            float: Some(value),
            ..common(Arm64OperandKind::Float)
        },
        Arm64OperandType::RegMrs(_)
        | Arm64OperandType::RegMsr(_)
        | Arm64OperandType::Pstate(_)
        | Arm64OperandType::Sys(_)
        | Arm64OperandType::Prefetch(_)
        | Arm64OperandType::Barrier(_) => common(Arm64OperandKind::System),
        Arm64OperandType::Invalid => common(Arm64OperandKind::Invalid),
    }
}

fn semantic_normalize_special_operands(instruction: &Insn, operand_views: &mut Vec<Arm64OperandView>) {
    let mnemonic = instruction.mnemonic().unwrap_or("").to_ascii_lowercase();
    let op_str = instruction.op_str().unwrap_or("");
    match mnemonic.as_str() {
        "mrs" => {
            if let Some(token) = op_str.split(',').next()
                && let Some(register) = semantic_register_from_text(token)
            {
                if let Some(existing) = operand_views
                    .iter_mut()
                    .find(|operand| operand.kind == Arm64OperandKind::Register)
                {
                    *existing = register;
                } else {
                    operand_views.insert(0, register);
                }
            }
        }
        "msr" => {
            if let Some(token) = op_str.rsplit(',').next()
                && let Some(register) = semantic_register_from_text(token)
            {
                if let Some(existing) = operand_views
                    .iter_mut()
                    .rev()
                    .find(|operand| operand.kind == Arm64OperandKind::Register)
                {
                    *existing = register;
                } else {
                    operand_views.push(register);
                }
            }
        }
        "ld1" => {
            if let Some(register_token) = op_str
                .split_once('{')
                .and_then(|(_, suffix)| suffix.split_once('}'))
                .map(|(register, suffix)| {
                    let lane_suffix = suffix
                        .trim_start()
                        .split(',')
                        .next()
                        .filter(|token| token.starts_with('[') && token.contains(']'))
                        .unwrap_or("");
                    format!("{}{}", register.trim(), lane_suffix)
                })
                && let Some(parsed) = semantic_register_from_text(&register_token)
            {
                if let Some(existing) = operand_views
                    .iter_mut()
                    .find(|operand| operand.kind == Arm64OperandKind::Register)
                {
                    let Arm64OperandView {
                        size_bits,
                        register_name,
                        vector_index,
                        ..
                    } = parsed;
                    existing.size_bits = size_bits;
                    existing.register_name = register_name;
                    existing.vector_index = vector_index;
                } else {
                    operand_views.insert(0, parsed);
                }
            }
            if let Some(memory_token) = op_str
                .split_once('[')
                .and_then(|(_, suffix)| suffix.split_once(']'))
                .map(|(memory, _)| format!("[{memory}]"))
                && !operand_views
                    .iter()
                    .any(|operand| operand.kind == Arm64OperandKind::Memory)
                && let Some(memory) = semantic_memory_from_text(&memory_token)
            {
                operand_views.push(memory);
            }
        }
        _ => {}
    }
}

fn semantic_instruction_view(
    disassembler: &arm64_capstone::Disassembler<'_>,
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Arm64InstructionView {
    let mut operand_views = operands
        .iter()
        .map(|operand| semantic_operand_view(disassembler, operand))
        .collect::<Vec<_>>();
    semantic_normalize_special_operands(instruction, &mut operand_views);
    Arm64InstructionView::new(
        machine,
        instruction.address(),
        instruction.mnemonic().unwrap_or(""),
        instruction.op_str().map(str::to_string),
        instruction.bytes().to_vec(),
        operand_views,
        condition_code,
    )
}

pub fn normalize_instruction_operands(
    disassembler: &arm64_capstone::Disassembler<'_>,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Vec<Operand> {
    let mut normalized = operands
        .iter()
        .filter_map(|operand| disassembler.normalize_operand(operand))
        .collect::<Vec<_>>();
    rewrite_raw_controlflow_immediates(instruction, &mut normalized);
    normalized
}

fn rewrite_raw_controlflow_immediates(instruction: &Insn, operands: &mut [Operand]) {
    let Some(index) = controlflow_immediate_operand_index(instruction) else {
        return;
    };
    let Some(Operand {
        kind: OperandKind::Immediate(immediate),
    }) = operands.get_mut(index)
    else {
        return;
    };
    immediate.value -= instruction.address() as i128;
}

fn controlflow_immediate_operand_index(instruction: &Insn) -> Option<usize> {
    let mnemonic = instruction.mnemonic().unwrap_or("");
    if matches!(mnemonic, "bl" | "b") || mnemonic.starts_with("b.") {
        return Some(0);
    }
    match mnemonic {
        "cbz" | "cbnz" => Some(1),
        "tbz" | "tbnz" => Some(2),
        _ => None,
    }
}

fn disassembly_text(instruction: &Insn) -> String {
    match instruction.op_str() {
        Some(op_str) if !op_str.is_empty() => {
            format!("{} {}", instruction.mnemonic().unwrap_or(""), op_str)
        }
        _ => instruction.mnemonic().unwrap_or("").to_string(),
    }
}

pub fn build_instruction(
    disassembler: &arm64_capstone::Disassembler<'_>,
    machine: Architecture,
    address: u64,
    cfg: &Graph,
) -> Result<Instruction, Error> {
    let instruction_container = disassembler.disassemble_instructions(address, 1)?;
    let instruction = instruction_container
        .iter()
        .next()
        .ok_or_else(|| Error::other(format!("0x{:x}: failed to disassemble instruction", address)))?;

    let instruction_mask = disassembler.get_instruction_chromosome_mask(instruction)?;
    let pattern = Chromosome::new(
        instruction.bytes().to_vec(),
        instruction_mask.clone(),
        cfg.config.clone(),
    )?
    .pattern();
    let mnemonic = instruction.mnemonic().unwrap_or("").to_ascii_lowercase();
    let operands = if matches!(mnemonic.as_str(), "mrs" | "msr") {
        Vec::new()
    } else {
        disassembler.get_instruction_operands(instruction).unwrap_or_default()
    };
    let is_jump = arm64_capstone::Disassembler::is_jump_instruction(instruction);
    let is_call = arm64_capstone::Disassembler::is_call_instruction(instruction);
    let is_return = arm64_capstone::Disassembler::is_return_instruction(instruction);
    let is_trap = arm64_capstone::Disassembler::is_trap_instruction(instruction);
    let is_conditional =
        is_jump && arm64_capstone::Disassembler::is_conditional_jump_instruction(instruction);
    let normalized_operands = if matches!(mnemonic.as_str(), "mrs" | "msr") {
        disassembler.parse_system_register_operands(instruction)
    } else {
        normalize_instruction_operands(disassembler, instruction, &operands)
    };
    let conditional_target = arm64_targets::conditional_jump_immutable(disassembler, instruction);
    let unconditional_target =
        arm64_targets::unconditional_jump_immutable(disassembler, instruction);
    let call_target = arm64_targets::call_immutable(disassembler, instruction);
    let executable_target =
        arm64_targets::instruction_executable_address(disassembler, instruction);
    let has_indirect_target = arm64_indirect::has_indirect_controlflow_target(instruction);
    let indirect_targets = if arm64_flow::should_collect_indirect_targets(has_indirect_target) {
        arm64_indirect::indirect_controlflow_targets(disassembler, instruction, cfg)
    } else {
        BTreeSet::new()
    };
    let function_targets = arm64_targets::function_targets(
        is_call,
        call_target,
        call_target.is_some_and(|addr| disassembler.is_executable_address(addr)),
        executable_target,
        executable_target.is_some_and(|addr| disassembler.has_function_prologue_pattern(addr)),
        &indirect_targets,
    );
    let edges = arm64_flow::instruction_edges(
        arm64_capstone::Disassembler::is_unconditional_jump_instruction(instruction),
        is_return,
        is_call,
        is_conditional,
    );
    let bytes = instruction.bytes().to_vec();
    let disassembly = disassembly_text(instruction);
    let condition_code = disassembler
        .get_instruction_condition_code(instruction)
        .ok()
        .flatten();
    let semantic_view =
        semantic_instruction_view(disassembler, machine, instruction, &operands, condition_code);
    let mut blinstruction =
        Instruction::create(instruction.address(), cfg.architecture, cfg.config.clone());

    blinstruction.is_jump = is_jump;
    blinstruction.is_call = is_call;
    blinstruction.is_return = is_return;
    blinstruction.is_trap = is_trap;
    blinstruction.is_conditional = is_conditional;
    blinstruction.edges = edges;
    blinstruction.bytes = bytes;
    blinstruction.chromosome_mask = instruction_mask;
    blinstruction.pattern = pattern;
    blinstruction.mnemonic = mnemonic;
    blinstruction.disassembly = disassembly;
    blinstruction.has_indirect_target = has_indirect_target;
    blinstruction.operands = normalized_operands;
    blinstruction.set_semantics_input(InstructionSemanticsInput::Arm64(semantic_view));

    if let Some(addr) = conditional_target {
        blinstruction.to.insert(addr);
    }
    if let Some(addr) = unconditional_target {
        blinstruction.to.insert(addr);
    }
    if blinstruction.is_jump {
        blinstruction.to.extend(indirect_targets.clone());
    }
    blinstruction.functions.extend(function_targets.clone());

    if blinstruction.is_jump || blinstruction.is_return || blinstruction.is_trap {
        blinstruction.edges = blinstruction.blocks().len();
    }

    if cfg.config.semantics.enabled {
        blinstruction.semantics = blinstruction.build_and_log_semantics();
    }

    Ok(blinstruction)
}
