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
use std::io::{Error, ErrorKind};

use ::capstone::{Insn, arch::ArchOperand, arch::x86::X86OperandType};

use crate::{
    Architecture,
    controlflow::graph::Graph,
    controlflow::{Instruction, InstructionDetail, InstructionRecord, Operand, OperandKind},
    disassemblers::x86::{
        backends::capstone as x86_capstone, flow as x86_flow, indirect as x86_indirect,
        targets as x86_targets,
    },
    genetics::Chromosome,
    semantics::x86::{
        InstructionDetailX86, X86MemoryOperandView, X86OperandKind, X86OperandView,
    },
};

fn leak_register_name(name: String) -> &'static str {
    Box::leak(name.into_boxed_str())
}

fn semantic_register_name(name: String) -> String {
    if let Some(index) = name
        .strip_prefix("st(")
        .and_then(|suffix| suffix.strip_suffix(')'))
    {
        return format!("st{index}");
    }
    name
}

fn semantic_operand_view(
    disassembler: &x86_capstone::Disassembler<'_>,
    operand: &ArchOperand,
) -> X86OperandView {
    let ArchOperand::X86Operand(op) = operand else {
        return X86OperandView {
            kind: X86OperandKind::Unsupported,
            size_bits: 0,
            register_name: None,
            immediate: None,
            memory: None,
        };
    };
    let size_bits = (op.size as u16).saturating_mul(8);
    match op.op_type {
        X86OperandType::Reg(reg) => X86OperandView {
            kind: X86OperandKind::Register,
            size_bits,
            register_name: disassembler
                .register_name(reg)
                .map(semantic_register_name)
                .map(leak_register_name),
            immediate: None,
            memory: None,
        },
        X86OperandType::Imm(value) => X86OperandView {
            kind: X86OperandKind::Immediate,
            size_bits,
            register_name: None,
            immediate: Some(value),
            memory: None,
        },
        X86OperandType::Mem(mem) => X86OperandView {
            kind: X86OperandKind::Memory,
            size_bits,
            register_name: None,
            immediate: None,
            memory: Some(X86MemoryOperandView {
                base_register_name: disassembler
                    .register_name(mem.base())
                    .map(semantic_register_name)
                    .map(leak_register_name),
                index_register_name: disassembler
                    .register_name(mem.index())
                    .map(semantic_register_name)
                    .map(leak_register_name),
                scale: mem.scale(),
                displacement: mem.disp(),
                segment_register_name: disassembler
                    .register_name(mem.segment())
                    .map(semantic_register_name)
                    .map(leak_register_name),
            }),
        },
        X86OperandType::Invalid => X86OperandView {
            kind: X86OperandKind::Invalid,
            size_bits,
            register_name: None,
            immediate: None,
            memory: None,
        },
    }
}

fn semantic_instruction_view(
    disassembler: &x86_capstone::Disassembler<'_>,
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> InstructionDetailX86 {
    InstructionDetailX86::new(
        machine,
        instruction.address(),
        instruction.mnemonic().unwrap_or(""),
        instruction.op_str().map(str::to_string),
        instruction.bytes().to_vec(),
        operands
            .iter()
            .map(|operand| semantic_operand_view(disassembler, operand))
            .collect(),
    )
}

pub fn normalize_instruction_operands(
    disassembler: &x86_capstone::Disassembler<'_>,
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
    if !x86_flow::has_pc_relative_controlflow_immediate(
        x86_capstone::Disassembler::is_conditional_jump_instruction(instruction),
        x86_capstone::Disassembler::is_unconditional_jump_instruction(instruction),
        x86_capstone::Disassembler::is_call_instruction(instruction),
    ) {
        return;
    }
    let Some(Operand {
        kind: OperandKind::Immediate(immediate),
    }) = operands.get_mut(0)
    else {
        return;
    };
    let next_address = instruction.address() as i128 + instruction.bytes().len() as i128;
    immediate.value -= next_address;
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
    disassembler: &x86_capstone::Disassembler<'_>,
    machine: Architecture,
    address: u64,
    cfg: &Graph,
) -> Result<InstructionRecord, Error> {
    let instruction_container = disassembler.disassemble_instructions(address, 1)?;
    let instruction = instruction_container.iter().next().ok_or_else(|| {
        Error::new(
            ErrorKind::Other,
            format!("0x{:x}: failed to disassemble instruction", address),
        )
    })?;

    let instruction_mask = disassembler.get_instruction_chromosome_mask(instruction)?;
    let pattern = Chromosome::new(
        instruction.bytes().to_vec(),
        instruction_mask.clone(),
        cfg.config.clone(),
    )?
    .pattern();
    let operands = disassembler
        .get_instruction_operands(instruction)
        .unwrap_or_default();
    let is_jump = x86_capstone::Disassembler::is_jump_instruction(instruction);
    let is_call = x86_capstone::Disassembler::is_call_instruction(instruction);
    let is_return = x86_capstone::Disassembler::is_return_instruction(instruction);
    let is_trap = x86_capstone::Disassembler::is_trap_instruction(instruction);
    let is_conditional =
        is_jump && x86_capstone::Disassembler::is_conditional_jump_instruction(instruction);
    let conditional_target = x86_targets::conditional_jump_immutable(disassembler, instruction);
    let unconditional_target = x86_targets::unconditional_jump_immutable(disassembler, instruction);
    let call_target = x86_targets::call_immutable(disassembler, instruction);
    let executable_target = x86_targets::instruction_executable_address(disassembler, instruction);
    let has_indirect_target =
        x86_indirect::has_indirect_controlflow_target(disassembler, instruction);
    let indirect_targets = if has_indirect_target {
        x86_indirect::indirect_controlflow_targets(disassembler, instruction, cfg)
    } else {
        BTreeSet::new()
    };
    let function_targets = x86_targets::function_targets(
        is_call,
        call_target,
        call_target.is_some_and(|addr| disassembler.is_executable_address(addr)),
        executable_target,
        &indirect_targets,
    );
    let normalized_operands = normalize_instruction_operands(disassembler, instruction, &operands);
    let edges = x86_flow::instruction_edges(
        x86_capstone::Disassembler::is_unconditional_jump_instruction(instruction),
        is_return,
        is_conditional,
    );
    let bytes = instruction.bytes().to_vec();
    let mnemonic = instruction.mnemonic().unwrap_or("").to_string();
    let disassembly = disassembly_text(instruction);
    let semantic_view = semantic_instruction_view(disassembler, machine, instruction, &operands);
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
    blinstruction.set_instruction_detail(InstructionDetail::x86(semantic_view));

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
        blinstruction.edges = blinstruction.successors().len();
    }

    if cfg.config.semantics.enabled {
        blinstruction.semantics = blinstruction.build_and_log_semantics();
    }

    Ok(blinstruction)
}
