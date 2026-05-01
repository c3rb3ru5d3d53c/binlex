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

use ::capstone::{Insn, arch::ArchOperand, arch::arm64::Arm64OperandType};

use crate::disassemblers::arm64::{backends::capstone as arm64_capstone, flow as arm64_flow};

pub fn function_targets(
    is_call: bool,
    call_target: Option<u64>,
    call_target_is_executable: bool,
    executable_target: Option<u64>,
    executable_target_is_function_candidate: bool,
    indirect_targets: &BTreeSet<u64>,
) -> BTreeSet<u64> {
    let mut function_targets = BTreeSet::new();
    if call_target_is_executable {
        if let Some(addr) = call_target {
            function_targets.insert(addr);
        }
    }
    if is_call {
        function_targets.extend(indirect_targets.iter().copied());
    }
    if executable_target_is_function_candidate {
        if let Some(addr) = executable_target {
            function_targets.insert(addr);
        }
    }
    function_targets
}

pub fn operand_immutable(op: &ArchOperand) -> Option<u64> {
    if let ArchOperand::Arm64Operand(op) = op {
        match op.op_type {
            Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => return Some(imm as u64),
            _ => {}
        }
    }
    None
}

pub fn call_immutable(
    disassembler: &arm64_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    if arm64_capstone::Disassembler::is_call_instruction(instruction) {
        let operand = disassembler.get_instruction_operand(instruction, 0).ok()?;
        return operand_immutable(&operand);
    }
    None
}

pub fn conditional_jump_immutable(
    disassembler: &arm64_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    if !arm64_capstone::Disassembler::is_conditional_jump_instruction(instruction) {
        return None;
    }
    let index = arm64_flow::conditional_target_operand_index(instruction.mnemonic().unwrap_or(""));
    let operand = disassembler
        .get_instruction_operand(instruction, index)
        .ok()?;
    operand_immutable(&operand)
}

pub fn unconditional_jump_immutable(
    disassembler: &arm64_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    let operand_index = arm64_flow::unconditional_target_operand_index(
        arm64_capstone::Disassembler::is_unconditional_jump_instruction(instruction),
    )?;
    let operand = disassembler
        .get_instruction_operand(instruction, operand_index)
        .ok()?;
    operand_immutable(&operand)
}

pub fn instruction_executable_address(
    disassembler: &arm64_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    let operand_index = arm64_flow::load_address_operand_index(
        arm64_capstone::Disassembler::is_load_address_instruction(instruction),
    )?;
    let operand = disassembler
        .get_instruction_operand(instruction, operand_index)
        .ok()?;
    let addr = operand_immutable(&operand)?;
    disassembler.is_executable_address(addr).then_some(addr)
}
