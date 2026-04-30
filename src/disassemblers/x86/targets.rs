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

use ::capstone::{
    Insn, RegId, arch::ArchOperand, arch::x86::X86OperandType, arch::x86::X86Reg::X86_REG_RIP,
};

use crate::disassemblers::x86::{
    backends::capstone as x86_capstone, decoded::X86DecodedOperand, flow as x86_flow,
};

pub fn function_targets(
    is_call: bool,
    call_target: Option<u64>,
    call_target_is_executable: bool,
    executable_target: Option<u64>,
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
    if let Some(addr) = executable_target {
        function_targets.insert(addr);
    }
    function_targets
}

pub fn operand_immutable(op: &ArchOperand) -> Option<u64> {
    if let ArchOperand::X86Operand(op) = op
        && let X86OperandType::Imm(imm) = op.op_type
    {
        return Some(imm as u64);
    }
    None
}

pub fn jump_immutable(disassembler: &x86_capstone::Disassembler<'_>, instruction: &Insn) -> Option<u64> {
    let operand_index = x86_flow::controlflow_target_operand_index(
        x86_capstone::Disassembler::is_jump_instruction(instruction),
        false,
    )?;
    let operand = disassembler.get_instruction_operand(instruction, operand_index).ok()?;
    operand_immutable(&operand)
}

pub fn conditional_jump_immutable(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    if x86_capstone::Disassembler::is_conditional_jump_instruction(instruction) {
        let operand = disassembler.get_instruction_operand(instruction, 0).ok()?;
        return operand_immutable(&operand);
    }
    None
}

pub fn unconditional_jump_immutable(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    if x86_capstone::Disassembler::is_unconditional_jump_instruction(instruction) {
        let operand = disassembler.get_instruction_operand(instruction, 0).ok()?;
        return operand_immutable(&operand);
    }
    None
}

pub fn call_immutable(disassembler: &x86_capstone::Disassembler<'_>, instruction: &Insn) -> Option<u64> {
    if x86_capstone::Disassembler::is_call_instruction(instruction) {
        let operand = disassembler.get_instruction_operand(instruction, 0).ok()?;
        return operand_immutable(&operand);
    }
    None
}

pub fn instruction_executable_address(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
) -> Option<u64> {
    if !x86_capstone::Disassembler::is_load_address_instruction(instruction) {
        return None;
    }
    let operands = disassembler.get_instruction_operands(instruction).ok()?;
    for operand in operands {
        let Some(decoded) = disassembler.decode_history_operand(&operand) else {
            continue;
        };
        if let X86DecodedOperand::Memory(mem) = decoded {
            let Some(address) = x86_flow::load_address_target_from_memory(
                instruction.address(),
                instruction.bytes().len(),
                mem.base.as_deref(),
                mem.index.as_deref(),
                mem.displacement,
            ) else {
                continue;
            };
            if !disassembler.is_executable_address(address) {
                continue;
            }
            return Some(address);
        }
    }
    None
}

pub fn resolve_jump_table_base(
    disassembler: &x86_capstone::Disassembler<'_>,
    instruction: &Insn,
    mem_base: RegId,
    displacement: i64,
    history: &[crate::disassemblers::x86::decoded::X86DecodedInstruction],
    resolve_register_value: impl Fn(&str, &[crate::disassemblers::x86::decoded::X86DecodedInstruction]) -> Option<u64>,
) -> Option<u64> {
    if mem_base == RegId(0) {
        return Some(displacement as u64);
    }
    if mem_base == RegId(X86_REG_RIP as u16) {
        return Some(
            (instruction.address() as i64 + displacement + instruction.bytes().len() as i64) as u64,
        );
    }
    let register = disassembler.register_name(mem_base)?;
    resolve_register_value(crate::disassemblers::x86::decoded::canonical_register_name(&register), history)
}

pub fn jump_table_entry_size(machine: crate::Architecture, scale: usize, operand_size: usize) -> usize {
    let pointer_size = match machine {
        crate::Architecture::AMD64 => 8,
        crate::Architecture::I386 => 4,
        _ => return 0,
    };

    if operand_size == pointer_size || operand_size == 4 {
        return operand_size;
    }
    if scale == pointer_size || scale == 4 {
        return scale;
    }
    0
}
