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

use std::{
    collections::BTreeMap,
    io::{Error, ErrorKind},
};

use capstone::{
    Insn, RegId,
    arch::ArchOperand,
    arch::x86::{X86OpMem, X86OperandType},
};
use serde_json::Value;

use crate::{
    controlflow::{
        ImmediateOperand, MemoryOperand, Operand, OperandKind, RegisterOperand, SpecialOperand,
    },
    disassemblers::x86::decoded::{
        X86DecodedMemoryOperand, X86DecodedOperand, canonical_register_name,
    },
    genetics::Chromosome,
};

use crate::disassemblers::x86::disassembler::Disassembler;

impl<'disassembler> Disassembler<'disassembler> {
    pub(crate) fn register_name(&self, reg: RegId) -> Option<String> {
        if reg.0 == 0 {
            return None;
        }
        self.cs.reg_name(reg)
    }

    fn normalize_memory_operand(&self, mem: X86OpMem) -> MemoryOperand {
        MemoryOperand {
            base: self.register_name(mem.base()),
            index: self.register_name(mem.index()),
            scale: Some(mem.scale()),
            displacement: mem.disp(),
            space: None,
            segment: self.register_name(mem.segment()),
        }
    }

    pub(crate) fn normalize_operand(&self, operand: &ArchOperand) -> Option<Operand> {
        let ArchOperand::X86Operand(op) = operand else {
            return None;
        };
        let kind = match op.op_type {
            X86OperandType::Reg(reg) => OperandKind::Register(RegisterOperand {
                name: self.register_name(reg)?,
            }),
            X86OperandType::Imm(value) => OperandKind::Immediate(ImmediateOperand {
                value: value as i128,
            }),
            X86OperandType::Mem(mem) => OperandKind::Memory(self.normalize_memory_operand(mem)),
            X86OperandType::Invalid => {
                let mut fields = BTreeMap::new();
                fields.insert("size".to_string(), Value::from(op.size));
                OperandKind::Special(SpecialOperand {
                    kind: "invalid".to_string(),
                    fields,
                })
            }
        };
        Some(Operand { kind })
    }

    pub(crate) fn decode_history_operand(
        &self,
        operand: &ArchOperand,
    ) -> Option<X86DecodedOperand> {
        let ArchOperand::X86Operand(op) = operand else {
            return None;
        };
        Some(match op.op_type {
            X86OperandType::Reg(reg) => X86DecodedOperand::Register(
                canonical_register_name(&self.register_name(reg)?).to_string(),
            ),
            X86OperandType::Imm(value) => X86DecodedOperand::Immediate(value),
            X86OperandType::Mem(mem) => X86DecodedOperand::Memory(X86DecodedMemoryOperand {
                base: self
                    .register_name(mem.base())
                    .map(|name| canonical_register_name(&name).to_string()),
                index: self
                    .register_name(mem.index())
                    .map(|name| canonical_register_name(&name).to_string()),
                scale: mem.scale(),
                displacement: mem.disp(),
                operand_size: op.size as usize,
            }),
            X86OperandType::Invalid => X86DecodedOperand::Invalid {
                size: op.size as usize,
            },
        })
    }

    pub(crate) fn decode_instruction_operand(
        &self,
        instruction: &Insn,
        index: usize,
    ) -> Option<X86DecodedOperand> {
        let operand = self.get_instruction_operand(instruction, index).ok()?;
        self.decode_history_operand(&operand)
    }

    pub fn get_operand_mem(operand: &ArchOperand) -> Option<X86OpMem> {
        if let ArchOperand::X86Operand(operand) = operand
            && let X86OperandType::Mem(mem) = operand.op_type
        {
            return Some(mem);
        }
        None
    }

    pub fn get_instruction_total_operand_size(&self, instruction: &Insn) -> Result<usize, Error> {
        let operands = self.get_instruction_operands(instruction)?;
        let mut result = 0usize;
        for operand in operands {
            match operand {
                ArchOperand::X86Operand(op) => {
                    result += op.size as usize;
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "unsupported operand architecture",
                    ));
                }
            }
        }
        Ok(result)
    }

    pub fn get_instruction_pattern(&self, instruction: &Insn) -> Result<String, Error> {
        let mask = self.get_instruction_chromosome_mask(instruction)?;
        Chromosome::new(instruction.bytes().to_vec(), mask, self.config.clone())
            .map(|c| c.pattern())
    }
}
