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

use std::collections::BTreeMap;

use capstone::{
    Insn, RegId,
    arch::ArchOperand,
    arch::arm64::{Arm64Extender, Arm64OperandType, Arm64Shift},
};
use serde_json::Value;

use crate::{
    controlflow::{
        FloatOperand, ImmediateOperand, MemoryOperand, Operand, OperandKind, RegisterOperand,
        SpecialOperand,
    },
    disassemblers::arm64::decoded::{
        Arm64DecodedMemoryOperand, Arm64DecodedOperand, canonical_register_family,
    },
};

use crate::disassemblers::arm64::disassembler::Disassembler;

impl<'disassembler> Disassembler<'disassembler> {
    pub(crate) fn register_name(&self, reg: RegId) -> Option<String> {
        if reg.0 == 0 {
            return None;
        }
        self.cs.reg_name(reg)
    }

    fn special_operand_fields() -> BTreeMap<String, Value> {
        BTreeMap::new()
    }

    pub(crate) fn parse_system_register_operands(&self, instruction: &Insn) -> Vec<Operand> {
        let mnemonic = instruction.mnemonic().unwrap_or("").to_ascii_lowercase();
        let parts: Vec<_> = instruction
            .op_str()
            .unwrap_or("")
            .split(',')
            .map(|part| part.trim())
            .filter(|part| !part.is_empty())
            .collect();

        match mnemonic.as_str() {
            "mrs" if parts.len() >= 2 => vec![
                Operand {
                    kind: OperandKind::Register(RegisterOperand {
                        name: parts[0].to_ascii_lowercase(),
                    }),
                },
                Operand {
                    kind: OperandKind::Special(SpecialOperand {
                        kind: "reg_mrs".to_string(),
                        fields: BTreeMap::from([(
                            "sysreg".to_string(),
                            Value::from(parts[1].to_string()),
                        )]),
                    }),
                },
            ],
            "msr" if parts.len() >= 2 => vec![
                Operand {
                    kind: OperandKind::Special(SpecialOperand {
                        kind: "reg_msr".to_string(),
                        fields: BTreeMap::from([(
                            "sysreg".to_string(),
                            Value::from(parts[0].to_string()),
                        )]),
                    }),
                },
                Operand {
                    kind: OperandKind::Register(RegisterOperand {
                        name: parts[1].to_ascii_lowercase(),
                    }),
                },
            ],
            _ => Vec::new(),
        }
    }

    pub(crate) fn normalize_operand(&self, operand: &ArchOperand) -> Option<Operand> {
        let ArchOperand::Arm64Operand(op) = operand else {
            return None;
        };
        let kind = match &op.op_type {
            Arm64OperandType::Reg(reg) => {
                let name = self.register_name(*reg)?;
                OperandKind::Register(RegisterOperand { name })
            }
            Arm64OperandType::Imm(value) | Arm64OperandType::Cimm(value) => {
                OperandKind::Immediate(ImmediateOperand {
                    value: *value as i128,
                })
            }
            Arm64OperandType::Mem(mem) => OperandKind::Memory(MemoryOperand {
                base: self.register_name(mem.base()),
                index: self.register_name(mem.index()),
                scale: None,
                displacement: mem.disp() as i64,
                space: None,
                segment: None,
            }),
            Arm64OperandType::Fp(value) => OperandKind::Float(FloatOperand { value: *value }),
            Arm64OperandType::RegMrs(sysreg) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("sysreg".to_string(), Value::from(format!("{:?}", sysreg)));
                OperandKind::Special(SpecialOperand {
                    kind: "reg_mrs".to_string(),
                    fields,
                })
            }
            Arm64OperandType::RegMsr(sysreg) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("sysreg".to_string(), Value::from(format!("{:?}", sysreg)));
                OperandKind::Special(SpecialOperand {
                    kind: "reg_msr".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Pstate(pstate) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("pstate".to_string(), Value::from(format!("{:?}", pstate)));
                OperandKind::Special(SpecialOperand {
                    kind: "pstate".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Sys(sys) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("sys".to_string(), Value::from(format!("{:?}", sys)));
                OperandKind::Special(SpecialOperand {
                    kind: "sys".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Prefetch(prefetch) => {
                let mut fields = Self::special_operand_fields();
                fields.insert(
                    "prefetch".to_string(),
                    Value::from(format!("{:?}", prefetch)),
                );
                OperandKind::Special(SpecialOperand {
                    kind: "prefetch".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Barrier(barrier) => {
                let mut fields = Self::special_operand_fields();
                fields.insert("barrier".to_string(), Value::from(format!("{:?}", barrier)));
                OperandKind::Special(SpecialOperand {
                    kind: "barrier".to_string(),
                    fields,
                })
            }
            Arm64OperandType::Invalid => {
                let fields = Self::special_operand_fields();
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
    ) -> Option<Arm64DecodedOperand> {
        let ArchOperand::Arm64Operand(op) = operand else {
            return None;
        };
        Some(match op.op_type {
            Arm64OperandType::Reg(reg) => {
                Arm64DecodedOperand::Register(canonical_register_family(&self.register_name(reg)?))
            }
            Arm64OperandType::Imm(value) | Arm64OperandType::Cimm(value) => {
                Arm64DecodedOperand::Immediate(value)
            }
            Arm64OperandType::Mem(mem) => Arm64DecodedOperand::Memory(Arm64DecodedMemoryOperand {
                base: self
                    .register_name(mem.base())
                    .map(|name| canonical_register_family(&name)),
                index: self
                    .register_name(mem.index())
                    .map(|name| canonical_register_family(&name)),
                displacement: mem.disp() as i64,
                shift_amount: match op.shift {
                    Arm64Shift::Lsl(value) => Some(value),
                    _ => None,
                },
                extender: match op.ext {
                    Arm64Extender::ARM64_EXT_UXTW => Some("uxtw".to_string()),
                    Arm64Extender::ARM64_EXT_SXTW => Some("sxtw".to_string()),
                    Arm64Extender::ARM64_EXT_UXTX => Some("uxtx".to_string()),
                    Arm64Extender::ARM64_EXT_SXTX => Some("sxtx".to_string()),
                    _ => None,
                },
                operand_size_bits: None,
            }),
            _ => Arm64DecodedOperand::Invalid,
        })
    }

    pub(crate) fn decode_instruction_operand(
        &self,
        instruction: &Insn,
        index: usize,
    ) -> Option<Arm64DecodedOperand> {
        let operand = self.get_instruction_operand(instruction, index).ok()?;
        self.decode_history_operand(&operand)
    }

    pub(crate) fn has_function_prologue_pattern(&self, address: u64) -> bool {
        let Ok(instructions) = self.disassemble_instructions(address, 2) else {
            return false;
        };
        if instructions.len() < 2 {
            return false;
        }

        let first = &instructions[0];
        let second = &instructions[1];

        if first.mnemonic().unwrap_or("") != "stp" || second.mnemonic().unwrap_or("") != "mov" {
            return false;
        }
        matches!(self.decode_instruction_operand(first, 0), Some(Arm64DecodedOperand::Register(dst0)) if dst0 == "x29")
            && matches!(self.decode_instruction_operand(first, 1), Some(Arm64DecodedOperand::Register(dst1)) if dst1 == "x30")
            && matches!(
                self.decode_instruction_operand(first, 2),
                Some(Arm64DecodedOperand::Memory(_))
            )
            && matches!(self.decode_instruction_operand(second, 0), Some(Arm64DecodedOperand::Register(dst)) if dst == "x29")
            && matches!(self.decode_instruction_operand(second, 1), Some(Arm64DecodedOperand::Register(src)) if src == "sp")
    }
}
