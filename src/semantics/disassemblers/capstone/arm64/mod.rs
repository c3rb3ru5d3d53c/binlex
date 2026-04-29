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
use crate::semantics::{
    InstructionEncoding, InstructionSemantics, SemanticDiagnostic, SemanticDiagnosticKind,
    SemanticStatus, SemanticTerminator,
};
use crate::semantics::architectures;
use crate::semantics::architectures::arm64::{
    Arm64InstructionView, Arm64MemoryOperandView, Arm64OperandKind, Arm64OperandView,
};
use crate::semantics::architectures::arm64::operand::Arm64ShiftKind;
use capstone::Insn;
use capstone::arch::ArchOperand;
use capstone::arch::arm64::{Arm64Extender, Arm64OperandType, Arm64Reg, Arm64Shift};
use capstone::RegId;

#[cfg(test)]
mod tests;

fn register_name(reg_id: u16) -> String {
    format!("reg_{}", reg_id)
}

fn register_bits(reg_id: u16) -> u16 {
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

fn map_operand(operand: &ArchOperand) -> Arm64OperandView {
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
            size_bits: register_bits(reg.0),
            register_name: Some(register_name(reg.0)),
            ..common(Arm64OperandKind::Register)
        },
        Arm64OperandType::Imm(value) | Arm64OperandType::Cimm(value) => Arm64OperandView {
            size_bits: 64,
            immediate: Some(value),
            ..common(Arm64OperandKind::Immediate)
        },
        Arm64OperandType::Mem(mem) => Arm64OperandView {
            memory: Some(Arm64MemoryOperandView {
                base_register_name: (mem.base().0 != 0).then(|| register_name(mem.base().0)),
                index_register_name: (mem.index().0 != 0).then(|| register_name(mem.index().0)),
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

fn named_register(reg_id: u16, size_bits: u16, vector_index: Option<u32>) -> Arm64OperandView {
    Arm64OperandView {
        kind: Arm64OperandKind::Register,
        size_bits,
        register_name: Some(register_name(reg_id)),
        immediate: None,
        float: None,
        memory: None,
        vector_index,
        vas: None,
        shift: None,
        extender: None,
    }
}

fn parse_indexed_register(token: &str) -> Option<(char, u16)> {
    let normalized = token.trim().to_ascii_lowercase();
    let mut chars = normalized.chars();
    let prefix = chars.next()?;
    let number = chars.as_str().parse::<u16>().ok()?;
    Some((prefix, number))
}

fn register_from_text(token: &str) -> Option<Arm64OperandView> {
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
    match base {
        "sp" => Some(named_register(Arm64Reg::ARM64_REG_SP as u16, 64, lane_index)),
        "wsp" => Some(named_register(Arm64Reg::ARM64_REG_WSP as u16, 32, lane_index)),
        "fp" => Some(named_register(Arm64Reg::ARM64_REG_FP as u16, 64, lane_index)),
        "lr" => Some(named_register(Arm64Reg::ARM64_REG_LR as u16, 64, lane_index)),
        "xzr" => Some(named_register(Arm64Reg::ARM64_REG_XZR as u16, 64, lane_index)),
        "wzr" => Some(named_register(Arm64Reg::ARM64_REG_WZR as u16, 32, lane_index)),
        _ => {
            let (prefix, number) = parse_indexed_register(base)?;
            match prefix {
                'x' if number <= 28 => Some(named_register(
                    (Arm64Reg::ARM64_REG_X0 + number as u32) as u16,
                    64,
                    lane_index,
                )),
                'x' if number == 29 => Some(named_register(
                    Arm64Reg::ARM64_REG_FP as u16,
                    64,
                    lane_index,
                )),
                'x' if number == 30 => Some(named_register(
                    Arm64Reg::ARM64_REG_LR as u16,
                    64,
                    lane_index,
                )),
                'w' if number <= 30 => Some(named_register(
                    (Arm64Reg::ARM64_REG_W0 + number as u32) as u16,
                    32,
                    lane_index,
                )),
                'v' if number <= 31 => Some(named_register(
                    (Arm64Reg::ARM64_REG_V0 + number as u32) as u16,
                    128,
                    lane_index,
                )),
                'q' if number <= 31 => Some(named_register(
                    (Arm64Reg::ARM64_REG_Q0 + number as u32) as u16,
                    128,
                    lane_index,
                )),
                'd' if number <= 31 => Some(named_register(
                    (Arm64Reg::ARM64_REG_D0 + number as u32) as u16,
                    64,
                    lane_index,
                )),
                's' if number <= 31 => Some(named_register(
                    (Arm64Reg::ARM64_REG_S0 + number as u32) as u16,
                    32,
                    lane_index,
                )),
                'h' if number <= 31 => Some(named_register(
                    (Arm64Reg::ARM64_REG_H0 + number as u32) as u16,
                    16,
                    lane_index,
                )),
                'b' if number <= 31 => Some(named_register(
                    (Arm64Reg::ARM64_REG_B0 + number as u32) as u16,
                    8,
                    lane_index,
                )),
                _ => None,
            }
        }
    }
}

fn memory_from_text(token: &str) -> Option<Arm64OperandView> {
    let inner = token
        .trim()
        .strip_prefix('[')?
        .strip_suffix(']')?
        .trim();
    let mut parts = inner.split(',').map(str::trim);
    let base_register_name = parts.next().and_then(register_from_text)?.register_name;
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
            index_register_name = register_from_text(second)?.register_name;
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

fn normalize_special_operands(instruction: &Insn, operand_views: &mut Vec<Arm64OperandView>) {
    let mnemonic = instruction.mnemonic().unwrap_or("").to_ascii_lowercase();
    let op_str = instruction.op_str().unwrap_or("");
    match mnemonic.as_str() {
        "mrs" => {
            if !operand_views.iter().any(|operand| operand.kind == Arm64OperandKind::Register) {
                if let Some(token) = op_str.split(',').next() {
                    if let Some(register) = register_from_text(token) {
                        operand_views.insert(0, register);
                    }
                }
            }
        }
        "msr" => {
            if !operand_views.iter().any(|operand| operand.kind == Arm64OperandKind::Register) {
                if let Some(token) = op_str.rsplit(',').next() {
                    if let Some(register) = register_from_text(token) {
                        operand_views.push(register);
                    }
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
            {
                if let Some(parsed) = register_from_text(&register_token) {
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
            }
            if let Some(memory_token) = op_str
                .split_once('[')
                .and_then(|(_, suffix)| suffix.split_once(']'))
                .map(|(memory, _)| format!("[{memory}]"))
            {
                if !operand_views
                    .iter()
                    .any(|operand| operand.kind == Arm64OperandKind::Memory)
                {
                    if let Some(memory) = memory_from_text(&memory_token) {
                        operand_views.push(memory);
                    }
                }
            }
        }
        _ => {}
    }
}

pub(crate) fn instruction_view(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> Arm64InstructionView {
    let mut operand_views = operands.iter().map(map_operand).collect::<Vec<_>>();
    normalize_special_operands(instruction, &mut operand_views);
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

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> InstructionSemantics {
    let view = instruction_view(machine, instruction, operands, condition_code);
    architectures::arm64::build(view).unwrap_or_else(|| {
        unsupported_fallthrough(machine, instruction, "arm64 mnemonic not implemented")
    })
}

fn diagnostic(kind: SemanticDiagnosticKind, message: impl Into<String>) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}

fn instruction_encoding(machine: Architecture, instruction: &Insn) -> InstructionEncoding {
    let mnemonic = instruction.mnemonic().unwrap_or("unknown").to_string();
    let disassembly = match instruction.op_str() {
        Some(op_str) if !op_str.is_empty() => format!("{mnemonic} {op_str}"),
        _ => mnemonic.clone(),
    };
    InstructionEncoding {
        architecture: machine.to_string(),
        mnemonic,
        disassembly,
        address: instruction.address(),
        bytes: instruction.bytes().to_vec(),
    }
}

fn unsupported_fallthrough(
    machine: Architecture,
    instruction: &Insn,
    message: &str,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        abi: None,
        encoding: Some(instruction_encoding(machine, instruction)),
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: SemanticTerminator::FallThrough,
        diagnostics: vec![diagnostic(
            SemanticDiagnosticKind::UnsupportedInstruction,
            format!(
                "0x{:x}: {} ({})",
                instruction.address(),
                message,
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
    }
}
