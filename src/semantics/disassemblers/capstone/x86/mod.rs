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
use crate::semantics::architectures::x86::{
    X86InstructionView, X86MemoryOperandView, X86OperandKind, X86OperandView,
};
use capstone::Insn;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86OperandType, X86Reg};

#[cfg(test)]
mod tests;

fn leak_register_name(reg_id: u16) -> &'static str {
    Box::leak(reg_id_name(reg_id).into_boxed_str())
}

pub(crate) fn reg_id_name(reg_id: u16) -> String {
    match reg_id {
        x if x == X86Reg::X86_REG_AL as u16 => "al".to_string(),
        x if x == X86Reg::X86_REG_AH as u16 => "ah".to_string(),
        x if x == X86Reg::X86_REG_AX as u16 => "ax".to_string(),
        x if x == X86Reg::X86_REG_EAX as u16 => "eax".to_string(),
        x if x == X86Reg::X86_REG_RAX as u16 => "rax".to_string(),
        x if x == X86Reg::X86_REG_BL as u16 => "bl".to_string(),
        x if x == X86Reg::X86_REG_BH as u16 => "bh".to_string(),
        x if x == X86Reg::X86_REG_BX as u16 => "bx".to_string(),
        x if x == X86Reg::X86_REG_EBX as u16 => "ebx".to_string(),
        x if x == X86Reg::X86_REG_RBX as u16 => "rbx".to_string(),
        x if x == X86Reg::X86_REG_CL as u16 => "cl".to_string(),
        x if x == X86Reg::X86_REG_CH as u16 => "ch".to_string(),
        x if x == X86Reg::X86_REG_CX as u16 => "cx".to_string(),
        x if x == X86Reg::X86_REG_ECX as u16 => "ecx".to_string(),
        x if x == X86Reg::X86_REG_RCX as u16 => "rcx".to_string(),
        x if x == X86Reg::X86_REG_DL as u16 => "dl".to_string(),
        x if x == X86Reg::X86_REG_DH as u16 => "dh".to_string(),
        x if x == X86Reg::X86_REG_DX as u16 => "dx".to_string(),
        x if x == X86Reg::X86_REG_EDX as u16 => "edx".to_string(),
        x if x == X86Reg::X86_REG_RDX as u16 => "rdx".to_string(),
        x if x == X86Reg::X86_REG_SI as u16 => "si".to_string(),
        x if x == X86Reg::X86_REG_ESI as u16 => "esi".to_string(),
        x if x == X86Reg::X86_REG_RSI as u16 => "rsi".to_string(),
        x if x == X86Reg::X86_REG_DI as u16 => "di".to_string(),
        x if x == X86Reg::X86_REG_EDI as u16 => "edi".to_string(),
        x if x == X86Reg::X86_REG_RDI as u16 => "rdi".to_string(),
        x if x == X86Reg::X86_REG_R8 as u16 => "r8".to_string(),
        x if x == X86Reg::X86_REG_R9 as u16 => "r9".to_string(),
        x if x == X86Reg::X86_REG_R10 as u16 => "r10".to_string(),
        x if x == X86Reg::X86_REG_BP as u16 => "bp".to_string(),
        x if x == X86Reg::X86_REG_EBP as u16 => "ebp".to_string(),
        x if x == X86Reg::X86_REG_RBP as u16 => "rbp".to_string(),
        x if x == X86Reg::X86_REG_SP as u16 => "sp".to_string(),
        x if x == X86Reg::X86_REG_ESP as u16 => "esp".to_string(),
        x if x == X86Reg::X86_REG_RSP as u16 => "rsp".to_string(),
        x if x == X86Reg::X86_REG_IP as u16 => "ip".to_string(),
        x if x == X86Reg::X86_REG_EIP as u16 => "eip".to_string(),
        x if x == X86Reg::X86_REG_RIP as u16 => "rip".to_string(),
        x if x == X86Reg::X86_REG_XMM0 as u16 => "xmm0".to_string(),
        x if x == X86Reg::X86_REG_XMM1 as u16 => "xmm1".to_string(),
        x if x == X86Reg::X86_REG_XMM2 as u16 => "xmm2".to_string(),
        x if x == X86Reg::X86_REG_XMM3 as u16 => "xmm3".to_string(),
        x if x == X86Reg::X86_REG_XMM4 as u16 => "xmm4".to_string(),
        x if x == X86Reg::X86_REG_XMM5 as u16 => "xmm5".to_string(),
        x if x == X86Reg::X86_REG_XMM6 as u16 => "xmm6".to_string(),
        x if x == X86Reg::X86_REG_XMM7 as u16 => "xmm7".to_string(),
        x if x == X86Reg::X86_REG_MM0 as u16 => "mm0".to_string(),
        x if x == X86Reg::X86_REG_MM1 as u16 => "mm1".to_string(),
        x if x == X86Reg::X86_REG_MM2 as u16 => "mm2".to_string(),
        x if x == X86Reg::X86_REG_MM3 as u16 => "mm3".to_string(),
        x if x == X86Reg::X86_REG_MM4 as u16 => "mm4".to_string(),
        x if x == X86Reg::X86_REG_MM5 as u16 => "mm5".to_string(),
        x if x == X86Reg::X86_REG_MM6 as u16 => "mm6".to_string(),
        x if x == X86Reg::X86_REG_MM7 as u16 => "mm7".to_string(),
        x if x == X86Reg::X86_REG_ST0 as u16 => "st0".to_string(),
        x if x == X86Reg::X86_REG_ST1 as u16 => "st1".to_string(),
        x if x == X86Reg::X86_REG_ST2 as u16 => "st2".to_string(),
        x if x == X86Reg::X86_REG_ST3 as u16 => "st3".to_string(),
        x if x == X86Reg::X86_REG_ST4 as u16 => "st4".to_string(),
        x if x == X86Reg::X86_REG_ST5 as u16 => "st5".to_string(),
        x if x == X86Reg::X86_REG_ST6 as u16 => "st6".to_string(),
        x if x == X86Reg::X86_REG_ST7 as u16 => "st7".to_string(),
        _ => format!("reg_{}", reg_id),
    }
}

fn map_operand(operand: &ArchOperand) -> X86OperandView {
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
            register_name: Some(leak_register_name(reg.0)),
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
                base_register_name: (mem.base().0 != 0).then(|| leak_register_name(mem.base().0)),
                index_register_name: (mem.index().0 != 0).then(|| leak_register_name(mem.index().0)),
                scale: mem.scale(),
                displacement: mem.disp(),
                segment_register_name: (mem.segment().0 != 0)
                    .then(|| leak_register_name(mem.segment().0)),
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

pub(crate) fn instruction_view(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> X86InstructionView {
    X86InstructionView::new(
        machine,
        instruction.address(),
        instruction.mnemonic().unwrap_or(""),
        instruction.op_str().map(str::to_string),
        instruction.bytes().to_vec(),
        operands.iter().map(map_operand).collect(),
    )
}

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> InstructionSemantics {
    let view = instruction_view(machine, instruction, operands);
    architectures::x86::build(view).unwrap_or_else(|| {
        unsupported_fallthrough(machine, instruction, "x86 mnemonic not implemented")
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
