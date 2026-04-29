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

extern crate capstone;

#[path = "common/addressing.rs"]
mod addressing_helpers;
#[path = "common/build.rs"]
mod build_helpers;
#[path = "common/conditions.rs"]
mod condition_helpers;
#[path = "common/expressions.rs"]
mod expression_helpers;

use crate::Architecture;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticDiagnostic, SemanticDiagnosticKind,
    SemanticEffect, SemanticExpression, SemanticLocation, SemanticOperationBinary,
    SemanticOperationCompare, SemanticOperationUnary, SemanticStatus, SemanticTerminator,
};
use capstone::Insn;
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg;

pub use addressing_helpers::*;
pub use build_helpers::*;
pub use condition_helpers::*;
pub use expression_helpers::*;

pub fn pointer_bits(machine: Architecture) -> u16 {
    match machine {
        Architecture::AMD64 => 64,
        Architecture::I386 => 32,
        _ => 64,
    }
}

pub fn bits_from_operand_size(size: u8, machine: Architecture) -> u16 {
    let bits = (size as u16) * 8;
    if bits == 0 {
        pointer_bits(machine)
    } else {
        bits
    }
}

pub fn flag(name: &str) -> SemanticLocation {
    SemanticLocation::Flag {
        name: name.to_string(),
        bits: 1,
    }
}

pub fn flag_expr(name: &str) -> SemanticExpression {
    SemanticExpression::Read(Box::new(flag(name)))
}

pub fn location_bits(location: &SemanticLocation) -> u16 {
    match location {
        SemanticLocation::Register { bits, .. } => *bits,
        SemanticLocation::Flag { bits, .. } => *bits,
        SemanticLocation::ProgramCounter { bits } => *bits,
        SemanticLocation::Temporary { bits, .. } => *bits,
        SemanticLocation::Memory { bits, .. } => *bits,
    }
}

pub fn reg(name: impl Into<String>, bits: u16) -> SemanticLocation {
    SemanticLocation::Register {
        name: name.into(),
        bits,
    }
}

pub fn reg_id_name(reg_id: u16) -> String {
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
        _ => format!("reg_{}", reg_id),
    }
}

pub fn reg_expr(reg_id: u16, bits: u16) -> SemanticExpression {
    SemanticExpression::Read(Box::new(reg(reg_id_name(reg_id), bits)))
}

pub fn const_u64(value: u64, bits: u16) -> SemanticExpression {
    SemanticExpression::Const {
        value: value as u128,
        bits,
    }
}
