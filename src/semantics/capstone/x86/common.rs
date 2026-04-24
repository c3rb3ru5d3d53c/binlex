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

use crate::Architecture;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticDiagnostic, SemanticDiagnosticKind,
    SemanticEffect, SemanticExpression, SemanticLocation, SemanticOperationBinary,
    SemanticOperationCompare, SemanticOperationUnary, SemanticStatus, SemanticTerminator,
};
use capstone::Insn;
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86Reg;
use capstone::arch::x86::X86OperandType;

pub fn partial(
    terminator: SemanticTerminator,
    diagnostics: Vec<SemanticDiagnostic>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator,
        diagnostics,
    }
}

pub fn complete(
    terminator: SemanticTerminator,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

pub fn partial_with_effects(
    terminator: SemanticTerminator,
    diagnostics: Vec<SemanticDiagnostic>,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics,
    }
}

pub fn partial_intrinsic_fallback(
    instruction: &Insn,
    terminator: SemanticTerminator,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    partial_with_effects(
        terminator,
        vec![diagnostic(
            SemanticDiagnosticKind::ArchSpecific {
                name: "x86.intrinsic_fallback".to_string(),
            },
            format!(
                "0x{:x}: semantics use x86 intrinsic fallback ({})",
                instruction.address(),
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
        effects,
    )
}

pub fn diagnostic(kind: SemanticDiagnosticKind, message: impl Into<String>) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}

pub fn unsupported_fallthrough(instruction: &Insn, message: &str) -> InstructionSemantics {
    partial(
        SemanticTerminator::FallThrough,
        vec![diagnostic(
            SemanticDiagnosticKind::UnsupportedInstruction,
            format!(
                "0x{:x}: {} ({})",
                instruction.address(),
                message,
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
    )
}

pub fn unsupported_with_kind(
    instruction: &Insn,
    kind: SemanticDiagnosticKind,
    message: &str,
    terminator: SemanticTerminator,
) -> InstructionSemantics {
    partial(
        terminator,
        vec![diagnostic(
            kind,
            format!(
                "0x{:x}: {} ({})",
                instruction.address(),
                message,
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
    )
}

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

pub fn bool_const(value: bool) -> SemanticExpression {
    const_u64(value as u64, 1)
}

pub fn add(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Add,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn mul(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn sub(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Sub,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn xor(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Xor,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn and(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::And,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn or(left: SemanticExpression, right: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Binary {
        op: SemanticOperationBinary::Or,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub fn compare(
    op: SemanticOperationCompare,
    left: SemanticExpression,
    right: SemanticExpression,
) -> SemanticExpression {
    SemanticExpression::Compare {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits: 1,
    }
}

pub fn extract_bit(arg: SemanticExpression, lsb: u16) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(arg),
        lsb,
        bits: 1,
    }
}

pub fn extract_low_byte(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(arg),
        lsb: 0,
        bits: 8,
    }
}

pub fn not(arg: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(arg),
        bits,
    }
}

pub fn parity_flag(arg: SemanticExpression) -> SemanticExpression {
    let low_byte = extract_low_byte(arg);
    let pop_count = SemanticExpression::Unary {
        op: SemanticOperationUnary::PopCount,
        arg: Box::new(low_byte),
        bits: 8,
    };
    compare(
        SemanticOperationCompare::Eq,
        extract_bit(pop_count, 0),
        bool_const(false),
    )
}

pub fn auxiliary_flag(
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    extract_bit(xor(xor(left, right, bits), result, bits), 4)
}

pub fn add_overflow(
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    extract_bit(
        and(
            not(xor(left.clone(), right, bits), bits),
            xor(left, result, bits),
            bits,
        ),
        bits - 1,
    )
}

pub fn sub_overflow(
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    extract_bit(
        and(
            xor(left.clone(), right, bits),
            xor(left, result, bits),
            bits,
        ),
        bits - 1,
    )
}

pub fn memory_addr(
    machine: Architecture,
    base: Option<SemanticExpression>,
    index: Option<(SemanticExpression, i32)>,
    disp: i64,
) -> SemanticExpression {
    let bits = pointer_bits(machine);
    let mut result = base.unwrap_or_else(|| const_u64(0, bits));
    if let Some((index_expr, scale)) = index {
        let scaled = if scale > 1 {
            mul(index_expr, const_u64(scale as u64, bits), bits)
        } else {
            index_expr
        };
        result = add(result, scaled, bits);
    }
    if disp != 0 {
        let disp_expr = SemanticExpression::Const {
            value: disp as i128 as u128,
            bits,
        };
        result = add(result, disp_expr, bits);
    }
    result
}

pub fn operand_expr(machine: Architecture, operand: &ArchOperand) -> Option<SemanticExpression> {
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    let bits = bits_from_operand_size(op.size, machine);
    match op.op_type {
        X86OperandType::Reg(reg_id) => Some(reg_expr(reg_id.0, bits)),
        X86OperandType::Imm(imm) => Some(SemanticExpression::Const {
            value: imm as i128 as u128,
            bits,
        }),
        X86OperandType::Mem(mem) => {
            let base = if mem.base().0 == 0 {
                None
            } else {
                Some(reg_expr(mem.base().0, pointer_bits(machine)))
            };
            let index = if mem.index().0 == 0 {
                None
            } else {
                Some((reg_expr(mem.index().0, pointer_bits(machine)), mem.scale()))
            };
            let addr = memory_addr(machine, base, index, mem.disp());
            Some(SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits,
            })
        }
        _ => None,
    }
}

pub fn operand_location(machine: Architecture, operand: &ArchOperand) -> Option<SemanticLocation> {
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    let bits = bits_from_operand_size(op.size, machine);
    match op.op_type {
        X86OperandType::Reg(reg_id) => Some(reg(reg_id_name(reg_id.0), bits)),
        X86OperandType::Mem(mem) => {
            let base = if mem.base().0 == 0 {
                None
            } else {
                Some(reg_expr(mem.base().0, pointer_bits(machine)))
            };
            let index = if mem.index().0 == 0 {
                None
            } else {
                Some((reg_expr(mem.index().0, pointer_bits(machine)), mem.scale()))
            };
            let addr = memory_addr(machine, base, index, mem.disp());
            Some(SemanticLocation::Memory {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits,
            })
        }
        _ => None,
    }
}

pub fn condition_intrinsic(instruction: &Insn) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!(
            "x86.condition.{}",
            instruction.mnemonic().unwrap_or("unknown")
        ),
        args: Vec::new(),
        bits: 1,
    }
}

pub fn operation_intrinsic(
    instruction: &Insn,
    bits: u16,
    args: Vec<SemanticExpression>,
) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!("x86.{}", instruction.mnemonic().unwrap_or("unknown")),
        args,
        bits,
    }
}

fn condition_suffix(mnemonic: &str) -> Option<&str> {
    if let Some(suffix) = mnemonic.strip_prefix("cmov") {
        return Some(suffix);
    }
    if let Some(suffix) = mnemonic.strip_prefix("set") {
        return Some(suffix);
    }
    if let Some(suffix) = mnemonic.strip_prefix('j') {
        return Some(suffix);
    }
    None
}

pub fn condition_from_mnemonic(mnemonic: &str) -> Option<SemanticExpression> {
    let suffix = condition_suffix(mnemonic)?;
    let zf = flag_expr("zf");
    let cf = flag_expr("cf");
    let sf = flag_expr("sf");
    let of = flag_expr("of");
    let pf = flag_expr("pf");

    match suffix {
        "e" | "z" => Some(zf),
        "ne" | "nz" => Some(compare(SemanticOperationCompare::Eq, zf, bool_const(false))),
        "b" | "c" | "nae" => Some(cf),
        "ae" | "nb" | "nc" => Some(compare(SemanticOperationCompare::Eq, cf, bool_const(false))),
        "be" | "na" => Some(or(zf, cf, 1)),
        "a" | "nbe" => {
            let not_cf = compare(SemanticOperationCompare::Eq, cf, bool_const(false));
            let not_zf = compare(SemanticOperationCompare::Eq, zf, bool_const(false));
            Some(and(not_cf, not_zf, 1))
        }
        "s" => Some(sf),
        "ns" => Some(compare(SemanticOperationCompare::Eq, sf, bool_const(false))),
        "o" => Some(of),
        "no" => Some(compare(SemanticOperationCompare::Eq, of, bool_const(false))),
        "p" | "pe" => Some(pf),
        "np" | "po" => Some(compare(SemanticOperationCompare::Eq, pf, bool_const(false))),
        "l" | "nge" => Some(xor(sf, of, 1)),
        "ge" | "nl" => Some(compare(
            SemanticOperationCompare::Eq,
            xor(sf, of, 1),
            bool_const(false),
        )),
        "le" | "ng" => Some(or(zf, xor(sf, of, 1), 1)),
        "g" | "nle" => {
            let not_zf = compare(SemanticOperationCompare::Eq, zf, bool_const(false));
            let sf_eq_of = compare(
                SemanticOperationCompare::Eq,
                xor(sf, of, 1),
                bool_const(false),
            );
            Some(and(not_zf, sf_eq_of, 1))
        }
        _ => None,
    }
}
