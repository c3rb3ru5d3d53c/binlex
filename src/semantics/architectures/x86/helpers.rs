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
    InstructionSemantics, SemanticDiagnostic, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticOperationBinary, SemanticOperationCompare,
    SemanticOperationUnary, SemanticStatus, SemanticTerminator,
};

pub use crate::semantics::SemanticDiagnosticKind;

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

fn extract_low_byte(arg: SemanticExpression) -> SemanticExpression {
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

pub fn partial(
    terminator: SemanticTerminator,
    diagnostics: Vec<SemanticDiagnostic>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        abi: None,
        encoding: None,
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
        abi: None,
        encoding: None,
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
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics,
    }
}

pub fn diagnostic(
    kind: crate::semantics::SemanticDiagnosticKind,
    message: impl Into<String>,
) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}
