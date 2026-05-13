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

use crate::ir::lir::{
    Lir, LirDiagnostic, LirDiagnosticKind, LirEffect, LirExpression, LirLocation,
    LirOperationBinary, LirOperationCast, LirOperationCompare, LirOperationUnary, LirStatus,
    LirTerminator,
};

pub(crate) fn zero_extend_to_bits(expression: LirExpression, bits: u16) -> LirExpression {
    if expression.bits() == bits {
        expression
    } else {
        LirExpression::Cast {
            op: LirOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(crate) fn reverse_bytes_in_chunks(
    src: LirExpression,
    bits: u16,
    chunk_bits: u16,
) -> Option<LirExpression> {
    if bits == 0 || chunk_bits == 0 || bits % chunk_bits != 0 || chunk_bits % 8 != 0 {
        return None;
    }
    let bytes_per_chunk = chunk_bits / 8;
    let chunk_count = bits / chunk_bits;
    let mut parts = Vec::with_capacity(bits as usize / 8);
    for chunk in (0..chunk_count).rev() {
        let base_byte = chunk * bytes_per_chunk;
        for byte in 0..bytes_per_chunk {
            parts.push(LirExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: (base_byte + byte) * 8,
                bits: 8,
            });
        }
    }
    Some(LirExpression::Concat { parts, bits })
}

pub(crate) fn sign_extend_to_bits(expression: LirExpression, bits: u16) -> LirExpression {
    if expression.bits() == bits {
        expression
    } else {
        LirExpression::Cast {
            op: LirOperationCast::SignExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(crate) fn truncate_to_bits(expression: LirExpression, bits: u16) -> LirExpression {
    if expression.bits() == bits {
        expression
    } else {
        LirExpression::Extract {
            arg: Box::new(expression),
            lsb: 0,
            bits,
        }
    }
}

pub(crate) fn location_bits(location: &LirLocation) -> u16 {
    match location {
        LirLocation::Register { bits, .. }
        | LirLocation::Flag { bits, .. }
        | LirLocation::ProgramCounter { bits }
        | LirLocation::Temporary { bits, .. }
        | LirLocation::Memory { bits, .. }
        | LirLocation::IndexedMemory { bits, .. }
        | LirLocation::StackMemory { bits, .. } => *bits,
    }
}

pub(crate) fn flag(name: &str) -> LirLocation {
    LirLocation::Flag {
        name: name.to_string(),
        bits: 1,
    }
}

pub(crate) fn flag_expr(name: &str) -> LirExpression {
    LirExpression::Read(Box::new(flag(name)))
}

pub(crate) fn set_flag(name: &str, expression: LirExpression) -> LirEffect {
    LirEffect::Set {
        dst: flag(name),
        expression,
    }
}

pub(crate) fn const_u64(value: u64, bits: u16) -> LirExpression {
    let masked = if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    };
    LirExpression::Const {
        value: masked as u128,
        bits,
    }
}

pub(crate) fn bitmask(bits: u16) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

pub(crate) fn bool_const(value: bool) -> LirExpression {
    const_u64(value as u64, 1)
}

pub(crate) fn binary(
    op: LirOperationBinary,
    left: LirExpression,
    right: LirExpression,
    bits: u16,
) -> LirExpression {
    LirExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub(crate) fn compare(
    op: LirOperationCompare,
    left: LirExpression,
    right: LirExpression,
) -> LirExpression {
    LirExpression::Compare {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits: 1,
    }
}

pub(crate) fn unary_not(arg: LirExpression) -> LirExpression {
    LirExpression::Unary {
        op: LirOperationUnary::Not,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(crate) fn sign_bit(arg: LirExpression) -> LirExpression {
    LirExpression::Extract {
        lsb: arg.bits() - 1,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(crate) fn arithmetic_flag_effects(
    op: LirOperationBinary,
    left: LirExpression,
    right: LirExpression,
    result: LirExpression,
) -> Vec<LirEffect> {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        LirOperationBinary::Add => compare(LirOperationCompare::Ult, result.clone(), left.clone()),
        LirOperationBinary::Sub => compare(LirOperationCompare::Uge, left.clone(), right.clone()),
        _ => bool_const(false),
    };

    let overflow = match op {
        LirOperationBinary::Add => binary(
            LirOperationBinary::And,
            unary_not(binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        LirOperationBinary::Sub => binary(
            LirOperationBinary::And,
            binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        _ => bool_const(false),
    };

    vec![
        set_flag("n", sign_result),
        set_flag(
            "z",
            compare(LirOperationCompare::Eq, result, const_u64(0, bits)),
        ),
        set_flag("c", carry),
        set_flag("v", overflow),
    ]
}

pub(crate) fn arithmetic_flag_values(
    op: LirOperationBinary,
    left: LirExpression,
    right: LirExpression,
    result: LirExpression,
) -> [LirExpression; 4] {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        LirOperationBinary::Add => compare(LirOperationCompare::Ult, result.clone(), left.clone()),
        LirOperationBinary::Sub => compare(LirOperationCompare::Uge, left.clone(), right.clone()),
        _ => bool_const(false),
    };

    let overflow = match op {
        LirOperationBinary::Add => binary(
            LirOperationBinary::And,
            unary_not(binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        LirOperationBinary::Sub => binary(
            LirOperationBinary::And,
            binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                LirOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        _ => bool_const(false),
    };

    [
        sign_result,
        compare(LirOperationCompare::Eq, result, const_u64(0, bits)),
        carry,
        overflow,
    ]
}

pub(crate) fn fp_compare_flag_values(
    left: LirExpression,
    right: LirExpression,
) -> [LirExpression; 4] {
    let unordered = compare(LirOperationCompare::Unordered, left.clone(), right.clone());
    [
        compare(LirOperationCompare::Olt, left.clone(), right.clone()),
        compare(LirOperationCompare::Oeq, left.clone(), right.clone()),
        binary(
            LirOperationBinary::Or,
            compare(LirOperationCompare::Oge, left.clone(), right.clone()),
            unordered.clone(),
            1,
        ),
        unordered,
    ]
}

pub(crate) fn condition_from_suffix(suffix: &str) -> Option<LirExpression> {
    let z = flag_expr("z");
    let n = flag_expr("n");
    let c = flag_expr("c");
    let v = flag_expr("v");

    Some(match suffix {
        "eq" => z,
        "ne" => unary_not(z),
        "hs" | "cs" => c,
        "lo" | "cc" => unary_not(c),
        "mi" => n,
        "pl" => unary_not(n),
        "vs" => v,
        "vc" => unary_not(v),
        "hi" => binary(LirOperationBinary::And, c, unary_not(flag_expr("z")), 1),
        "ls" => binary(LirOperationBinary::Or, unary_not(c), flag_expr("z"), 1),
        "ge" => compare(LirOperationCompare::Eq, n, v),
        "lt" => compare(LirOperationCompare::Ne, n, v),
        "gt" => binary(
            LirOperationBinary::And,
            unary_not(flag_expr("z")),
            compare(LirOperationCompare::Eq, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "le" => binary(
            LirOperationBinary::Or,
            flag_expr("z"),
            compare(LirOperationCompare::Ne, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "al" | "nv" => bool_const(true),
        _ => return None,
    })
}

pub(crate) fn condition_from_cc(cc: u64) -> Option<LirExpression> {
    let suffix = match cc {
        1 => "eq",
        2 => "ne",
        3 => "hs",
        4 => "lo",
        5 => "mi",
        6 => "pl",
        7 => "vs",
        8 => "vc",
        9 => "hi",
        10 => "ls",
        11 => "ge",
        12 => "lt",
        13 => "gt",
        14 => "le",
        15 | 16 => "al",
        _ => return None,
    };
    condition_from_suffix(suffix)
}

pub(crate) fn complete(terminator: LirTerminator, effects: Vec<LirEffect>) -> Lir {
    Lir {
        version: 1,
        status: LirStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

#[allow(dead_code)]
pub(crate) fn diagnostic(kind: LirDiagnosticKind, message: impl Into<String>) -> LirDiagnostic {
    LirDiagnostic {
        kind,
        message: message.into(),
    }
}
