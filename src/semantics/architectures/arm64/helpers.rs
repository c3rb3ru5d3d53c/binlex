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

use crate::semantics::{
    InstructionSemantics, SemanticDiagnostic, SemanticDiagnosticKind, SemanticEffect,
    SemanticExpression, SemanticLocation, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary, SemanticStatus, SemanticTerminator,
};

pub(crate) fn zero_extend_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(crate) fn reverse_bytes_in_chunks(
    src: SemanticExpression,
    bits: u16,
    chunk_bits: u16,
) -> Option<SemanticExpression> {
    if bits == 0 || chunk_bits == 0 || bits % chunk_bits != 0 || chunk_bits % 8 != 0 {
        return None;
    }
    let bytes_per_chunk = chunk_bits / 8;
    let chunk_count = bits / chunk_bits;
    let mut parts = Vec::with_capacity(bits as usize / 8);
    for chunk in (0..chunk_count).rev() {
        let base_byte = chunk * bytes_per_chunk;
        for byte in 0..bytes_per_chunk {
            parts.push(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: (base_byte + byte) * 8,
                bits: 8,
            });
        }
    }
    Some(SemanticExpression::Concat { parts, bits })
}

pub(crate) fn sign_extend_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(crate) fn truncate_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Extract {
            arg: Box::new(expression),
            lsb: 0,
            bits,
        }
    }
}

pub(crate) fn location_bits(location: &SemanticLocation) -> u16 {
    match location {
        SemanticLocation::Register { bits, .. }
        | SemanticLocation::Flag { bits, .. }
        | SemanticLocation::ProgramCounter { bits }
        | SemanticLocation::Temporary { bits, .. }
        | SemanticLocation::Memory { bits, .. } => *bits,
    }
}

pub(crate) fn flag(name: &str) -> SemanticLocation {
    SemanticLocation::Flag {
        name: name.to_string(),
        bits: 1,
    }
}

pub(crate) fn flag_expr(name: &str) -> SemanticExpression {
    SemanticExpression::Read(Box::new(flag(name)))
}

pub(crate) fn set_flag(name: &str, expression: SemanticExpression) -> SemanticEffect {
    SemanticEffect::Set {
        dst: flag(name),
        expression,
    }
}

pub(crate) fn const_u64(value: u64, bits: u16) -> SemanticExpression {
    let masked = if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    };
    SemanticExpression::Const {
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

pub(crate) fn bool_const(value: bool) -> SemanticExpression {
    const_u64(value as u64, 1)
}

pub(crate) fn binary(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    SemanticExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub(crate) fn compare(
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

pub(crate) fn unary_not(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(crate) fn sign_bit(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        lsb: arg.bits() - 1,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(crate) fn arithmetic_flag_effects(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
) -> Vec<SemanticEffect> {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        SemanticOperationBinary::Add => {
            compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
        }
        SemanticOperationBinary::Sub => {
            compare(SemanticOperationCompare::Uge, left.clone(), right.clone())
        }
        _ => bool_const(false),
    };

    let overflow = match op {
        SemanticOperationBinary::Add => binary(
            SemanticOperationBinary::And,
            unary_not(binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        SemanticOperationBinary::Sub => binary(
            SemanticOperationBinary::And,
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                SemanticOperationBinary::Xor,
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
            compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
        ),
        set_flag("c", carry),
        set_flag("v", overflow),
    ]
}

pub(crate) fn arithmetic_flag_values(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    result: SemanticExpression,
) -> [SemanticExpression; 4] {
    let bits = result.bits();
    let sign_left = sign_bit(left.clone());
    let sign_right = sign_bit(right.clone());
    let sign_result = sign_bit(result.clone());

    let carry = match op {
        SemanticOperationBinary::Add => {
            compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
        }
        SemanticOperationBinary::Sub => {
            compare(SemanticOperationCompare::Uge, left.clone(), right.clone())
        }
        _ => bool_const(false),
    };

    let overflow = match op {
        SemanticOperationBinary::Add => binary(
            SemanticOperationBinary::And,
            unary_not(binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            )),
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_result.clone(),
                1,
            ),
            1,
        ),
        SemanticOperationBinary::Sub => binary(
            SemanticOperationBinary::And,
            binary(
                SemanticOperationBinary::Xor,
                sign_left.clone(),
                sign_right.clone(),
                1,
            ),
            binary(
                SemanticOperationBinary::Xor,
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
        compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
        carry,
        overflow,
    ]
}

pub(crate) fn fp_compare_flag_values(
    left: SemanticExpression,
    right: SemanticExpression,
) -> [SemanticExpression; 4] {
    let unordered = compare(
        SemanticOperationCompare::Unordered,
        left.clone(),
        right.clone(),
    );
    [
        compare(SemanticOperationCompare::Olt, left.clone(), right.clone()),
        compare(SemanticOperationCompare::Oeq, left.clone(), right.clone()),
        binary(
            SemanticOperationBinary::Or,
            compare(SemanticOperationCompare::Oge, left.clone(), right.clone()),
            unordered.clone(),
            1,
        ),
        unordered,
    ]
}

pub(crate) fn condition_from_suffix(suffix: &str) -> Option<SemanticExpression> {
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
        "hi" => binary(
            SemanticOperationBinary::And,
            c,
            unary_not(flag_expr("z")),
            1,
        ),
        "ls" => binary(SemanticOperationBinary::Or, unary_not(c), flag_expr("z"), 1),
        "ge" => compare(SemanticOperationCompare::Eq, n, v),
        "lt" => compare(SemanticOperationCompare::Ne, n, v),
        "gt" => binary(
            SemanticOperationBinary::And,
            unary_not(flag_expr("z")),
            compare(SemanticOperationCompare::Eq, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "le" => binary(
            SemanticOperationBinary::Or,
            flag_expr("z"),
            compare(SemanticOperationCompare::Ne, flag_expr("n"), flag_expr("v")),
            1,
        ),
        "al" | "nv" => bool_const(true),
        _ => return None,
    })
}

pub(crate) fn condition_from_cc(cc: u64) -> Option<SemanticExpression> {
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

pub(crate) fn complete(
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

#[allow(dead_code)]
pub(crate) fn diagnostic(
    kind: SemanticDiagnosticKind,
    message: impl Into<String>,
) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}
