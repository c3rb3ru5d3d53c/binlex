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

use crate::semantics::cil::InstructionDetailCil;
use crate::semantics::{
    Semantic, SemanticExpression, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator,
};

use super::super::helpers::common::{
    binary, bool_to_i64, compare, complete_with_effects, pop_stack, push_effects,
    push_runtime_binary_intrinsic, push_runtime_unary_intrinsic, unary,
};

pub(crate) fn build(instruction: &InstructionDetailCil) -> Option<Semantic> {
    match instruction.mnemonic_text() {
        "add" => simple_binary(SemanticOperationBinary::Add),
        "add.ovf" | "add.ovf.un" => Some(push_runtime_binary_intrinsic(instruction, "cil.add.ovf")),
        "mul" => simple_binary(SemanticOperationBinary::Mul),
        "mul.ovf" | "mul.ovf.un" => Some(push_runtime_binary_intrinsic(instruction, "cil.mul.ovf")),
        "div" => simple_binary(SemanticOperationBinary::SDiv),
        "div.un" => simple_binary(SemanticOperationBinary::UDiv),
        "and" => simple_binary(SemanticOperationBinary::And),
        "or" => simple_binary(SemanticOperationBinary::Or),
        "xor" => simple_binary(SemanticOperationBinary::Xor),
        "sub" => simple_binary(SemanticOperationBinary::Sub),
        "sub.ovf" | "sub.ovf.un" => Some(push_runtime_binary_intrinsic(instruction, "cil.sub.ovf")),
        "rem" => simple_binary(SemanticOperationBinary::SRem),
        "rem.un" => simple_binary(SemanticOperationBinary::URem),
        "shl" => simple_binary(SemanticOperationBinary::Shl),
        "shr" => simple_binary(SemanticOperationBinary::AShr),
        "shr.un" => simple_binary(SemanticOperationBinary::LShr),
        "not" => simple_unary(SemanticOperationUnary::Not),
        "neg" => simple_unary(SemanticOperationUnary::Neg),
        "ceq" => compare_to_i64(SemanticOperationCompare::Eq),
        "cgt.un" => compare_to_i64(SemanticOperationCompare::Ugt),
        "cgt" => compare_to_i64(SemanticOperationCompare::Sgt),
        "clt.un" => compare_to_i64(SemanticOperationCompare::Ult),
        "clt" => compare_to_i64(SemanticOperationCompare::Slt),
        "conv.ovf.i" | "conv.ovf.i.un" | "conv.ovf.i1" | "conv.ovf.i1.un" | "conv.ovf.i2"
        | "conv.ovf.i2.un" | "conv.ovf.i4" | "conv.ovf.i4.un" | "conv.ovf.i8"
        | "conv.ovf.i8.un" | "conv.ovf.u" | "conv.ovf.u.un" | "conv.ovf.u1" | "conv.ovf.u1.un"
        | "conv.ovf.u2" | "conv.ovf.u2.un" | "conv.ovf.u4" | "conv.ovf.u4.un" | "conv.ovf.u8"
        | "conv.ovf.u8.un" | "conv.r.un" | "conv.r4" => Some(push_runtime_unary_intrinsic(
            instruction,
            &format!("cil.{}", instruction.mnemonic),
        )),
        "conv.r8" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(SemanticExpression::Cast {
                op: SemanticOperationCast::IntToFloat,
                arg: Box::new(value),
                bits: 64,
            }));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        _ => None,
    }
}

fn simple_binary(op: SemanticOperationBinary) -> Option<Semantic> {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    effects.extend(push_effects(binary(op, left, right, 64)));
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}

fn simple_unary(op: SemanticOperationUnary) -> Option<Semantic> {
    let (mut effects, value) = pop_stack();
    effects.extend(push_effects(unary(op, value, 64)));
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}

fn compare_to_i64(op: SemanticOperationCompare) -> Option<Semantic> {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    effects.extend(push_effects(bool_to_i64(compare(op, left, right))));
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}
