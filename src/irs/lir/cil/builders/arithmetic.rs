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

use crate::irs::lir::cil::InstructionDetailCil;
use crate::irs::lir::{
    Lir, LirExpression, LirOperationBinary, LirOperationCast, LirOperationCompare,
    LirOperationUnary, LirTerminator,
};

use super::super::helpers::common::{
    binary, bool_to_i64, compare, complete_with_effects, pop_stack, push_effects,
    push_runtime_binary_intrinsic, push_runtime_unary_intrinsic, unary,
};

pub(crate) fn build(instruction: &InstructionDetailCil) -> Option<Lir> {
    match instruction.mnemonic_text() {
        "add" => simple_binary(LirOperationBinary::Add),
        "add.ovf" | "add.ovf.un" => Some(push_runtime_binary_intrinsic(instruction, "cil.add.ovf")),
        "mul" => simple_binary(LirOperationBinary::Mul),
        "mul.ovf" | "mul.ovf.un" => Some(push_runtime_binary_intrinsic(instruction, "cil.mul.ovf")),
        "div" => simple_binary(LirOperationBinary::SDiv),
        "div.un" => simple_binary(LirOperationBinary::UDiv),
        "and" => simple_binary(LirOperationBinary::And),
        "or" => simple_binary(LirOperationBinary::Or),
        "xor" => simple_binary(LirOperationBinary::Xor),
        "sub" => simple_binary(LirOperationBinary::Sub),
        "sub.ovf" | "sub.ovf.un" => Some(push_runtime_binary_intrinsic(instruction, "cil.sub.ovf")),
        "rem" => simple_binary(LirOperationBinary::SRem),
        "rem.un" => simple_binary(LirOperationBinary::URem),
        "shl" => simple_binary(LirOperationBinary::Shl),
        "shr" => simple_binary(LirOperationBinary::AShr),
        "shr.un" => simple_binary(LirOperationBinary::LShr),
        "not" => simple_unary(LirOperationUnary::Not),
        "neg" => simple_unary(LirOperationUnary::Neg),
        "ceq" => compare_to_i64(LirOperationCompare::Eq),
        "cgt.un" => compare_to_i64(LirOperationCompare::Ugt),
        "cgt" => compare_to_i64(LirOperationCompare::Sgt),
        "clt.un" => compare_to_i64(LirOperationCompare::Ult),
        "clt" => compare_to_i64(LirOperationCompare::Slt),
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
            effects.extend(push_effects(LirExpression::Cast {
                op: LirOperationCast::IntToFloat,
                arg: Box::new(value),
                bits: 64,
            }));
            Some(complete_with_effects(LirTerminator::FallThrough, effects))
        }
        _ => None,
    }
}

fn simple_binary(op: LirOperationBinary) -> Option<Lir> {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    effects.extend(push_effects(binary(op, left, right, 64)));
    Some(complete_with_effects(LirTerminator::FallThrough, effects))
}

fn simple_unary(op: LirOperationUnary) -> Option<Lir> {
    let (mut effects, value) = pop_stack();
    effects.extend(push_effects(unary(op, value, 64)));
    Some(complete_with_effects(LirTerminator::FallThrough, effects))
}

fn compare_to_i64(op: LirOperationCompare) -> Option<Lir> {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    effects.extend(push_effects(bool_to_i64(compare(op, left, right))));
    Some(complete_with_effects(LirTerminator::FallThrough, effects))
}
