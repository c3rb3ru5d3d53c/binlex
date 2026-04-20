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

use crate::disassemblers::cil::{Instruction, Mnemonic};
use crate::semantics::{
    InstructionSemantics, SemanticExpression, SemanticOperationBinary, SemanticOperationCast,
    SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator,
};

use super::common::{
    binary, bool_to_i64, compare, complete_with_effects, pop_stack, push_effects,
    push_runtime_binary_intrinsic, push_runtime_unary_intrinsic, unary,
};

pub(crate) fn build(instruction: &Instruction<'_>) -> Option<InstructionSemantics> {
    match instruction.mnemonic {
        Mnemonic::Add => simple_binary(SemanticOperationBinary::Add),
        Mnemonic::AddOvf | Mnemonic::AddOvfUn => {
            Some(push_runtime_binary_intrinsic(instruction, "cil.add.ovf"))
        }
        Mnemonic::Mul => simple_binary(SemanticOperationBinary::Mul),
        Mnemonic::MulOvf | Mnemonic::MulOvfUn => {
            Some(push_runtime_binary_intrinsic(instruction, "cil.mul.ovf"))
        }
        Mnemonic::Div => simple_binary(SemanticOperationBinary::SDiv),
        Mnemonic::DivUn => simple_binary(SemanticOperationBinary::UDiv),
        Mnemonic::And => simple_binary(SemanticOperationBinary::And),
        Mnemonic::Or => simple_binary(SemanticOperationBinary::Or),
        Mnemonic::Xor => simple_binary(SemanticOperationBinary::Xor),
        Mnemonic::Sub => simple_binary(SemanticOperationBinary::Sub),
        Mnemonic::SubOvf | Mnemonic::SubOvfUn => {
            Some(push_runtime_binary_intrinsic(instruction, "cil.sub.ovf"))
        }
        Mnemonic::Rem => simple_binary(SemanticOperationBinary::SRem),
        Mnemonic::RemUn => simple_binary(SemanticOperationBinary::URem),
        Mnemonic::Shl => simple_binary(SemanticOperationBinary::Shl),
        Mnemonic::Shr => simple_binary(SemanticOperationBinary::AShr),
        Mnemonic::ShrUn => simple_binary(SemanticOperationBinary::LShr),
        Mnemonic::Not => simple_unary(SemanticOperationUnary::Not),
        Mnemonic::Neg => simple_unary(SemanticOperationUnary::Neg),
        Mnemonic::Ceq => compare_to_i64(SemanticOperationCompare::Eq),
        Mnemonic::CgtUn => compare_to_i64(SemanticOperationCompare::Ugt),
        Mnemonic::Cgt => compare_to_i64(SemanticOperationCompare::Sgt),
        Mnemonic::CltUn => compare_to_i64(SemanticOperationCompare::Ult),
        Mnemonic::Clt => compare_to_i64(SemanticOperationCompare::Slt),
        Mnemonic::ConvOvfI
        | Mnemonic::ConvOvfIUn
        | Mnemonic::ConvOvfI1
        | Mnemonic::ConvOvfI1Un
        | Mnemonic::ConvOvfI2
        | Mnemonic::ConvOvfI2Un
        | Mnemonic::ConvOvfI4
        | Mnemonic::ConvOvfI4Un
        | Mnemonic::ConvOvfI8
        | Mnemonic::ConvOvfI8Un
        | Mnemonic::ConvOvfU
        | Mnemonic::ConvOvfUUn
        | Mnemonic::ConvOvfU1
        | Mnemonic::ConvOvfU1Un
        | Mnemonic::ConvOvfU2
        | Mnemonic::ConvOvfU2Un
        | Mnemonic::ConvOvfU4
        | Mnemonic::ConvOvfU4Un
        | Mnemonic::ConvOvfU8
        | Mnemonic::ConvOvfU8Un
        | Mnemonic::ConvRUn
        | Mnemonic::ConvR4 => Some(push_runtime_unary_intrinsic(
            instruction,
            &format!("cil.{:?}", instruction.mnemonic).to_lowercase(),
        )),
        Mnemonic::ConvR8 => {
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

fn simple_binary(op: SemanticOperationBinary) -> Option<InstructionSemantics> {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    effects.extend(push_effects(binary(op, left, right, 64)));
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}

fn simple_unary(op: SemanticOperationUnary) -> Option<InstructionSemantics> {
    let (mut effects, value) = pop_stack();
    effects.extend(push_effects(unary(op, value, 64)));
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}

fn compare_to_i64(op: SemanticOperationCompare) -> Option<InstructionSemantics> {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    effects.extend(push_effects(bool_to_i64(compare(op, left, right))));
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}
