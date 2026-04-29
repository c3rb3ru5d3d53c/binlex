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

use crate::semantics::architectures::arm64::Arm64InstructionView;
use crate::semantics::architectures::arm64::builders::memory::{
    operand_expression, register_location,
};
use crate::semantics::architectures::arm64::helpers::{
    binary, complete, const_u64, location_bits, sign_extend_to_bits, zero_extend_to_bits,
};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticOperationBinary, SemanticTerminator,
};

pub(crate) fn build(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    match view.mnemonic.as_str() {
        "madd" => build_madd(view),
        "smaddl" => build_smaddl(view),
        "smull" => build_smull(view),
        "smulh" => build_smulh(view),
        "smsubl" => build_smsubl(view),
        "msub" => build_msub(view),
        "mul" => build_mul(view),
        "mneg" => build_mneg(view),
        "umulh" => build_umulh(view),
        "sdiv" => build_sdiv(view),
        "udiv" => build_udiv(view),
        "umull" => build_umull(view),
        "umaddl" => build_umaddl(view),
        "umsubl" => build_umsubl(view),
        "umnegl" => build_umnegl(view),
        _ => None,
    }
}

fn build_madd(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let addend = operand_expression(view.operand(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Add, product, addend, bits),
        }],
    ))
}

fn build_smaddl(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = sign_extend_to_bits(operand_expression(view.operand(1)?)?, 64);
    let right = sign_extend_to_bits(operand_expression(view.operand(2)?)?, 64);
    let addend = operand_expression(view.operand(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Add, product, addend, bits),
        }],
    ))
}

fn build_umaddl(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = zero_extend_to_bits(operand_expression(view.operand(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(view.operand(2)?)?, 64);
    let addend = operand_expression(view.operand(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Add, product, addend, bits),
        }],
    ))
}

fn build_mul(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Mul, left, right, bits),
        }],
    ))
}

fn build_mneg(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, const_u64(0, bits), product, bits),
        }],
    ))
}

fn build_umulh(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::UMulHigh, left, right, bits),
        }],
    ))
}

fn build_smulh(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::SMulHigh, left, right, bits),
        }],
    ))
}

fn build_sdiv(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::SDiv, left, right, bits),
        }],
    ))
}

fn build_udiv(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::UDiv, left, right, bits),
        }],
    ))
}

fn build_msub(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let subtrahend = operand_expression(view.operand(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, subtrahend, product, bits),
        }],
    ))
}

fn build_smsubl(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = sign_extend_to_bits(operand_expression(view.operand(1)?)?, 64);
    let right = sign_extend_to_bits(operand_expression(view.operand(2)?)?, 64);
    let subtrahend = operand_expression(view.operand(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, subtrahend, product, bits),
        }],
    ))
}

fn build_umull(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = zero_extend_to_bits(operand_expression(view.operand(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(view.operand(2)?)?, 64);
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Mul, left, right, bits),
        }],
    ))
}

fn build_umsubl(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = zero_extend_to_bits(operand_expression(view.operand(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(view.operand(2)?)?, 64);
    let subtrahend = operand_expression(view.operand(3)?)?;
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, subtrahend, product, bits),
        }],
    ))
}

fn build_smull(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = sign_extend_to_bits(operand_expression(view.operand(1)?)?, 64);
    let right = sign_extend_to_bits(operand_expression(view.operand(2)?)?, 64);
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Mul, left, right, bits),
        }],
    ))
}

fn build_umnegl(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = zero_extend_to_bits(operand_expression(view.operand(1)?)?, 64);
    let right = zero_extend_to_bits(operand_expression(view.operand(2)?)?, 64);
    let bits = location_bits(&dst);
    let product = binary(SemanticOperationBinary::Mul, left, right, bits);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, const_u64(0, bits), product, bits),
        }],
    ))
}
