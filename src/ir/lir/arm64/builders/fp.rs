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

use crate::ir::lir::arm64::InstructionDetailArm64;
use crate::ir::lir::arm64::builders::memory::{operand_expression, register_location};
use crate::ir::lir::arm64::helpers::{
    bool_const, complete, condition_from_cc, const_u64, fp_compare_flag_values, location_bits,
};
use crate::ir::lir::{
    Lir, LirEffect, LirExpression, LirOperationBinary, LirOperationCast, LirOperationCompare,
    LirOperationUnary, LirTerminator,
};

pub(crate) fn build(view: &InstructionDetailArm64) -> Option<Lir> {
    match view.mnemonic.as_str() {
        "fabs" => build_fabs(view),
        "fneg" => build_fneg(view),
        "fcmp" | "fcmpe" => build_fcmp(view),
        "fccmp" => build_fccmp(view),
        "fadd" => build_fp_binary(view, LirOperationBinary::FAdd),
        "fsub" => build_fp_binary(view, LirOperationBinary::FSub),
        "fmul" => build_fp_binary(view, LirOperationBinary::FMul),
        "fdiv" => build_fp_binary(view, LirOperationBinary::FDiv),
        "fnmul" => build_fnmul(view),
        "fmadd" => build_fmadd(view),
        "fmsub" => build_fmsub(view),
        "scvtf" => build_scvtf(view),
        "ucvtf" => build_ucvtf(view),
        "fcvtzs" => build_fcvtzs(view),
        "fcvtzu" => build_fcvtzu(view),
        "fmin" => build_fp_minmax(view, LirOperationCompare::Olt),
        "fmax" => build_fp_minmax(view, LirOperationCompare::Ogt),
        _ => None,
    }
}

fn build_fcmp(view: &InstructionDetailArm64) -> Option<Lir> {
    let left = fp_operand_expression(view, 0)?;
    let right = match view.operand(1) {
        Some(_) => fp_operand_expression(view, 1)?,
        None => LirExpression::Const {
            value: 0,
            bits: left.bits(),
        },
    };
    let compare_flags = fp_compare_flag_values(left, right);
    Some(complete(
        LirTerminator::FallThrough,
        vec![
            set_flag_effect("n", compare_flags[0].clone()),
            set_flag_effect("z", compare_flags[1].clone()),
            set_flag_effect("c", compare_flags[2].clone()),
            set_flag_effect("v", compare_flags[3].clone()),
        ],
    ))
}

fn build_fccmp(view: &InstructionDetailArm64) -> Option<Lir> {
    let left = fp_operand_expression(view, 0)?;
    let right = fp_operand_expression(view, 1)?;
    let fallback_nzcv = view.operand(2)?.immediate_value()?;
    let condition = condition_from_cc(
        view.operand(3)
            .and_then(|operand| operand.immediate_value())
            .or(view.condition_code.map(|cc| cc as i64))? as u64,
    )?;
    let compare_flags = fp_compare_flag_values(left, right);
    let fallback_flags = [
        ((fallback_nzcv >> 3) & 1) != 0,
        ((fallback_nzcv >> 2) & 1) != 0,
        ((fallback_nzcv >> 1) & 1) != 0,
        (fallback_nzcv & 1) != 0,
    ];
    let flag_names = ["n", "z", "c", "v"];
    let effects = flag_names
        .into_iter()
        .zip(compare_flags)
        .zip(fallback_flags)
        .map(|((name, compare_value), fallback_value)| LirEffect::Set {
            dst: flag_location(name),
            expression: LirExpression::Select {
                condition: Box::new(condition.clone()),
                when_true: Box::new(compare_value),
                when_false: Box::new(bool_const(fallback_value)),
                bits: 1,
            },
        })
        .collect();
    Some(complete(LirTerminator::FallThrough, effects))
}

fn build_fp_binary(view: &InstructionDetailArm64, op: LirOperationBinary) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let left = fp_operand_expression(view, 1)?;
    let right = fp_operand_expression(view, 2)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Binary {
                op,
                left: Box::new(left),
                right: Box::new(right),
                bits,
            },
        }],
    ))
}

fn build_fp_minmax(view: &InstructionDetailArm64, compare_op: LirOperationCompare) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let left = fp_operand_expression(view, 1)?;
    let right = fp_operand_expression(view, 2)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Select {
                condition: Box::new(LirExpression::Compare {
                    op: compare_op,
                    left: Box::new(left.clone()),
                    right: Box::new(right.clone()),
                    bits: 1,
                }),
                when_true: Box::new(left),
                when_false: Box::new(right),
                bits,
            },
        }],
    ))
}

fn build_fnmul(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let left = fp_operand_expression(view, 1)?;
    let right = fp_operand_expression(view, 2)?;
    let bits = location_bits(&dst);
    let zero = match bits {
        32 => const_u64(f32::to_bits(0.0) as u64, 32),
        64 => const_u64(f64::to_bits(0.0), 64),
        _ => return None,
    };
    let product = LirExpression::Binary {
        op: LirOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Binary {
                op: LirOperationBinary::FSub,
                left: Box::new(zero),
                right: Box::new(product),
                bits,
            },
        }],
    ))
}

fn build_fmadd(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let left = fp_operand_expression(view, 1)?;
    let right = fp_operand_expression(view, 2)?;
    let addend = fp_operand_expression(view, 3)?;
    let bits = location_bits(&dst);
    let product = LirExpression::Binary {
        op: LirOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Binary {
                op: LirOperationBinary::FAdd,
                left: Box::new(product),
                right: Box::new(addend),
                bits,
            },
        }],
    ))
}

fn build_fmsub(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let left = fp_operand_expression(view, 1)?;
    let right = fp_operand_expression(view, 2)?;
    let addend = fp_operand_expression(view, 3)?;
    let bits = location_bits(&dst);
    let product = LirExpression::Binary {
        op: LirOperationBinary::FMul,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Binary {
                op: LirOperationBinary::FSub,
                left: Box::new(addend),
                right: Box::new(product),
                bits,
            },
        }],
    ))
}

fn build_scvtf(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Cast {
                op: LirOperationCast::IntToFloat,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_ucvtf(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Cast {
                op: LirOperationCast::UIntToFloat,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_fcvtzs(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let src = fp_operand_expression(view, 1)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Cast {
                op: LirOperationCast::FloatToInt,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_fcvtzu(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let src = fp_operand_expression(view, 1)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Cast {
                op: LirOperationCast::FloatToUInt,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_fabs(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let src = fp_operand_expression(view, 1)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Unary {
                op: LirOperationUnary::Abs,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_fneg(view: &InstructionDetailArm64) -> Option<Lir> {
    let dst = register_location(view.operand(0)?)?;
    let src = fp_operand_expression(view, 1)?;
    let bits = location_bits(&dst);
    Some(complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Unary {
                op: LirOperationUnary::Neg,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn fp_operand_expression(view: &InstructionDetailArm64, index: usize) -> Option<LirExpression> {
    let operand = view.operand(index)?;
    if let Some(value) = operand.float {
        let bits = operand.size_bits.max(32);
        return Some(match bits {
            32 => const_u64((value as f32).to_bits() as u64, 32),
            64 => const_u64(value.to_bits(), 64),
            _ => return None,
        });
    }
    operand_expression(operand)
}

fn flag_location(name: &str) -> crate::ir::lir::LirLocation {
    crate::ir::lir::LirLocation::Flag {
        name: name.to_string(),
        bits: 1,
    }
}

fn set_flag_effect(name: &str, expression: LirExpression) -> LirEffect {
    LirEffect::Set {
        dst: flag_location(name),
        expression,
    }
}
