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

use crate::semantics::arm64::InstructionDetailArm64;
use crate::semantics::arm64::helpers::{compare, complete, condition_from_suffix, const_u64};
use crate::semantics::arm64::{Arm64OperandKind, Arm64OperandView};
use crate::semantics::{
    Semantic, SemanticEffect, SemanticExpression, SemanticLocation, SemanticOperationCompare,
    SemanticStatus, SemanticTerminator, SemanticTrapKind,
};

pub(crate) fn build(view: &InstructionDetailArm64) -> Option<Semantic> {
    let bits = 64;
    let next = const_u64(view.address + view.bytes.len() as u64, bits);
    match view.mnemonic.as_str() {
        "b" => {
            let target = operand_expression(view.operands().first()?)?;
            Some(complete(SemanticTerminator::Jump { target }, Vec::new()))
        }
        mnemonic if mnemonic.starts_with("b.") => {
            let target = operand_expression(view.operands().first()?)?;
            let condition = condition_from_suffix(mnemonic.strip_prefix("b.")?)?;
            Some(complete(
                SemanticTerminator::Branch {
                    condition,
                    true_target: target,
                    false_target: next,
                },
                Vec::new(),
            ))
        }
        "bl" => {
            let target = operand_expression(view.operands().first()?)?;
            Some(complete(
                SemanticTerminator::Call {
                    target,
                    return_target: Some(next.clone()),
                    does_return: Some(true),
                },
                vec![SemanticEffect::Set {
                    dst: link_register(),
                    expression: next,
                }],
            ))
        }
        "br" => {
            let target = operand_expression(view.operands().first()?)?;
            Some(complete(SemanticTerminator::Jump { target }, Vec::new()))
        }
        "blr" => {
            let target = operand_expression(view.operands().first()?)?;
            Some(complete(
                SemanticTerminator::Call {
                    target,
                    return_target: Some(next.clone()),
                    does_return: Some(true),
                },
                vec![SemanticEffect::Set {
                    dst: link_register(),
                    expression: next,
                }],
            ))
        }
        "cbz" => build_compare_branch(
            view,
            SemanticOperationCompare::Eq,
            view.operands().first()?,
            view.operands().get(1)?,
        ),
        "cbnz" => build_compare_branch(
            view,
            SemanticOperationCompare::Ne,
            view.operands().first()?,
            view.operands().get(1)?,
        ),
        "tbz" => build_test_bit_branch(view, SemanticOperationCompare::Eq),
        "tbnz" => build_test_bit_branch(view, SemanticOperationCompare::Ne),
        "ret" => {
            let expression = Some(
                view.operands()
                    .first()
                    .and_then(operand_expression)
                    .unwrap_or_else(link_register_expr),
            );
            Some(complete(
                SemanticTerminator::Return { expression },
                Vec::new(),
            ))
        }
        "brk" => Some(Semantic {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Breakpoint,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        _ => None,
    }
}

fn build_compare_branch(
    view: &InstructionDetailArm64,
    compare_op: SemanticOperationCompare,
    lhs_operand: &Arm64OperandView,
    target_operand: &Arm64OperandView,
) -> Option<Semantic> {
    let bits = operand_bits(lhs_operand);
    let condition = compare(
        compare_op,
        operand_expression(lhs_operand)?,
        const_u64(0, bits),
    );
    let target = operand_expression(target_operand)?;
    let next = const_u64(view.address + view.bytes.len() as u64, 64);
    Some(complete(
        SemanticTerminator::Branch {
            condition,
            true_target: target,
            false_target: next,
        },
        Vec::new(),
    ))
}

fn build_test_bit_branch(
    view: &InstructionDetailArm64,
    compare_op: SemanticOperationCompare,
) -> Option<Semantic> {
    let value = operand_expression(view.operands().first()?)?;
    let bit = view.operand(1)?.immediate_value()? as u16;
    let target = operand_expression(view.operand(2)?)?;
    let next = const_u64(view.address + view.bytes.len() as u64, 64);
    let extracted = SemanticExpression::Extract {
        arg: Box::new(value),
        lsb: bit,
        bits: 1,
    };
    let condition = compare(compare_op, extracted, const_u64(0, 1));
    Some(complete(
        SemanticTerminator::Branch {
            condition,
            true_target: target,
            false_target: next,
        },
        Vec::new(),
    ))
}

fn operand_expression(operand: &Arm64OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        Arm64OperandKind::Register => Some(SemanticExpression::Read(Box::new(
            SemanticLocation::Register {
                name: operand.register_name()?.to_string(),
                bits: operand_bits(operand),
            },
        ))),
        Arm64OperandKind::Immediate => Some(const_u64(
            operand.immediate_value()? as i64 as u64,
            operand_bits(operand),
        )),
        _ => None,
    }
}

fn operand_bits(operand: &Arm64OperandView) -> u16 {
    if operand.size_bits == 0 {
        64
    } else {
        operand.size_bits
    }
}

fn link_register() -> SemanticLocation {
    SemanticLocation::Register {
        name: "x30".to_string(),
        bits: 64,
    }
}

fn link_register_expr() -> SemanticExpression {
    SemanticExpression::Read(Box::new(link_register()))
}
