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
use crate::semantics::architectures::x86::X86InstructionView;
use crate::semantics::architectures::x86::helpers as common;
use crate::semantics::architectures::x86::{X86OperandKind, X86OperandView};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCompare, SemanticTerminator,
};

pub(crate) fn build(
    machine: Architecture,
    view: &X86InstructionView,
) -> Option<InstructionSemantics> {
    match view.mnemonic.as_str() {
        "andn" => andn(machine, view.operands()),
        "test" => test(machine, view.operands()),
        "and" => binary(machine, view.operands(), SemanticOperationBinary::And),
        "or" => binary(machine, view.operands(), SemanticOperationBinary::Or),
        "xor" => binary(machine, view.operands(), SemanticOperationBinary::Xor),
        _ => None,
    }
}

fn andn(machine: Architecture, operands: &[X86OperandView]) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src1 = operand_expr(machine, operands.get(1)?)?;
    let src2 = operand_expr(machine, operands.get(2)?)?;
    let bits = common::location_bits(&dst);
    let result = common::and(common::not(src1, bits), src2, bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        logic_effects(Some(dst), result, bits),
    ))
}

fn test(machine: Architecture, operands: &[X86OperandView]) -> Option<InstructionSemantics> {
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = operands
        .first()
        .and_then(|operand| operand_location(machine, operand))
        .map(|location| common::location_bits(&location))
        .unwrap_or_else(|| common::pointer_bits(machine));
    let result = common::and(left.clone(), right.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        logic_effects(None, result, bits),
    ))
}

fn binary(
    machine: Architecture,
    operands: &[X86OperandView],
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        logic_effects(Some(dst), result, bits),
    ))
}

fn logic_effects(
    dst: Option<SemanticLocation>,
    result: SemanticExpression,
    bits: u16,
) -> Vec<SemanticEffect> {
    let mut effects = Vec::new();
    if let Some(dst) = dst {
        effects.push(SemanticEffect::Set {
            dst,
            expression: result.clone(),
        });
    }
    effects.extend([
        SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: common::compare(
                SemanticOperationCompare::Eq,
                result.clone(),
                common::const_u64(0, bits),
            ),
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
        },
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: common::bool_const(false),
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: common::bool_const(false),
        },
        SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(result),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
    ]);
    effects
}

fn operand_expr(machine: Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(SemanticExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(SemanticExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticExpression::Load {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(machine: Architecture, operand: &X86OperandView) -> Option<SemanticLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticLocation::Memory {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}
