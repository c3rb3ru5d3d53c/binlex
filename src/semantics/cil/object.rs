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
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticTerminator,
};

use super::common::{
    complete_with_effects, const_u64, operand_value, pop_stack, push_effects, push_expression,
    push_with_prefix,
};

pub(crate) fn build(instruction: &Instruction<'_>) -> Option<InstructionSemantics> {
    match instruction.mnemonic {
        Mnemonic::NewArr => {
            let token = operand_value(instruction) as u32;
            let (mut effects, length) = pop_stack();
            effects.push(SemanticEffect::Intrinsic {
                name: "cil.newarr".to_string(),
                args: vec![length.clone(), const_u64(token as u64, 32)],
                outputs: Vec::new(),
            });
            effects.extend(push_effects(SemanticExpression::Intrinsic {
                name: "cil.newarr.result".to_string(),
                args: vec![length, const_u64(token as u64, 32)],
                bits: 64,
            }));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::NewObj => {
            let token = operand_value(instruction) as u32;
            let mut effects = vec![SemanticEffect::Intrinsic {
                name: "cil.newobj".to_string(),
                args: vec![const_u64(token as u64, 32)],
                outputs: Vec::new(),
            }];
            effects.extend(push_effects(SemanticExpression::Intrinsic {
                name: "cil.newobj.result".to_string(),
                args: vec![const_u64(token as u64, 32)],
                bits: 64,
            }));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::Box => {
            let token = operand_value(instruction) as u32;
            let (mut effects, value) = pop_stack();
            effects.push(SemanticEffect::Intrinsic {
                name: "cil.box".to_string(),
                args: vec![value.clone(), const_u64(token as u64, 32)],
                outputs: Vec::new(),
            });
            effects.extend(push_effects(SemanticExpression::Intrinsic {
                name: "cil.box.result".to_string(),
                args: vec![value, const_u64(token as u64, 32)],
                bits: 64,
            }));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::CastClass => {
            let token = operand_value(instruction) as u32;
            let (effects, value) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.castclass".to_string(),
                    args: vec![value, const_u64(token as u64, 32)],
                    bits: 64,
                },
            ))
        }
        Mnemonic::IsInst => {
            let token = operand_value(instruction) as u32;
            let (effects, value) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Select {
                    condition: Box::new(SemanticExpression::Intrinsic {
                        name: "cil.isinst.test".to_string(),
                        args: vec![value.clone(), const_u64(token as u64, 32)],
                        bits: 1,
                    }),
                    when_true: Box::new(value),
                    when_false: Box::new(const_u64(0, 64)),
                    bits: 64,
                },
            ))
        }
        Mnemonic::UnboxAny => {
            let token = operand_value(instruction) as u32;
            let (effects, value) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(SemanticExpression::Intrinsic {
                        name: "cil.unbox".to_string(),
                        args: vec![value, const_u64(token as u64, 32)],
                        bits: 64,
                    }),
                    bits: 64,
                },
            ))
        }
        Mnemonic::LdToken => Some(push_expression(const_u64(operand_value(instruction), 64))),
        Mnemonic::LdVirtFtn => {
            let token = operand_value(instruction) as u32;
            let (effects, object) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.ldvirtftn".to_string(),
                    args: vec![object, const_u64(token as u64, 32)],
                    bits: 64,
                },
            ))
        }
        Mnemonic::MkRefAny => {
            let token = operand_value(instruction) as u32;
            let (effects, address) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.mkrefany".to_string(),
                    args: vec![address, const_u64(token as u64, 32)],
                    bits: 64,
                },
            ))
        }
        Mnemonic::RefAnyType => {
            let (effects, typed_ref) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.refanytype".to_string(),
                    args: vec![typed_ref],
                    bits: 64,
                },
            ))
        }
        Mnemonic::RefAnyVal => {
            let token = operand_value(instruction) as u32;
            let (effects, typed_ref) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.refanyval".to_string(),
                    args: vec![typed_ref, const_u64(token as u64, 32)],
                    bits: 64,
                },
            ))
        }
        Mnemonic::SizeOf => Some(push_expression(SemanticExpression::Intrinsic {
            name: "cil.sizeof".to_string(),
            args: vec![const_u64(operand_value(instruction), 32)],
            bits: 64,
        })),
        Mnemonic::Unbox => {
            let token = operand_value(instruction) as u32;
            let (effects, boxed) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.unbox".to_string(),
                    args: vec![boxed, const_u64(token as u64, 32)],
                    bits: 64,
                },
            ))
        }
        _ => None,
    }
}
