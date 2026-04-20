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
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticStatus, SemanticTerminator,
    SemanticTrapKind,
};

use super::common::{
    complete_with_effects, const_u64, operand_value, pop_stack, push_expression,
    push_runtime_unary_intrinsic, push_with_prefix,
};

pub(crate) fn build(instruction: &Instruction<'_>) -> Option<InstructionSemantics> {
    match instruction.mnemonic {
        Mnemonic::ArgList => Some(push_expression(SemanticExpression::Intrinsic {
            name: "cil.arglist".to_string(),
            args: Vec::new(),
            bits: 64,
        })),
        Mnemonic::LdFtn => Some(push_expression(SemanticExpression::Intrinsic {
            name: "cil.ldftn".to_string(),
            args: vec![const_u64(operand_value(instruction), 32)],
            bits: 64,
        })),
        Mnemonic::InitObj => {
            let token = operand_value(instruction) as u32;
            let (mut effects, address) = pop_stack();
            effects.push(SemanticEffect::Intrinsic {
                name: "cil.initobj".to_string(),
                args: vec![address, const_u64(token as u64, 32)],
                outputs: Vec::new(),
            });
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::Volatile | Mnemonic::Constrained | Mnemonic::Cpobj => Some(
            complete_with_effects(SemanticTerminator::FallThrough, vec![SemanticEffect::Nop]),
        ),
        Mnemonic::LocAlloc => {
            let (effects, size) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.localloc".to_string(),
                    args: vec![size],
                    bits: 64,
                },
            ))
        }
        Mnemonic::CkInite => Some(push_runtime_unary_intrinsic(instruction, "cil.ckfinite")),
        Mnemonic::No | Mnemonic::ReadOnly | Mnemonic::Tail | Mnemonic::Unaligned => Some(
            complete_with_effects(SemanticTerminator::FallThrough, vec![SemanticEffect::Nop]),
        ),
        Mnemonic::End => Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::ArchSpecific {
                    name: "cil.endfinally".to_string(),
                },
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        Mnemonic::EndFilter => {
            let (mut effects, value) = pop_stack();
            effects.push(SemanticEffect::Intrinsic {
                name: "cil.endfilter".to_string(),
                args: vec![value],
                outputs: Vec::new(),
            });
            Some(complete_with_effects(SemanticTerminator::Trap, effects))
        }
        Mnemonic::ReThrow => Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::ArchSpecific {
                    name: "cil.rethrow".to_string(),
                },
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        _ => None,
    }
}
