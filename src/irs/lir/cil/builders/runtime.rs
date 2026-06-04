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
use crate::irs::lir::{Lir, LirEffect, LirExpression, LirStatus, LirTerminator, LirTrapKind};

use super::super::helpers::common::{
    complete_with_effects, const_u64, operand_value, pop_stack, push_expression,
    push_runtime_unary_intrinsic, push_with_prefix,
};

pub(crate) fn build(instruction: &InstructionDetailCil) -> Option<Lir> {
    match instruction.mnemonic_text() {
        "arglist" => Some(push_expression(LirExpression::Intrinsic {
            name: "cil.arglist".to_string(),
            args: Vec::new(),
            bits: 64,
        })),
        "ldftn" => Some(push_expression(LirExpression::Intrinsic {
            name: "cil.ldftn".to_string(),
            args: vec![const_u64(operand_value(instruction), 32)],
            bits: 64,
        })),
        "initobj" => {
            let token = operand_value(instruction) as u32;
            let (mut effects, address) = pop_stack();
            effects.push(LirEffect::Intrinsic {
                name: "cil.initobj".to_string(),
                args: vec![address, const_u64(token as u64, 32)],
                outputs: Vec::new(),
            });
            Some(complete_with_effects(LirTerminator::FallThrough, effects))
        }
        "volatile." | "constrained." | "cpobj" => Some(complete_with_effects(
            LirTerminator::FallThrough,
            vec![LirEffect::Nop],
        )),
        "localloc" => {
            let (effects, size) = pop_stack();
            Some(push_with_prefix(
                effects,
                LirExpression::Intrinsic {
                    name: "cil.localloc".to_string(),
                    args: vec![size],
                    bits: 64,
                },
            ))
        }
        "ckfinite" => Some(push_runtime_unary_intrinsic(instruction, "cil.ckfinite")),
        "no." | "readonly." | "tail." | "unaligned." => Some(complete_with_effects(
            LirTerminator::FallThrough,
            vec![LirEffect::Nop],
        )),
        "endfinally" => Some(Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Trap {
                kind: LirTrapKind::Named {
                    name: "cil.endfinally".to_string(),
                },
            }],
            terminator: LirTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        "endfilter" => {
            let (mut effects, value) = pop_stack();
            effects.push(LirEffect::Intrinsic {
                name: "cil.endfilter".to_string(),
                args: vec![value],
                outputs: Vec::new(),
            });
            Some(complete_with_effects(LirTerminator::Trap, effects))
        }
        "rethrow" => Some(Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Trap {
                kind: LirTrapKind::Named {
                    name: "cil.rethrow".to_string(),
                },
            }],
            terminator: LirTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        _ => None,
    }
}
