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

use crate::semantics::architectures::cil::CilInstructionView;
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticOperationCompare,
    SemanticStatus, SemanticTerminator,
};

use super::super::helpers::common::{
    compare, complete_with_effects, const_u64, operand_args, pop_stack,
};

pub(crate) fn build(instruction: &CilInstructionView) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic_text();
    if instruction.is_return() {
        return Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: if mnemonic == "throw" {
                SemanticTerminator::Trap
            } else {
                SemanticTerminator::Return { expression: None }
            },
            diagnostics: Vec::new(),
        });
    }

    if instruction.is_call() {
        return Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::Call {
                target: SemanticExpression::Intrinsic {
                    name: format!("cil.{}.target", instruction.mnemonic),
                    args: operand_args(instruction),
                    bits: 64,
                },
                return_target: instruction.next().map(|next| SemanticExpression::Const {
                    value: next as u128,
                    bits: 64,
                }),
                does_return: Some(true),
            },
            diagnostics: Vec::new(),
        });
    }

    if instruction.is_conditional_jump() {
        let true_target = instruction.to().iter().next().copied().unwrap_or_default();
        if matches!(mnemonic, "brtrue" | "brtrue.s") {
            let (effects, value) = pop_stack();
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ne, value, const_u64(0, 64)),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "brfalse" | "brfalse.s") {
            let (effects, value) = pop_stack();
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Eq, value, const_u64(0, 64)),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "beq" | "beq.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Eq, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bne.un" | "bne.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ne, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "blt" | "blt.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Slt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "blt.un" | "blt.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ult, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bgt" | "bgt.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Sgt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bge.un" | "bge.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Uge, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bgt.un" | "bgt.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ugt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "ble" | "ble.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Sle, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "ble.un" | "ble.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ule, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bge" | "bge.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Sge, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            ));
        }
        return Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::Branch {
                condition: SemanticExpression::Intrinsic {
                    name: format!("cil.{}.cond", instruction.mnemonic),
                    args: operand_args(instruction),
                    bits: 1,
                },
                true_target: SemanticExpression::Const {
                    value: true_target as u128,
                    bits: 64,
                },
                false_target: SemanticExpression::Const {
                    value: instruction.next().unwrap_or(instruction.address) as u128,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        });
    }

    if instruction.is_jump() || instruction.is_switch() {
        let target = instruction.to().iter().next().copied().unwrap_or_default();
        return Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: SemanticTerminator::Jump {
                target: SemanticExpression::Const {
                    value: target as u128,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        });
    }

    None
}
