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
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticOperationCompare,
    SemanticStatus, SemanticTerminator,
};

use super::common::{compare, complete_with_effects, const_u64, operand_args, pop_stack};

pub(crate) fn build(instruction: &Instruction<'_>) -> Option<InstructionSemantics> {
    if instruction.is_return() {
        return Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: if matches!(instruction.mnemonic, Mnemonic::Throw) {
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
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{:?}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::Call {
                target: SemanticExpression::Intrinsic {
                    name: format!("cil.{:?}.target", instruction.mnemonic),
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
        if matches!(instruction.mnemonic, Mnemonic::BrTrue | Mnemonic::BrTrueS) {
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
        if matches!(instruction.mnemonic, Mnemonic::BrFalse | Mnemonic::BrFalseS) {
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
        if matches!(instruction.mnemonic, Mnemonic::Beq | Mnemonic::BeqS) {
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
        if matches!(instruction.mnemonic, Mnemonic::BneUn | Mnemonic::BneUnS) {
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
        if matches!(instruction.mnemonic, Mnemonic::Blt | Mnemonic::BltS) {
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
        if matches!(instruction.mnemonic, Mnemonic::BltUn | Mnemonic::BltUnS) {
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
        if matches!(instruction.mnemonic, Mnemonic::Bgt | Mnemonic::BgtS) {
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
        if matches!(instruction.mnemonic, Mnemonic::BgeUn | Mnemonic::BgeUnS) {
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
        if matches!(instruction.mnemonic, Mnemonic::BgtUn | Mnemonic::BgtUnS) {
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
        if matches!(instruction.mnemonic, Mnemonic::Ble | Mnemonic::BleS) {
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
        if matches!(instruction.mnemonic, Mnemonic::BleUn | Mnemonic::BleUnS) {
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
        if matches!(instruction.mnemonic, Mnemonic::Bge | Mnemonic::BgeS) {
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
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{:?}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::Branch {
                condition: SemanticExpression::Intrinsic {
                    name: format!("cil.{:?}.cond", instruction.mnemonic),
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
