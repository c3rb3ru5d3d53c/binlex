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

use crate::ir::lir::cil::InstructionDetailCil;
use crate::ir::lir::{
    Lir, LirEffect, LirExpression, LirOperationCompare, LirStatus, LirTerminator,
};

use super::super::helpers::common::{
    compare, complete_with_effects, const_u64, operand_args, pop_stack,
};

pub(crate) fn build(instruction: &InstructionDetailCil) -> Option<Lir> {
    let mnemonic = instruction.mnemonic_text();
    if instruction.is_return() {
        return Some(Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: if mnemonic == "throw" {
                LirTerminator::Trap
            } else {
                LirTerminator::Return { expression: None }
            },
            diagnostics: Vec::new(),
        });
    }

    if instruction.is_call() {
        return Some(Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Intrinsic {
                name: format!("cil.{}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: LirTerminator::Call {
                target: LirExpression::Intrinsic {
                    name: format!("cil.{}.target", instruction.mnemonic),
                    args: operand_args(instruction),
                    bits: 64,
                },
                return_target: instruction.fallthrough().map(|next| LirExpression::Const {
                    value: next as u128,
                    bits: 64,
                }),
                does_return: Some(true),
            },
            diagnostics: Vec::new(),
        });
    }

    if instruction.is_conditional_jump() {
        let true_target = instruction
            .branches()
            .iter()
            .next()
            .copied()
            .unwrap_or_default();
        if matches!(mnemonic, "brtrue" | "brtrue.s") {
            let (effects, value) = pop_stack();
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Ne, value, const_u64(0, 64)),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "brfalse" | "brfalse.s") {
            let (effects, value) = pop_stack();
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Eq, value, const_u64(0, 64)),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "beq" | "beq.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Eq, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bne.un" | "bne.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Ne, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "blt" | "blt.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Slt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "blt.un" | "blt.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Ult, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bgt" | "bgt.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Sgt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bge.un" | "bge.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Uge, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bgt.un" | "bgt.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Ugt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "ble" | "ble.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Sle, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "ble.un" | "ble.un.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Ule, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        if matches!(mnemonic, "bge" | "bge.s") {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return Some(complete_with_effects(
                LirTerminator::Branch {
                    condition: compare(LirOperationCompare::Sge, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(
                        instruction.fallthrough().unwrap_or(instruction.address),
                        64,
                    ),
                },
                effects,
            ));
        }
        return Some(Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![LirEffect::Intrinsic {
                name: format!("cil.{}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: LirTerminator::Branch {
                condition: LirExpression::Intrinsic {
                    name: format!("cil.{}.cond", instruction.mnemonic),
                    args: operand_args(instruction),
                    bits: 1,
                },
                true_target: LirExpression::Const {
                    value: true_target as u128,
                    bits: 64,
                },
                false_target: LirExpression::Const {
                    value: instruction.fallthrough().unwrap_or(instruction.address) as u128,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        });
    }

    if instruction.is_jump() || instruction.is_switch() {
        let target = instruction
            .branches()
            .iter()
            .next()
            .copied()
            .unwrap_or_default();
        return Some(Lir {
            version: 1,
            status: LirStatus::Complete,
            metadata: Default::default(),
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::Jump {
                target: LirExpression::Const {
                    value: target as u128,
                    bits: 64,
                },
            },
            diagnostics: Vec::new(),
        });
    }

    None
}
