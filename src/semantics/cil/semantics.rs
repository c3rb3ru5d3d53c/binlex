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

use crate::disassemblers::cil::Instruction;
use crate::disassemblers::cil::Mnemonic;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticDiagnostic, SemanticDiagnosticKind,
    SemanticEffect, SemanticExpression, SemanticLocation, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticStatus,
    SemanticTerminator, SemanticTrapKind,
};

pub fn build(instruction: &Instruction<'_>) -> InstructionSemantics {
    if instruction.is_return() {
        return InstructionSemantics {
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
        };
    }

    if instruction.is_call() {
        return InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("dotnet.{:?}", instruction.mnemonic),
                args: operand_args(instruction),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::Call {
                target: SemanticExpression::Intrinsic {
                    name: format!("dotnet.{:?}.target", instruction.mnemonic),
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
        };
    }

    if instruction.is_conditional_jump() {
        let true_target = instruction.to().iter().next().copied().unwrap_or_default();
        if matches!(instruction.mnemonic, Mnemonic::BrTrue | Mnemonic::BrTrueS) {
            let (effects, value) = pop_stack();
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ne, value, const_u64(0, 64)),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::BrFalse | Mnemonic::BrFalseS) {
            let (effects, value) = pop_stack();
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Eq, value, const_u64(0, 64)),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::Beq | Mnemonic::BeqS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Eq, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::BneUn | Mnemonic::BneUnS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ne, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::Blt | Mnemonic::BltS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Slt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::BltUn | Mnemonic::BltUnS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ult, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::Bgt | Mnemonic::BgtS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Sgt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::BgeUn | Mnemonic::BgeUnS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Uge, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::BgtUn | Mnemonic::BgtUnS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ugt, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::Ble | Mnemonic::BleS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Sle, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::BleUn | Mnemonic::BleUnS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Ule, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        if matches!(instruction.mnemonic, Mnemonic::Bge | Mnemonic::BgeS) {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            return complete_with_effects(
                SemanticTerminator::Branch {
                    condition: compare(SemanticOperationCompare::Sge, left, right),
                    true_target: const_u64(true_target, 64),
                    false_target: const_u64(instruction.next().unwrap_or(instruction.address), 64),
                },
                effects,
            );
        }
        return InstructionSemantics {
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
        };
    }

    if instruction.is_jump() || instruction.is_switch() {
        let target = instruction.to().iter().next().copied().unwrap_or_default();
        return InstructionSemantics {
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
        };
    }

    match instruction.mnemonic {
        Mnemonic::Nop => InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Nop],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: Vec::new(),
        },
        Mnemonic::Break => InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Breakpoint,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        },
        Mnemonic::DUP => {
            let (mut effects, value) = peek_stack();
            effects.extend(push_effects(value));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Pop => {
            let (effects, _) = pop_stack();
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Add => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::Add,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Mul => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::Mul,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Div => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::SDiv,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::DivUn => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::UDiv,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::And => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::And,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Or => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::Or,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Xor => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::Xor,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Sub => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::Sub,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Rem => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::SRem,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Shl => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::Shl,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Shr => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::AShr,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ShrUn => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(binary(
                SemanticOperationBinary::LShr,
                left,
                right,
                64,
            )));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Not => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(unary(SemanticOperationUnary::Not, value, 64)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Neg => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(unary(SemanticOperationUnary::Neg, value, 64)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Ceq => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(bool_to_i64(compare(
                SemanticOperationCompare::Eq,
                left,
                right,
            ))));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::CgtUn => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(bool_to_i64(compare(
                SemanticOperationCompare::Ugt,
                left,
                right,
            ))));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Cgt => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(bool_to_i64(compare(
                SemanticOperationCompare::Sgt,
                left,
                right,
            ))));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::CltUn => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(bool_to_i64(compare(
                SemanticOperationCompare::Ult,
                left,
                right,
            ))));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Clt => {
            let (mut effects, right) = pop_stack();
            let (mut more_effects, left) = pop_stack();
            effects.append(&mut more_effects);
            effects.extend(push_effects(bool_to_i64(compare(
                SemanticOperationCompare::Slt,
                left,
                right,
            ))));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvI4 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i32(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvI2 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i16(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvI1 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i8(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvI8 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i64(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvU2 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i16(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvU1 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i8(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvU4 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i32(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvU => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i64(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvU8 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i64(value)));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::ConvR8 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(SemanticExpression::Intrinsic {
                name: "cil.conv.r8".to_string(),
                args: vec![value],
                bits: 64,
            }));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::LdNull => push_expression(const_u64(0, 64)),
        Mnemonic::LdcI40 => push_expression(const_u64(0, 64)),
        Mnemonic::LdcI41 => push_expression(const_u64(1, 64)),
        Mnemonic::LdcI42 => push_expression(const_u64(2, 64)),
        Mnemonic::LdcI43 => push_expression(const_u64(3, 64)),
        Mnemonic::LdcI44 => push_expression(const_u64(4, 64)),
        Mnemonic::LdcI45 => push_expression(const_u64(5, 64)),
        Mnemonic::LdcI46 => push_expression(const_u64(6, 64)),
        Mnemonic::LdcI47 => push_expression(const_u64(7, 64)),
        Mnemonic::LdcI48 => push_expression(const_u64(8, 64)),
        Mnemonic::LdcI4M1 => push_expression(const_u64(u64::MAX, 64)),
        Mnemonic::LdcI4S => {
            push_expression(const_u64(sign_extend(operand_value(instruction), 8), 64))
        }
        Mnemonic::LdcI4 => {
            push_expression(const_u64(sign_extend(operand_value(instruction), 32), 64))
        }
        Mnemonic::LdcI8 => push_expression(const_u64(operand_value(instruction), 64)),
        Mnemonic::LdcR4 => push_expression(const_u64(operand_value(instruction), 64)),
        Mnemonic::LdcR8 => push_expression(const_u64(operand_value(instruction), 64)),
        Mnemonic::LdArg0 => push_expression(read(cil_argument(0))),
        Mnemonic::LdArg1 => push_expression(read(cil_argument(1))),
        Mnemonic::LdArg2 => push_expression(read(cil_argument(2))),
        Mnemonic::LdArg3 => push_expression(read(cil_argument(3))),
        Mnemonic::LdArgS | Mnemonic::LdArg => {
            push_expression(read(cil_argument(operand_value(instruction) as u32)))
        }
        Mnemonic::LdArgAS | Mnemonic::LdArgA => push_expression(read(cil_argument_address(
            operand_value(instruction) as u32,
        ))),
        Mnemonic::LdLoc0 => push_expression(read(cil_local(0))),
        Mnemonic::LdLoc1 => push_expression(read(cil_local(1))),
        Mnemonic::LdLoc2 => push_expression(read(cil_local(2))),
        Mnemonic::LdLoc3 => push_expression(read(cil_local(3))),
        Mnemonic::LdLocS | Mnemonic::LdLoc => {
            push_expression(read(cil_local(operand_value(instruction) as u32)))
        }
        Mnemonic::LdLocAS | Mnemonic::LdLocA => {
            push_expression(read(cil_local_address(operand_value(instruction) as u32)))
        }
        Mnemonic::LdFtn => push_expression(SemanticExpression::Intrinsic {
            name: "cil.ldftn".to_string(),
            args: vec![const_u64(operand_value(instruction), 32)],
            bits: 64,
        }),
        Mnemonic::StLoc0 => pop_to_location(cil_local(0)),
        Mnemonic::StLoc1 => pop_to_location(cil_local(1)),
        Mnemonic::StLoc2 => pop_to_location(cil_local(2)),
        Mnemonic::StLoc3 => pop_to_location(cil_local(3)),
        Mnemonic::StLocS | Mnemonic::SLoc => {
            pop_to_location(cil_local(operand_value(instruction) as u32))
        }
        Mnemonic::StArgS | Mnemonic::StArg => {
            pop_to_location(cil_argument(operand_value(instruction) as u32))
        }
        Mnemonic::LdStr => push_expression(const_u64(operand_value(instruction), 64)),
        Mnemonic::LdLen => {
            let (effects, array) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.array.len".to_string(),
                    args: vec![array],
                    bits: 64,
                },
            )
        }
        Mnemonic::LdElmRef => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_element_address(array, index)),
                    bits: 64,
                },
            )
        }
        Mnemonic::LdElmU1 => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(
                effects,
                zero_extend_i8(SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_element_address(array, index)),
                    bits: 8,
                }),
            )
        }
        Mnemonic::LdElmU4 => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(
                effects,
                zero_extend_i32(SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_element_address(array, index)),
                    bits: 32,
                }),
            )
        }
        Mnemonic::LdElmU2 => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(
                effects,
                zero_extend_i16(SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_element_address(array, index)),
                    bits: 16,
                }),
            )
        }
        Mnemonic::LdElmI4 => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(
                effects,
                sign_extend_i32(SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_element_address(array, index)),
                    bits: 32,
                }),
            )
        }
        Mnemonic::LdElm => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_element_address(array, index)),
                    bits: 64,
                },
            )
        }
        Mnemonic::LdElmR8 => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_element_address(array, index)),
                    bits: 64,
                },
            )
        }
        Mnemonic::LdElmA => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            push_with_prefix(effects, cil_array_element_address(array, index))
        }
        Mnemonic::LdIndRef => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 64,
                },
            )
        }
        Mnemonic::LdIndU1 => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                zero_extend_i8(SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 8,
                }),
            )
        }
        Mnemonic::LdIndU2 => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                zero_extend_i16(SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 16,
                }),
            )
        }
        Mnemonic::LdIndU4 => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                zero_extend_i32(SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 32,
                }),
            )
        }
        Mnemonic::LdIndI4 => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                sign_extend_i32(SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 32,
                }),
            )
        }
        Mnemonic::LdIndU8 => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                zero_extend_i64(SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 64,
                }),
            )
        }
        Mnemonic::LdIndR4 => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 32,
                },
            )
        }
        Mnemonic::LdIndR8 => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 64,
                },
            )
        }
        Mnemonic::LdObj => {
            let (effects, address) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(address),
                    bits: 64,
                },
            )
        }
        Mnemonic::LdFld => {
            let token = operand_value(instruction) as u32;
            let (effects, object) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_field_address(token, Some(object))),
                    bits: 64,
                },
            )
        }
        Mnemonic::LdFldA => {
            let token = operand_value(instruction) as u32;
            let (effects, object) = pop_stack();
            push_with_prefix(effects, cil_field_address(token, Some(object)))
        }
        Mnemonic::LdSFld => push_expression(SemanticExpression::Load {
            space: SemanticAddressSpace::Global,
            addr: Box::new(cil_field_address(operand_value(instruction) as u32, None)),
            bits: 64,
        }),
        Mnemonic::LdSFldA => {
            push_expression(cil_field_address(operand_value(instruction) as u32, None))
        }
        Mnemonic::StFld => {
            let token = operand_value(instruction) as u32;
            let (mut effects, value) = pop_stack();
            let (mut more_effects, object) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Heap,
                addr: cil_field_address(token, Some(object)),
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StSFld => {
            let token = operand_value(instruction) as u32;
            let (mut effects, value) = pop_stack();
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Global,
                addr: cil_field_address(token, None),
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndI4 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: truncate_i32(value),
                bits: 32,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndI1 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: truncate_i8(value),
                bits: 8,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndI2 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: truncate_i16(value),
                bits: 16,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndI8 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndI => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndRef => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndR8 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StIndR4 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: truncate_i32(value),
                bits: 32,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StObj => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, address) = pop_stack();
            effects.append(&mut more_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr: address,
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::NewArr => {
            let token = operand_value(instruction) as u32;
            let (effects, length) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.newarr".to_string(),
                    args: vec![length, const_u64(token as u64, 32)],
                    bits: 64,
                },
            )
        }
        Mnemonic::NewObj => {
            let token = operand_value(instruction) as u32;
            let mut effects = vec![SemanticEffect::Intrinsic {
                name: "dotnet.newobj".to_string(),
                args: vec![const_u64(token as u64, 32)],
                outputs: Vec::new(),
            }];
            effects.extend(push_effects(SemanticExpression::Intrinsic {
                name: "dotnet.newobj.result".to_string(),
                args: vec![const_u64(token as u64, 32)],
                bits: 64,
            }));
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::Box => {
            let token = operand_value(instruction) as u32;
            let (effects, value) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.box".to_string(),
                    args: vec![value, const_u64(token as u64, 32)],
                    bits: 64,
                },
            )
        }
        Mnemonic::InitObj => {
            let token = operand_value(instruction) as u32;
            let (mut effects, address) = pop_stack();
            effects.push(SemanticEffect::Intrinsic {
                name: "dotnet.initobj".to_string(),
                args: vec![address, const_u64(token as u64, 32)],
                outputs: Vec::new(),
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::IsInst => {
            let token = operand_value(instruction) as u32;
            let (effects, value) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.isinst".to_string(),
                    args: vec![value, const_u64(token as u64, 32)],
                    bits: 64,
                },
            )
        }
        Mnemonic::StElemREF => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, index) = pop_stack();
            let (mut array_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            effects.append(&mut array_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Heap,
                addr: cil_array_element_address(array, index),
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StElemI1 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, index) = pop_stack();
            let (mut array_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            effects.append(&mut array_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Heap,
                addr: cil_array_element_address(array, index),
                expression: truncate_i8(value),
                bits: 8,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StElemI4 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, index) = pop_stack();
            let (mut array_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            effects.append(&mut array_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Heap,
                addr: cil_array_element_address(array, index),
                expression: truncate_i32(value),
                bits: 32,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StElemI2 => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, index) = pop_stack();
            let (mut array_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            effects.append(&mut array_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Heap,
                addr: cil_array_element_address(array, index),
                expression: truncate_i16(value),
                bits: 16,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::StElem => {
            let (mut effects, value) = pop_stack();
            let (mut more_effects, index) = pop_stack();
            let (mut array_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            effects.append(&mut array_effects);
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Heap,
                addr: cil_array_element_address(array, index),
                expression: value,
                bits: 64,
            });
            complete_with_effects(SemanticTerminator::FallThrough, effects)
        }
        Mnemonic::CastClass => {
            let token = operand_value(instruction) as u32;
            let (effects, value) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.castclass".to_string(),
                    args: vec![value, const_u64(token as u64, 32)],
                    bits: 64,
                },
            )
        }
        Mnemonic::UnboxAny => {
            let token = operand_value(instruction) as u32;
            let (effects, value) = pop_stack();
            push_with_prefix(
                effects,
                SemanticExpression::Intrinsic {
                    name: "cil.unbox.any".to_string(),
                    args: vec![value, const_u64(token as u64, 32)],
                    bits: 64,
                },
            )
        }
        Mnemonic::Volatile => {
            complete_with_effects(SemanticTerminator::FallThrough, vec![SemanticEffect::Nop])
        }
        Mnemonic::Constrained => {
            complete_with_effects(SemanticTerminator::FallThrough, vec![SemanticEffect::Nop])
        }
        Mnemonic::Cpobj => {
            complete_with_effects(SemanticTerminator::FallThrough, vec![SemanticEffect::Nop])
        }
        Mnemonic::LdToken => push_expression(const_u64(operand_value(instruction), 64)),
        mnemonic
            if matches!(mnemonic, |Mnemonic::AddOvf| Mnemonic::AddOvfUn
                | Mnemonic::MulOvf
                | Mnemonic::MulOvfUn
                | Mnemonic::RemUn
                | Mnemonic::SubOvf
                | Mnemonic::SubOvfUn
                | Mnemonic::Cgt
                | Mnemonic::ConvI
                | Mnemonic::ConvOvfI
                | Mnemonic::ConvOvfIUn
                | Mnemonic::ConvOvfI1
                | Mnemonic::ConvOvfI1Un
                | Mnemonic::ConvOvfI2
                | Mnemonic::ConvOvfI2Un
                | Mnemonic::ConvOvfI4
                | Mnemonic::ConvOvfI4Un
                | Mnemonic::ConvOvfI8
                | Mnemonic::ConvOvfI8Un
                | Mnemonic::ConvOvfU
                | Mnemonic::ConvOvfUUn
                | Mnemonic::ConvOvfU1
                | Mnemonic::ConvOvfU1Un
                | Mnemonic::ConvOvfU2
                | Mnemonic::ConvOvfU2Un
                | Mnemonic::ConvOvfU4
                | Mnemonic::ConvOvfU4Un
                | Mnemonic::ConvOvfU8
                | Mnemonic::ConvOvfU8Un
                | Mnemonic::ConvRUn
                | Mnemonic::ConvR4
                | Mnemonic::ConvU
                | Mnemonic::ConvU1
                | Mnemonic::CastClass
                | Mnemonic::CkInite
                | Mnemonic::CpBlk
                | Mnemonic::End
                | Mnemonic::EndFilter
                | Mnemonic::InitBlk
                | Mnemonic::Jmp
                | Mnemonic::LdElmI
                | Mnemonic::LdElmI1
                | Mnemonic::LdElmI2
                | Mnemonic::LdElmU8
                | Mnemonic::LdElmR4
                | Mnemonic::LdIndI
                | Mnemonic::LdIndI1
                | Mnemonic::LdIndI2
                | Mnemonic::LdVirtFtn
                | Mnemonic::Leave
                | Mnemonic::LeaveS
                | Mnemonic::LocAlloc
                | Mnemonic::MkRefAny
                | Mnemonic::No
                | Mnemonic::ReadOnly
                | Mnemonic::RefAnyType
                | Mnemonic::RefAnyVal
                | Mnemonic::ReThrow
                | Mnemonic::SizeOf
                | Mnemonic::StElemI
                | Mnemonic::StElemI1
                | Mnemonic::StElemI8
                | Mnemonic::StElemR4
                | Mnemonic::StElemR8
                | Mnemonic::Tail
                | Mnemonic::Unaligned
                | Mnemonic::Unbox) =>
        {
            complete_intrinsic(instruction, format!("cil.{:?}", mnemonic))
        }
        _ => InstructionSemantics {
            version: 1,
            status: SemanticStatus::Partial,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Intrinsic {
                name: format!("cil.{:?}", instruction.mnemonic),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
            terminator: SemanticTerminator::FallThrough,
            diagnostics: vec![diagnostic(
                SemanticDiagnosticKind::ArchSpecific {
                    name: "cil.stack".to_string(),
                },
                "CIL stack effects currently modeled as intrinsics",
            )],
        },
    }
}

fn complete_intrinsic(instruction: &Instruction<'_>, name: String) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        temporaries: Vec::new(),
        effects: vec![SemanticEffect::Intrinsic {
            name,
            args: operand_args(instruction),
            outputs: Vec::new(),
        }],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    }
}

fn push_expression(expression: SemanticExpression) -> InstructionSemantics {
    complete_with_effects(SemanticTerminator::FallThrough, push_effects(expression))
}

fn push_with_prefix(
    mut effects: Vec<SemanticEffect>,
    expression: SemanticExpression,
) -> InstructionSemantics {
    effects.extend(push_effects(expression));
    complete_with_effects(SemanticTerminator::FallThrough, effects)
}

fn pop_to_location(dst: SemanticLocation) -> InstructionSemantics {
    let (mut effects, value) = pop_stack();
    effects.push(SemanticEffect::Set {
        dst,
        expression: value,
    });
    complete_with_effects(SemanticTerminator::FallThrough, effects)
}

fn operand_args(instruction: &Instruction<'_>) -> Vec<SemanticExpression> {
    if instruction.operand_size() == 0 {
        return Vec::new();
    }
    vec![SemanticExpression::Const {
        value: operand_value(instruction) as u128,
        bits: (instruction.operand_size() * 8) as u16,
    }]
}

fn operand_value(instruction: &Instruction<'_>) -> u64 {
    let mut bytes = [0u8; 8];
    let operand = instruction.operand_bytes();
    let len = operand.len().min(bytes.len());
    bytes[..len].copy_from_slice(&operand[..len]);
    u64::from_le_bytes(bytes)
}

fn diagnostic(kind: SemanticDiagnosticKind, message: &str) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.to_string(),
    }
}

fn complete_with_effects(
    terminator: SemanticTerminator,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

fn cil_stack_pointer() -> SemanticLocation {
    SemanticLocation::Register {
        name: "cil.stack.sp".to_string(),
        bits: 64,
    }
}

fn cil_argument(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.arg.{index}"),
        bits: 64,
    }
}

fn cil_argument_address(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.arg.addr.{index}"),
        bits: 64,
    }
}

fn cil_local(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.local.{index}"),
        bits: 64,
    }
}

fn cil_local_address(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.local.addr.{index}"),
        bits: 64,
    }
}

fn read(location: SemanticLocation) -> SemanticExpression {
    SemanticExpression::Read(Box::new(location))
}

fn cil_field_address(token: u32, object: Option<SemanticExpression>) -> SemanticExpression {
    let mut args = Vec::new();
    if let Some(object) = object {
        args.push(object);
    }
    args.push(const_u64(token as u64, 32));
    SemanticExpression::Intrinsic {
        name: "cil.field.addr".to_string(),
        args,
        bits: 64,
    }
}

fn cil_array_element_address(
    array: SemanticExpression,
    index: SemanticExpression,
) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: "cil.array.elem.addr".to_string(),
        args: vec![array, index],
        bits: 64,
    }
}

fn compare(
    op: SemanticOperationCompare,
    left: SemanticExpression,
    right: SemanticExpression,
) -> SemanticExpression {
    SemanticExpression::Compare {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits: 1,
    }
}

fn bool_to_i64(condition: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Select {
        condition: Box::new(condition),
        when_true: Box::new(const_u64(1, 64)),
        when_false: Box::new(const_u64(0, 64)),
        bits: 64,
    }
}

fn sign_extend_i32(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::SignExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 32,
        }),
        bits: 64,
    }
}

fn sign_extend_i16(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::SignExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 16,
        }),
        bits: 64,
    }
}

fn sign_extend_i8(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::SignExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 8,
        }),
        bits: 64,
    }
}

fn sign_extend_i64(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::SignExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 64,
        }),
        bits: 64,
    }
}

fn zero_extend_i16(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 16,
        }),
        bits: 64,
    }
}

fn zero_extend_i32(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 32,
        }),
        bits: 64,
    }
}

fn zero_extend_i8(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 8,
        }),
        bits: 64,
    }
}

fn zero_extend_i64(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 64,
        }),
        bits: 64,
    }
}

fn truncate_i32(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 32,
    }
}

fn truncate_i16(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 16,
    }
}

fn truncate_i8(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 8,
    }
}

fn const_u64(value: u64, bits: u16) -> SemanticExpression {
    SemanticExpression::Const {
        value: value as u128,
        bits,
    }
}

fn binary(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    SemanticExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

fn unary(op: SemanticOperationUnary, arg: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Unary {
        op,
        arg: Box::new(arg),
        bits,
    }
}

fn push_effects(expression: SemanticExpression) -> Vec<SemanticEffect> {
    let sp = cil_stack_pointer();
    let sp_read = read(sp.clone());
    let next_sp = binary(
        SemanticOperationBinary::Add,
        sp_read.clone(),
        const_u64(8, 64),
        64,
    );
    vec![
        SemanticEffect::Store {
            space: SemanticAddressSpace::Stack,
            addr: sp_read,
            expression,
            bits: 64,
        },
        SemanticEffect::Set {
            dst: sp,
            expression: next_sp,
        },
    ]
}

fn pop_stack() -> (Vec<SemanticEffect>, SemanticExpression) {
    let sp = cil_stack_pointer();
    let sp_read = read(sp.clone());
    let prev_sp = binary(SemanticOperationBinary::Sub, sp_read, const_u64(8, 64), 64);
    let value = SemanticExpression::Load {
        space: SemanticAddressSpace::Stack,
        addr: Box::new(prev_sp.clone()),
        bits: 64,
    };
    (
        vec![SemanticEffect::Set {
            dst: sp,
            expression: prev_sp,
        }],
        value,
    )
}

fn peek_stack() -> (Vec<SemanticEffect>, SemanticExpression) {
    let sp_read = read(cil_stack_pointer());
    let top_addr = binary(SemanticOperationBinary::Sub, sp_read, const_u64(8, 64), 64);
    (
        Vec::new(),
        SemanticExpression::Load {
            space: SemanticAddressSpace::Stack,
            addr: Box::new(top_addr),
            bits: 64,
        },
    )
}

fn sign_extend(value: u64, source_bits: u16) -> u64 {
    if source_bits == 0 || source_bits >= 64 {
        return value;
    }
    let shift = 64 - source_bits;
    (((value << shift) as i64) >> shift) as u64
}
