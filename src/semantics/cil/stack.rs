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
    InstructionSemantics, SemanticEffect, SemanticTerminator, SemanticTrapKind,
};

use super::common::{
    cil_argument, cil_argument_address, cil_local, cil_local_address, complete_with_effects,
    const_u64, operand_value, peek_stack, pop_stack, pop_to_location, push_effects,
    push_expression, read, sign_extend, sign_extend_i8, sign_extend_i16, sign_extend_i32,
    sign_extend_i64, zero_extend_i8, zero_extend_i16, zero_extend_i32, zero_extend_i64,
};

pub(crate) fn build(instruction: &Instruction<'_>) -> Option<InstructionSemantics> {
    match instruction.mnemonic {
        Mnemonic::Nop => Some(complete_with_effects(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        Mnemonic::Break => Some(InstructionSemantics {
            version: 1,
            status: crate::semantics::SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Breakpoint,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        Mnemonic::DUP => {
            let (mut effects, value) = peek_stack();
            effects.extend(push_effects(value));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::Pop => {
            let (effects, _) = pop_stack();
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::LdNull => Some(push_expression(const_u64(0, 64))),
        Mnemonic::LdcI40 => Some(push_expression(const_u64(0, 64))),
        Mnemonic::LdcI41 => Some(push_expression(const_u64(1, 64))),
        Mnemonic::LdcI42 => Some(push_expression(const_u64(2, 64))),
        Mnemonic::LdcI43 => Some(push_expression(const_u64(3, 64))),
        Mnemonic::LdcI44 => Some(push_expression(const_u64(4, 64))),
        Mnemonic::LdcI45 => Some(push_expression(const_u64(5, 64))),
        Mnemonic::LdcI46 => Some(push_expression(const_u64(6, 64))),
        Mnemonic::LdcI47 => Some(push_expression(const_u64(7, 64))),
        Mnemonic::LdcI48 => Some(push_expression(const_u64(8, 64))),
        Mnemonic::LdcI4M1 => Some(push_expression(const_u64(u64::MAX, 64))),
        Mnemonic::LdcI4S => Some(push_expression(const_u64(
            sign_extend(operand_value(instruction), 8),
            64,
        ))),
        Mnemonic::LdcI4 => Some(push_expression(const_u64(
            sign_extend(operand_value(instruction), 32),
            64,
        ))),
        Mnemonic::LdcI8 => Some(push_expression(const_u64(operand_value(instruction), 64))),
        Mnemonic::LdcR4 => Some(push_expression(const_u64(operand_value(instruction), 64))),
        Mnemonic::LdcR8 => Some(push_expression(const_u64(operand_value(instruction), 64))),
        Mnemonic::LdArg0 => Some(push_expression(read(cil_argument(0)))),
        Mnemonic::LdArg1 => Some(push_expression(read(cil_argument(1)))),
        Mnemonic::LdArg2 => Some(push_expression(read(cil_argument(2)))),
        Mnemonic::LdArg3 => Some(push_expression(read(cil_argument(3)))),
        Mnemonic::LdArgS | Mnemonic::LdArg => Some(push_expression(read(cil_argument(
            operand_value(instruction) as u32,
        )))),
        Mnemonic::LdArgAS | Mnemonic::LdArgA => Some(push_expression(read(cil_argument_address(
            operand_value(instruction) as u32,
        )))),
        Mnemonic::LdLoc0 => Some(push_expression(read(cil_local(0)))),
        Mnemonic::LdLoc1 => Some(push_expression(read(cil_local(1)))),
        Mnemonic::LdLoc2 => Some(push_expression(read(cil_local(2)))),
        Mnemonic::LdLoc3 => Some(push_expression(read(cil_local(3)))),
        Mnemonic::LdLocS | Mnemonic::LdLoc => Some(push_expression(read(cil_local(
            operand_value(instruction) as u32,
        )))),
        Mnemonic::LdLocAS | Mnemonic::LdLocA => Some(push_expression(read(cil_local_address(
            operand_value(instruction) as u32,
        )))),
        Mnemonic::StLoc0 => Some(pop_to_location(cil_local(0))),
        Mnemonic::StLoc1 => Some(pop_to_location(cil_local(1))),
        Mnemonic::StLoc2 => Some(pop_to_location(cil_local(2))),
        Mnemonic::StLoc3 => Some(pop_to_location(cil_local(3))),
        Mnemonic::StLocS | Mnemonic::SLoc => Some(pop_to_location(cil_local(operand_value(
            instruction,
        ) as u32))),
        Mnemonic::StArgS | Mnemonic::StArg => Some(pop_to_location(cil_argument(operand_value(
            instruction,
        ) as u32))),
        Mnemonic::LdStr => Some(push_expression(const_u64(operand_value(instruction), 64))),
        Mnemonic::ConvI4 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i32(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::ConvI2 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i16(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::ConvI1 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i8(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::ConvI8 | Mnemonic::ConvI => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i64(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::ConvU2 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i16(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::ConvU1 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i8(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::ConvU4 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i32(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::ConvU | Mnemonic::ConvU8 => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i64(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        _ => None,
    }
}
