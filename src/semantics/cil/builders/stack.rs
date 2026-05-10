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

use crate::semantics::cil::InstructionDetailCil;
use crate::semantics::{Semantic, SemanticEffect, SemanticTerminator, SemanticTrapKind};

use super::super::helpers::common::{
    cil_argument, cil_argument_address, cil_local, cil_local_address, complete_with_effects,
    const_u64, operand_value, peek_stack, pop_stack, pop_to_location, push_effects,
    push_expression, read, sign_extend, sign_extend_i8, sign_extend_i16, sign_extend_i32,
    sign_extend_i64, zero_extend_i8, zero_extend_i16, zero_extend_i32, zero_extend_i64,
};

pub(crate) fn build(instruction: &InstructionDetailCil) -> Option<Semantic> {
    match instruction.mnemonic_text() {
        "nop" => Some(complete_with_effects(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        "break" => Some(Semantic {
            version: 1,
            status: crate::semantics::SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Breakpoint,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        "dup" => {
            let (mut effects, value) = peek_stack();
            effects.extend(push_effects(value));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "pop" => {
            let (effects, _) = pop_stack();
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "ldnull" => Some(push_expression(const_u64(0, 64))),
        "ldc.i4.0" => Some(push_expression(const_u64(0, 64))),
        "ldc.i4.1" => Some(push_expression(const_u64(1, 64))),
        "ldc.i4.2" => Some(push_expression(const_u64(2, 64))),
        "ldc.i4.3" => Some(push_expression(const_u64(3, 64))),
        "ldc.i4.4" => Some(push_expression(const_u64(4, 64))),
        "ldc.i4.5" => Some(push_expression(const_u64(5, 64))),
        "ldc.i4.6" => Some(push_expression(const_u64(6, 64))),
        "ldc.i4.7" => Some(push_expression(const_u64(7, 64))),
        "ldc.i4.8" => Some(push_expression(const_u64(8, 64))),
        "ldc.i4.m1" => Some(push_expression(const_u64(u64::MAX, 64))),
        "ldc.i4.s" => Some(push_expression(const_u64(
            sign_extend(operand_value(instruction), 8),
            64,
        ))),
        "ldc.i4" => Some(push_expression(const_u64(
            sign_extend(operand_value(instruction), 32),
            64,
        ))),
        "ldc.i8" => Some(push_expression(const_u64(operand_value(instruction), 64))),
        "ldc.r4" => Some(push_expression(const_u64(operand_value(instruction), 64))),
        "ldc.r8" => Some(push_expression(const_u64(operand_value(instruction), 64))),
        "ldarg.0" => Some(push_expression(read(cil_argument(0)))),
        "ldarg.1" => Some(push_expression(read(cil_argument(1)))),
        "ldarg.2" => Some(push_expression(read(cil_argument(2)))),
        "ldarg.3" => Some(push_expression(read(cil_argument(3)))),
        "ldarg.s" | "ldarg" => Some(push_expression(read(cil_argument(
            operand_value(instruction) as u32,
        )))),
        "ldarga.s" | "ldarga" => Some(push_expression(read(cil_argument_address(operand_value(
            instruction,
        )
            as u32)))),
        "ldloc.0" => Some(push_expression(read(cil_local(0)))),
        "ldloc.1" => Some(push_expression(read(cil_local(1)))),
        "ldloc.2" => Some(push_expression(read(cil_local(2)))),
        "ldloc.3" => Some(push_expression(read(cil_local(3)))),
        "ldloc.s" | "ldloc" => Some(push_expression(read(cil_local(
            operand_value(instruction) as u32
        )))),
        "ldloca.s" | "ldloca" => Some(push_expression(read(cil_local_address(operand_value(
            instruction,
        ) as u32)))),
        "stloc.0" => Some(pop_to_location(cil_local(0))),
        "stloc.1" => Some(pop_to_location(cil_local(1))),
        "stloc.2" => Some(pop_to_location(cil_local(2))),
        "stloc.3" => Some(pop_to_location(cil_local(3))),
        "stloc.s" | "stloc" => Some(pop_to_location(
            cil_local(operand_value(instruction) as u32),
        )),
        "starg.s" | "starg" => Some(pop_to_location(cil_argument(
            operand_value(instruction) as u32
        ))),
        "ldstr" => Some(push_expression(const_u64(operand_value(instruction), 64))),
        "conv.i4" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i32(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "conv.i2" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i16(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "conv.i1" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i8(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "conv.i8" | "conv.i" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(sign_extend_i64(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "conv.u2" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i16(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "conv.u1" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i8(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "conv.u4" => {
            let (mut effects, value) = pop_stack();
            effects.extend(push_effects(zero_extend_i32(value)));
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "conv.u" | "conv.u8" => {
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
