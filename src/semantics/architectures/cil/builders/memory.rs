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
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticTerminator,
};

use super::super::helpers::common::{
    cil_array_element_address, cil_array_length_address, cil_field_address, complete_with_effects,
    effect_runtime_ternary_intrinsic, operand_value, pop_stack, push_expression, push_with_prefix,
    sign_extend_i8, sign_extend_i16, sign_extend_i32, sign_extend_i64, truncate_i8, truncate_i16,
    truncate_i32, zero_extend_i8, zero_extend_i16, zero_extend_i32, zero_extend_i64,
};

pub(crate) fn build(instruction: &CilInstructionView) -> Option<InstructionSemantics> {
    match instruction.mnemonic_text() {
        "ldlen" => {
            let (effects, array) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_array_length_address(array)),
                    bits: 64,
                },
            ))
        }
        "ldelem.ref" => heap_load(64, Identity::Direct),
        "ldelem.u1" => heap_load(8, Identity::Zero8),
        "ldelem.u2" => heap_load(16, Identity::Zero16),
        "ldelem.u4" => heap_load(32, Identity::Zero32),
        "ldelem.i1" => heap_load(8, Identity::Sign8),
        "ldelem.i2" => heap_load(16, Identity::Sign16),
        "ldelem.i4" => heap_load(32, Identity::Sign32),
        "ldelem" | "ldelem.i" | "ldelem.r8" => heap_load(64, Identity::Direct),
        "ldelem.i8" => heap_load(64, Identity::Sign64),
        "ldelem.u8" => heap_load(64, Identity::Zero64),
        "ldelem.r4" => heap_load(32, Identity::Direct),
        "ldelema" | "ldelem.a" => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            Some(push_with_prefix(
                effects,
                cil_array_element_address(array, index),
            ))
        }
        "ldind.ref" => direct_load(SemanticAddressSpace::Default, 64, Identity::Direct),
        "ldind.u1" => direct_load(SemanticAddressSpace::Default, 8, Identity::Zero8),
        "ldind.u2" => direct_load(SemanticAddressSpace::Default, 16, Identity::Zero16),
        "ldind.i1" => direct_load(SemanticAddressSpace::Default, 8, Identity::Sign8),
        "ldind.i2" => direct_load(SemanticAddressSpace::Default, 16, Identity::Sign16),
        "ldind.u4" => direct_load(SemanticAddressSpace::Default, 32, Identity::Zero32),
        "ldind.i4" => direct_load(SemanticAddressSpace::Default, 32, Identity::Sign32),
        "ldind.i8" => direct_load(SemanticAddressSpace::Default, 64, Identity::Zero64),
        "ldind.i" => direct_load(SemanticAddressSpace::Default, 64, Identity::Sign64),
        "ldind.r4" => direct_load(SemanticAddressSpace::Default, 32, Identity::Direct),
        "ldind.r8" | "ldobj" => direct_load(SemanticAddressSpace::Default, 64, Identity::Direct),
        "ldfld" => {
            let token = operand_value(instruction) as u32;
            let (effects, object) = pop_stack();
            Some(push_with_prefix(
                effects,
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Heap,
                    addr: Box::new(cil_field_address(token, Some(object))),
                    bits: 64,
                },
            ))
        }
        "ldflda" => {
            let token = operand_value(instruction) as u32;
            let (effects, object) = pop_stack();
            Some(push_with_prefix(
                effects,
                cil_field_address(token, Some(object)),
            ))
        }
        "ldsfld" => Some(push_expression(SemanticExpression::Load {
            space: SemanticAddressSpace::Global,
            addr: Box::new(cil_field_address(operand_value(instruction) as u32, None)),
            bits: 64,
        })),
        "ldsflda" => Some(push_expression(cil_field_address(
            operand_value(instruction) as u32,
            None,
        ))),
        "stfld" => {
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
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "stsfld" => {
            let token = operand_value(instruction) as u32;
            let (mut effects, value) = pop_stack();
            effects.push(SemanticEffect::Store {
                space: SemanticAddressSpace::Global,
                addr: cil_field_address(token, None),
                expression: value,
                bits: 64,
            });
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        "stind.i4" => store_default(32, StoreValue::Trunc32),
        "stind.i1" => store_default(8, StoreValue::Trunc8),
        "stind.i2" => store_default(16, StoreValue::Trunc16),
        "stind.i8" | "stind.i" | "stind.ref" | "stind.r8" | "stobj" => {
            store_default(64, StoreValue::Direct)
        }
        "stind.r4" => store_default(32, StoreValue::Trunc32),
        "stelem.ref" => store_heap(64, StoreValue::Direct),
        "stelem.i1" => store_heap(8, StoreValue::Trunc8),
        "stelem.i" | "stelem.i8" | "stelem.r8" | "stelem" => store_heap(64, StoreValue::Direct),
        "stelem.r4" | "stelem.i4" => store_heap(32, StoreValue::Trunc32),
        "stelem.i2" => store_heap(16, StoreValue::Trunc16),
        "cpblk" => Some(effect_runtime_ternary_intrinsic(instruction, "cil.cpblk")),
        "initblk" => Some(effect_runtime_ternary_intrinsic(instruction, "cil.initblk")),
        _ => None,
    }
}

enum Identity {
    Direct,
    Sign8,
    Sign16,
    Sign32,
    Sign64,
    Zero8,
    Zero16,
    Zero32,
    Zero64,
}

enum StoreValue {
    Direct,
    Trunc8,
    Trunc16,
    Trunc32,
}

fn heap_load(bits: u16, identity: Identity) -> Option<InstructionSemantics> {
    let (mut effects, index) = pop_stack();
    let (mut more_effects, array) = pop_stack();
    effects.append(&mut more_effects);
    let load = SemanticExpression::Load {
        space: SemanticAddressSpace::Heap,
        addr: Box::new(cil_array_element_address(array, index)),
        bits,
    };
    Some(push_with_prefix(effects, apply_identity(load, identity)))
}

fn direct_load(
    space: SemanticAddressSpace,
    bits: u16,
    identity: Identity,
) -> Option<InstructionSemantics> {
    let (effects, address) = pop_stack();
    let load = SemanticExpression::Load {
        space,
        addr: Box::new(address),
        bits,
    };
    Some(push_with_prefix(effects, apply_identity(load, identity)))
}

fn store_default(bits: u16, value_kind: StoreValue) -> Option<InstructionSemantics> {
    let (mut effects, value) = pop_stack();
    let (mut more_effects, address) = pop_stack();
    effects.append(&mut more_effects);
    effects.push(SemanticEffect::Store {
        space: SemanticAddressSpace::Default,
        addr: address,
        expression: apply_store_value(value, value_kind),
        bits,
    });
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}

fn store_heap(bits: u16, value_kind: StoreValue) -> Option<InstructionSemantics> {
    let (mut effects, value) = pop_stack();
    let (mut more_effects, index) = pop_stack();
    let (mut array_effects, array) = pop_stack();
    effects.append(&mut more_effects);
    effects.append(&mut array_effects);
    effects.push(SemanticEffect::Store {
        space: SemanticAddressSpace::Heap,
        addr: cil_array_element_address(array, index),
        expression: apply_store_value(value, value_kind),
        bits,
    });
    Some(complete_with_effects(
        SemanticTerminator::FallThrough,
        effects,
    ))
}

fn apply_identity(value: SemanticExpression, identity: Identity) -> SemanticExpression {
    match identity {
        Identity::Direct => value,
        Identity::Sign8 => sign_extend_i8(value),
        Identity::Sign16 => sign_extend_i16(value),
        Identity::Sign32 => sign_extend_i32(value),
        Identity::Sign64 => sign_extend_i64(value),
        Identity::Zero8 => zero_extend_i8(value),
        Identity::Zero16 => zero_extend_i16(value),
        Identity::Zero32 => zero_extend_i32(value),
        Identity::Zero64 => zero_extend_i64(value),
    }
}

fn apply_store_value(value: SemanticExpression, kind: StoreValue) -> SemanticExpression {
    match kind {
        StoreValue::Direct => value,
        StoreValue::Trunc8 => truncate_i8(value),
        StoreValue::Trunc16 => truncate_i16(value),
        StoreValue::Trunc32 => truncate_i32(value),
    }
}
