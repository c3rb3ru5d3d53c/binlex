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
    cil_array_element_address, cil_array_length_address, cil_field_address, complete_with_effects,
    effect_runtime_ternary_intrinsic, operand_value, pop_stack, push_expression, push_with_prefix,
    sign_extend_i8, sign_extend_i16, sign_extend_i32, sign_extend_i64, truncate_i8, truncate_i16,
    truncate_i32, zero_extend_i8, zero_extend_i16, zero_extend_i32, zero_extend_i64,
};

pub(crate) fn build(instruction: &Instruction<'_>) -> Option<InstructionSemantics> {
    match instruction.mnemonic {
        Mnemonic::LdLen => {
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
        Mnemonic::LdElmRef => heap_load(64, Identity::Direct),
        Mnemonic::LdElmU1 => heap_load(8, Identity::Zero8),
        Mnemonic::LdElmU2 => heap_load(16, Identity::Zero16),
        Mnemonic::LdElmU4 => heap_load(32, Identity::Zero32),
        Mnemonic::LdElmI1 => heap_load(8, Identity::Sign8),
        Mnemonic::LdElmI2 => heap_load(16, Identity::Sign16),
        Mnemonic::LdElmI4 => heap_load(32, Identity::Sign32),
        Mnemonic::LdElm | Mnemonic::LdElmR8 => heap_load(64, Identity::Direct),
        Mnemonic::LdElmI => heap_load(64, Identity::Sign64),
        Mnemonic::LdElmU8 => heap_load(64, Identity::Zero64),
        Mnemonic::LdElmR4 => heap_load(32, Identity::Direct),
        Mnemonic::LdElmA => {
            let (mut effects, index) = pop_stack();
            let (mut more_effects, array) = pop_stack();
            effects.append(&mut more_effects);
            Some(push_with_prefix(
                effects,
                cil_array_element_address(array, index),
            ))
        }
        Mnemonic::LdIndRef => direct_load(SemanticAddressSpace::Default, 64, Identity::Direct),
        Mnemonic::LdIndU1 => direct_load(SemanticAddressSpace::Default, 8, Identity::Zero8),
        Mnemonic::LdIndU2 => direct_load(SemanticAddressSpace::Default, 16, Identity::Zero16),
        Mnemonic::LdIndI1 => direct_load(SemanticAddressSpace::Default, 8, Identity::Sign8),
        Mnemonic::LdIndI2 => direct_load(SemanticAddressSpace::Default, 16, Identity::Sign16),
        Mnemonic::LdIndU4 => direct_load(SemanticAddressSpace::Default, 32, Identity::Zero32),
        Mnemonic::LdIndI4 => direct_load(SemanticAddressSpace::Default, 32, Identity::Sign32),
        Mnemonic::LdIndU8 => direct_load(SemanticAddressSpace::Default, 64, Identity::Zero64),
        Mnemonic::LdIndI => direct_load(SemanticAddressSpace::Default, 64, Identity::Sign64),
        Mnemonic::LdIndR4 => direct_load(SemanticAddressSpace::Default, 32, Identity::Direct),
        Mnemonic::LdIndR8 | Mnemonic::LdObj => {
            direct_load(SemanticAddressSpace::Default, 64, Identity::Direct)
        }
        Mnemonic::LdFld => {
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
        Mnemonic::LdFldA => {
            let token = operand_value(instruction) as u32;
            let (effects, object) = pop_stack();
            Some(push_with_prefix(
                effects,
                cil_field_address(token, Some(object)),
            ))
        }
        Mnemonic::LdSFld => Some(push_expression(SemanticExpression::Load {
            space: SemanticAddressSpace::Global,
            addr: Box::new(cil_field_address(operand_value(instruction) as u32, None)),
            bits: 64,
        })),
        Mnemonic::LdSFldA => Some(push_expression(cil_field_address(
            operand_value(instruction) as u32,
            None,
        ))),
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
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
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
            Some(complete_with_effects(
                SemanticTerminator::FallThrough,
                effects,
            ))
        }
        Mnemonic::StIndI4 => store_default(32, StoreValue::Trunc32),
        Mnemonic::StIndI1 => store_default(8, StoreValue::Trunc8),
        Mnemonic::StIndI2 => store_default(16, StoreValue::Trunc16),
        Mnemonic::StIndI8
        | Mnemonic::StIndI
        | Mnemonic::StIndRef
        | Mnemonic::StIndR8
        | Mnemonic::StObj => store_default(64, StoreValue::Direct),
        Mnemonic::StIndR4 => store_default(32, StoreValue::Trunc32),
        Mnemonic::StElemREF => store_heap(64, StoreValue::Direct),
        Mnemonic::StElemI1 => store_heap(8, StoreValue::Trunc8),
        Mnemonic::StElemI | Mnemonic::StElemI8 | Mnemonic::StElemR8 | Mnemonic::StElem => {
            store_heap(64, StoreValue::Direct)
        }
        Mnemonic::StElemR4 | Mnemonic::StElemI4 => store_heap(32, StoreValue::Trunc32),
        Mnemonic::StElemI2 => store_heap(16, StoreValue::Trunc16),
        Mnemonic::CpBlk => Some(effect_runtime_ternary_intrinsic(instruction, "cil.cpblk")),
        Mnemonic::InitBlk => Some(effect_runtime_ternary_intrinsic(instruction, "cil.initblk")),
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
