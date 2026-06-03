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
    Lir, LirAddressSpace, LirDiagnostic, LirDiagnosticKind, LirEffect, LirExpression, LirLocation,
    LirOperationBinary, LirOperationCast, LirOperationCompare, LirOperationUnary, LirStatus,
    LirTerminator,
};

pub(crate) fn partial_intrinsic_fallthrough(
    instruction: &InstructionDetailCil,
    message: &str,
) -> Lir {
    Lir {
        version: 1,
        status: LirStatus::Partial,
        metadata: Default::default(),
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects: vec![LirEffect::Intrinsic {
            name: format!("cil.{}", instruction.mnemonic),
            args: Vec::new(),
            outputs: Vec::new(),
        }],
        terminator: LirTerminator::FallThrough,
        diagnostics: vec![diagnostic(
            LirDiagnosticKind::Named {
                name: "cil.stack".to_string(),
            },
            message,
        )],
    }
}

pub(crate) fn push_runtime_unary_intrinsic(instruction: &InstructionDetailCil, name: &str) -> Lir {
    let (effects, value) = pop_stack();
    let mut args = vec![value];
    args.extend(operand_args(instruction));
    push_with_prefix(
        effects,
        LirExpression::Intrinsic {
            name: name.to_string(),
            args,
            bits: 64,
        },
    )
}

pub(crate) fn push_runtime_binary_intrinsic(instruction: &InstructionDetailCil, name: &str) -> Lir {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    let mut args = vec![left, right];
    args.extend(operand_args(instruction));
    push_with_prefix(
        effects,
        LirExpression::Intrinsic {
            name: name.to_string(),
            args,
            bits: 64,
        },
    )
}

pub(crate) fn effect_runtime_ternary_intrinsic(
    instruction: &InstructionDetailCil,
    name: &str,
) -> Lir {
    let (mut effects, third) = pop_stack();
    let (mut more_effects, second) = pop_stack();
    let (mut first_effects, first) = pop_stack();
    effects.append(&mut more_effects);
    effects.append(&mut first_effects);
    let mut args = vec![first, second, third];
    args.extend(operand_args(instruction));
    effects.push(LirEffect::Intrinsic {
        name: name.to_string(),
        args,
        outputs: Vec::new(),
    });
    complete_with_effects(LirTerminator::FallThrough, effects)
}

pub(crate) fn push_expression(expression: LirExpression) -> Lir {
    complete_with_effects(LirTerminator::FallThrough, push_effects(expression))
}

pub(crate) fn push_with_prefix(mut effects: Vec<LirEffect>, expression: LirExpression) -> Lir {
    effects.extend(push_effects(expression));
    complete_with_effects(LirTerminator::FallThrough, effects)
}

pub(crate) fn pop_to_location(dst: LirLocation) -> Lir {
    let (mut effects, value) = pop_stack();
    effects.push(LirEffect::Set {
        dst,
        expression: value,
    });
    complete_with_effects(LirTerminator::FallThrough, effects)
}

pub(crate) fn operand_args(instruction: &InstructionDetailCil) -> Vec<LirExpression> {
    if instruction.operand_size() == 0 {
        return Vec::new();
    }
    vec![LirExpression::Const {
        value: operand_value(instruction) as u128,
        bits: (instruction.operand_size() * 8) as u16,
    }]
}

pub(crate) fn operand_value(instruction: &InstructionDetailCil) -> u64 {
    let mut bytes = [0u8; 8];
    let operand = instruction.operand_bytes();
    let len = operand.len().min(bytes.len());
    bytes[..len].copy_from_slice(&operand[..len]);
    u64::from_le_bytes(bytes)
}

pub(crate) fn diagnostic(kind: LirDiagnosticKind, message: &str) -> LirDiagnostic {
    LirDiagnostic {
        kind,
        message: message.to_string(),
    }
}

pub(crate) fn complete_with_effects(terminator: LirTerminator, effects: Vec<LirEffect>) -> Lir {
    Lir {
        version: 1,
        status: LirStatus::Complete,
        metadata: Default::default(),
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

pub(crate) fn cil_stack_pointer() -> LirLocation {
    LirLocation::Register {
        name: "cil.stack.sp".to_string(),
        bits: 64,
    }
}

pub(crate) fn cil_argument(index: u32) -> LirLocation {
    LirLocation::Register {
        name: format!("cil.arg.{index}"),
        bits: 64,
    }
}

pub(crate) fn cil_argument_address(index: u32) -> LirLocation {
    LirLocation::Register {
        name: format!("cil.arg.addr.{index}"),
        bits: 64,
    }
}

pub(crate) fn cil_local(index: u32) -> LirLocation {
    LirLocation::Register {
        name: format!("cil.local.{index}"),
        bits: 64,
    }
}

pub(crate) fn cil_local_address(index: u32) -> LirLocation {
    LirLocation::Register {
        name: format!("cil.local.addr.{index}"),
        bits: 64,
    }
}

pub(crate) fn read(location: LirLocation) -> LirExpression {
    LirExpression::Read(Box::new(location))
}

pub(crate) fn cil_field_address(token: u32, object: Option<LirExpression>) -> LirExpression {
    let mut args = Vec::new();
    if let Some(object) = object {
        args.push(object);
    }
    args.push(const_u64(token as u64, 32));
    LirExpression::Intrinsic {
        name: "cil.field.addr".to_string(),
        args,
        bits: 64,
    }
}

pub(crate) fn cil_array_element_address(
    array: LirExpression,
    index: LirExpression,
) -> LirExpression {
    LirExpression::Intrinsic {
        name: "cil.array.elem.addr".to_string(),
        args: vec![array, index],
        bits: 64,
    }
}

pub(crate) fn cil_array_length_address(array: LirExpression) -> LirExpression {
    LirExpression::Intrinsic {
        name: "cil.array.length.addr".to_string(),
        args: vec![array],
        bits: 64,
    }
}

pub(crate) fn compare(
    op: LirOperationCompare,
    left: LirExpression,
    right: LirExpression,
) -> LirExpression {
    LirExpression::Compare {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits: 1,
    }
}

pub(crate) fn bool_to_i64(condition: LirExpression) -> LirExpression {
    LirExpression::Select {
        condition: Box::new(condition),
        when_true: Box::new(const_u64(1, 64)),
        when_false: Box::new(const_u64(0, 64)),
        bits: 64,
    }
}

pub(crate) fn sign_extend_i32(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::SignExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 32,
        }),
        bits: 64,
    }
}

pub(crate) fn sign_extend_i16(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::SignExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 16,
        }),
        bits: 64,
    }
}

pub(crate) fn sign_extend_i8(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::SignExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 8,
        }),
        bits: 64,
    }
}

pub(crate) fn sign_extend_i64(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::SignExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 64,
        }),
        bits: 64,
    }
}

pub(crate) fn zero_extend_i16(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 16,
        }),
        bits: 64,
    }
}

pub(crate) fn zero_extend_i32(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 32,
        }),
        bits: 64,
    }
}

pub(crate) fn zero_extend_i8(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 8,
        }),
        bits: 64,
    }
}

pub(crate) fn zero_extend_i64(value: LirExpression) -> LirExpression {
    LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits: 64,
        }),
        bits: 64,
    }
}

pub(crate) fn truncate_i32(value: LirExpression) -> LirExpression {
    LirExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 32,
    }
}

pub(crate) fn truncate_i16(value: LirExpression) -> LirExpression {
    LirExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 16,
    }
}

pub(crate) fn truncate_i8(value: LirExpression) -> LirExpression {
    LirExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 8,
    }
}

pub(crate) fn const_u64(value: u64, bits: u16) -> LirExpression {
    LirExpression::Const {
        value: value as u128,
        bits,
    }
}

pub(crate) fn binary(
    op: LirOperationBinary,
    left: LirExpression,
    right: LirExpression,
    bits: u16,
) -> LirExpression {
    LirExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub(crate) fn unary(op: LirOperationUnary, arg: LirExpression, bits: u16) -> LirExpression {
    LirExpression::Unary {
        op,
        arg: Box::new(arg),
        bits,
    }
}

pub(crate) fn push_effects(expression: LirExpression) -> Vec<LirEffect> {
    let sp = cil_stack_pointer();
    let sp_read = read(sp.clone());
    let next_sp = binary(
        LirOperationBinary::Add,
        sp_read.clone(),
        const_u64(8, 64),
        64,
    );
    vec![
        LirEffect::Store {
            space: LirAddressSpace::Stack,
            addr: sp_read,
            expression,
            bits: 64,
        },
        LirEffect::Set {
            dst: sp,
            expression: next_sp,
        },
    ]
}

pub(crate) fn pop_stack() -> (Vec<LirEffect>, LirExpression) {
    let sp = cil_stack_pointer();
    let sp_read = read(sp.clone());
    let prev_sp = binary(LirOperationBinary::Sub, sp_read, const_u64(8, 64), 64);
    let value = LirExpression::Load {
        space: LirAddressSpace::Stack,
        addr: Box::new(prev_sp.clone()),
        bits: 64,
    };
    (
        vec![LirEffect::Set {
            dst: sp,
            expression: prev_sp,
        }],
        value,
    )
}

pub(crate) fn peek_stack() -> (Vec<LirEffect>, LirExpression) {
    let sp_read = read(cil_stack_pointer());
    let top_addr = binary(LirOperationBinary::Sub, sp_read, const_u64(8, 64), 64);
    (
        Vec::new(),
        LirExpression::Load {
            space: LirAddressSpace::Stack,
            addr: Box::new(top_addr),
            bits: 64,
        },
    )
}

pub(crate) fn sign_extend(value: u64, source_bits: u16) -> u64 {
    if source_bits == 0 || source_bits >= 64 {
        return value;
    }
    let shift = 64 - source_bits;
    (((value << shift) as i64) >> shift) as u64
}
