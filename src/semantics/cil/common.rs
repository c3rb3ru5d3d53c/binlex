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
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticDiagnostic, SemanticDiagnosticKind,
    SemanticEffect, SemanticExpression, SemanticLocation, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticStatus,
    SemanticTerminator,
};

pub(crate) fn partial_intrinsic_fallthrough(
    instruction: &Instruction<'_>,
    message: &str,
) -> InstructionSemantics {
    InstructionSemantics {
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
            message,
        )],
    }
}

pub(crate) fn push_runtime_unary_intrinsic(
    instruction: &Instruction<'_>,
    name: &str,
) -> InstructionSemantics {
    let (effects, value) = pop_stack();
    let mut args = vec![value];
    args.extend(operand_args(instruction));
    push_with_prefix(
        effects,
        SemanticExpression::Intrinsic {
            name: name.to_string(),
            args,
            bits: 64,
        },
    )
}

pub(crate) fn push_runtime_binary_intrinsic(
    instruction: &Instruction<'_>,
    name: &str,
) -> InstructionSemantics {
    let (mut effects, right) = pop_stack();
    let (mut more_effects, left) = pop_stack();
    effects.append(&mut more_effects);
    let mut args = vec![left, right];
    args.extend(operand_args(instruction));
    push_with_prefix(
        effects,
        SemanticExpression::Intrinsic {
            name: name.to_string(),
            args,
            bits: 64,
        },
    )
}

pub(crate) fn effect_runtime_ternary_intrinsic(
    instruction: &Instruction<'_>,
    name: &str,
) -> InstructionSemantics {
    let (mut effects, third) = pop_stack();
    let (mut more_effects, second) = pop_stack();
    let (mut first_effects, first) = pop_stack();
    effects.append(&mut more_effects);
    effects.append(&mut first_effects);
    let mut args = vec![first, second, third];
    args.extend(operand_args(instruction));
    effects.push(SemanticEffect::Intrinsic {
        name: name.to_string(),
        args,
        outputs: Vec::new(),
    });
    complete_with_effects(SemanticTerminator::FallThrough, effects)
}

pub(crate) fn push_expression(expression: SemanticExpression) -> InstructionSemantics {
    complete_with_effects(SemanticTerminator::FallThrough, push_effects(expression))
}

pub(crate) fn push_with_prefix(
    mut effects: Vec<SemanticEffect>,
    expression: SemanticExpression,
) -> InstructionSemantics {
    effects.extend(push_effects(expression));
    complete_with_effects(SemanticTerminator::FallThrough, effects)
}

pub(crate) fn pop_to_location(dst: SemanticLocation) -> InstructionSemantics {
    let (mut effects, value) = pop_stack();
    effects.push(SemanticEffect::Set {
        dst,
        expression: value,
    });
    complete_with_effects(SemanticTerminator::FallThrough, effects)
}

pub(crate) fn operand_args(instruction: &Instruction<'_>) -> Vec<SemanticExpression> {
    if instruction.operand_size() == 0 {
        return Vec::new();
    }
    vec![SemanticExpression::Const {
        value: operand_value(instruction) as u128,
        bits: (instruction.operand_size() * 8) as u16,
    }]
}

pub(crate) fn operand_value(instruction: &Instruction<'_>) -> u64 {
    let mut bytes = [0u8; 8];
    let operand = instruction.operand_bytes();
    let len = operand.len().min(bytes.len());
    bytes[..len].copy_from_slice(&operand[..len]);
    u64::from_le_bytes(bytes)
}

pub(crate) fn diagnostic(kind: SemanticDiagnosticKind, message: &str) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.to_string(),
    }
}

pub(crate) fn complete_with_effects(
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

pub(crate) fn cil_stack_pointer() -> SemanticLocation {
    SemanticLocation::Register {
        name: "cil.stack.sp".to_string(),
        bits: 64,
    }
}

pub(crate) fn cil_argument(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.arg.{index}"),
        bits: 64,
    }
}

pub(crate) fn cil_argument_address(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.arg.addr.{index}"),
        bits: 64,
    }
}

pub(crate) fn cil_local(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.local.{index}"),
        bits: 64,
    }
}

pub(crate) fn cil_local_address(index: u32) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("cil.local.addr.{index}"),
        bits: 64,
    }
}

pub(crate) fn read(location: SemanticLocation) -> SemanticExpression {
    SemanticExpression::Read(Box::new(location))
}

pub(crate) fn cil_field_address(
    token: u32,
    object: Option<SemanticExpression>,
) -> SemanticExpression {
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

pub(crate) fn cil_array_element_address(
    array: SemanticExpression,
    index: SemanticExpression,
) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: "cil.array.elem.addr".to_string(),
        args: vec![array, index],
        bits: 64,
    }
}

pub(crate) fn cil_array_length_address(array: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: "cil.array.length.addr".to_string(),
        args: vec![array],
        bits: 64,
    }
}

pub(crate) fn compare(
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

pub(crate) fn bool_to_i64(condition: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Select {
        condition: Box::new(condition),
        when_true: Box::new(const_u64(1, 64)),
        when_false: Box::new(const_u64(0, 64)),
        bits: 64,
    }
}

pub(crate) fn sign_extend_i32(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn sign_extend_i16(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn sign_extend_i8(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn sign_extend_i64(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn zero_extend_i16(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn zero_extend_i32(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn zero_extend_i8(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn zero_extend_i64(value: SemanticExpression) -> SemanticExpression {
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

pub(crate) fn truncate_i32(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 32,
    }
}

pub(crate) fn truncate_i16(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 16,
    }
}

pub(crate) fn truncate_i8(value: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(value),
        lsb: 0,
        bits: 8,
    }
}

pub(crate) fn const_u64(value: u64, bits: u16) -> SemanticExpression {
    SemanticExpression::Const {
        value: value as u128,
        bits,
    }
}

pub(crate) fn binary(
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

pub(crate) fn unary(
    op: SemanticOperationUnary,
    arg: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    SemanticExpression::Unary {
        op,
        arg: Box::new(arg),
        bits,
    }
}

pub(crate) fn push_effects(expression: SemanticExpression) -> Vec<SemanticEffect> {
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

pub(crate) fn pop_stack() -> (Vec<SemanticEffect>, SemanticExpression) {
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

pub(crate) fn peek_stack() -> (Vec<SemanticEffect>, SemanticExpression) {
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

pub(crate) fn sign_extend(value: u64, source_bits: u16) -> u64 {
    if source_bits == 0 || source_bits >= 64 {
        return value;
    }
    let shift = 64 - source_bits;
    (((value << shift) as i64) >> shift) as u64
}
