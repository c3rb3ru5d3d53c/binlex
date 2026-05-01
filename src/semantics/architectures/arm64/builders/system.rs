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

use crate::semantics::architectures::arm64::Arm64InstructionView;
use crate::semantics::architectures::arm64::helpers::{
    binary, bool_const, complete, const_u64, flag_expr, set_flag, unary_not,
};
use crate::semantics::architectures::arm64::{Arm64OperandKind, Arm64OperandView};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticStatus, SemanticTerminator, SemanticTrapKind,
};

const TPIDR_EL0_SEMANTIC_NAME: &str = "arm64_sysreg_tpidr_el0";
const FPCR_SEMANTIC_NAME: &str = "arm64_sysreg_fpcr";

pub(crate) fn build(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    match view.mnemonic.as_str() {
        "axflag" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![
                set_flag("n", bool_const(false)),
                set_flag(
                    "z",
                    binary(
                        SemanticOperationBinary::Or,
                        flag_expr("z"),
                        flag_expr("v"),
                        1,
                    ),
                ),
                set_flag(
                    "c",
                    binary(
                        SemanticOperationBinary::And,
                        flag_expr("c"),
                        unary_not(flag_expr("v")),
                        1,
                    ),
                ),
                set_flag("v", bool_const(false)),
            ],
        )),
        "cfinv" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![set_flag("c", unary_not(flag_expr("c")))],
        )),
        "nop" | "pacibsp" | "autibsp" | "xpaclri" | "csdb" | "dmb" | "prfm" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        "svc" => Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            abi: None,
            encoding: None,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Syscall,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        "mrs" => build_mrs(view),
        "msr" => build_msr(view),
        _ => None,
    }
}

fn instruction_mentions_tpidr_el0(view: &Arm64InstructionView) -> bool {
    view.operand_text.as_deref().is_some_and(|op_str| {
        let lowered = op_str.to_ascii_lowercase();
        lowered.contains("tpidr_el0") || lowered.contains("s3_3_c13_c0_2")
    }) || view.bytes.as_slice().ends_with(&[0xd0, 0x3b, 0xd5])
        || view.bytes.as_slice().ends_with(&[0xd0, 0x1b, 0xd5])
}

fn instruction_mentions_fpcr(view: &Arm64InstructionView) -> bool {
    view.operand_text.as_deref().is_some_and(|op_str| {
        let lowered = op_str.to_ascii_lowercase();
        lowered.contains("fpcr") || lowered.contains("s3_3_c4_c4_0")
    }) || view.bytes.as_slice().ends_with(&[0x44, 0x3b, 0xd5])
        || view.bytes.as_slice().ends_with(&[0x44, 0x1b, 0xd5])
}

fn build_mrs(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let semantic_name = if instruction_mentions_tpidr_el0(view) {
        TPIDR_EL0_SEMANTIC_NAME
    } else if instruction_mentions_fpcr(view) {
        FPCR_SEMANTIC_NAME
    } else {
        return None;
    };
    let dst = view.operands().iter().find_map(register_location)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: crate::semantics::SemanticExpression::Read(Box::new(
                SemanticLocation::Register {
                    name: semantic_name.to_string(),
                    bits: 64,
                },
            )),
        }],
    ))
}

fn build_msr(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let semantic_name = if instruction_mentions_tpidr_el0(view) {
        TPIDR_EL0_SEMANTIC_NAME
    } else if instruction_mentions_fpcr(view) {
        FPCR_SEMANTIC_NAME
    } else {
        return None;
    };
    let src = view.operands().iter().rev().find_map(operand_expression)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: SemanticLocation::Register {
                name: semantic_name.to_string(),
                bits: 64,
            },
            expression: src,
        }],
    ))
}

fn register_location(operand: &Arm64OperandView) -> Option<SemanticLocation> {
    Some(SemanticLocation::Register {
        name: operand.register_name()?.to_string(),
        bits: operand_bits(operand),
    })
}

fn operand_expression(operand: &Arm64OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        Arm64OperandKind::Register => Some(SemanticExpression::Read(Box::new(
            SemanticLocation::Register {
                name: operand.register_name()?.to_string(),
                bits: operand_bits(operand),
            },
        ))),
        Arm64OperandKind::Immediate => Some(const_u64(
            operand.immediate_value()? as i64 as u64,
            operand_bits(operand),
        )),
        _ => None,
    }
}

fn operand_bits(operand: &Arm64OperandView) -> u16 {
    if operand.size_bits == 0 {
        64
    } else {
        operand.size_bits
    }
}
