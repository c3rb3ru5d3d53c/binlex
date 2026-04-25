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

use super::*;
use crate::semantics::SemanticLocation;

const TPIDR_EL0_SEMANTIC_NAME: &str = "arm64_sysreg_tpidr_el0";
const FPCR_SEMANTIC_NAME: &str = "arm64_sysreg_fpcr";

fn instruction_mentions_tpidr_el0(instruction: &Insn) -> bool {
    instruction
        .op_str()
        .is_some_and(|op_str| op_str.to_ascii_lowercase().contains("tpidr_el0"))
}

fn instruction_mentions_fpcr(instruction: &Insn) -> bool {
    instruction
        .op_str()
        .is_some_and(|op_str| op_str.to_ascii_lowercase().contains("fpcr"))
}

fn build_mrs(machine: Architecture, instruction: &Insn, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let semantic_name = if instruction_mentions_tpidr_el0(instruction) {
        TPIDR_EL0_SEMANTIC_NAME
    } else if instruction_mentions_fpcr(instruction) {
        FPCR_SEMANTIC_NAME
    } else {
        return build_intrinsic_fallthrough(
            machine,
            instruction,
            operands,
            Some(vec![operand_location(machine, operands.first()?)?]),
        );
    };
    let dst = operand_location(machine, operands.first()?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Read(Box::new(SemanticLocation::Register {
                name: semantic_name.to_string(),
                bits: 64,
            })),
        }],
    ))
}

fn build_msr(machine: Architecture, instruction: &Insn, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let semantic_name = if instruction_mentions_tpidr_el0(instruction) {
        TPIDR_EL0_SEMANTIC_NAME
    } else if instruction_mentions_fpcr(instruction) {
        FPCR_SEMANTIC_NAME
    } else {
        return build_effect_intrinsic(instruction, operands, Vec::new(), String::from("arm64.msr"));
    };
    let _ = machine;
    let src = operand_expression(operands.get(1)?)?;
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

pub(super) fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    match instruction.mnemonic().unwrap_or("") {
        "nop" | "pacibsp" | "autibsp" | "xpaclri" | "csdb" | "dmb" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        "msr" => build_msr(machine, instruction, operands),
        "svc" => Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Syscall,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        "mrs" => build_mrs(machine, instruction, operands),
        "prfm" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        _ => None,
    }
}
