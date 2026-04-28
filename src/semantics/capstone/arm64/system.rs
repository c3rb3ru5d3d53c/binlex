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
use capstone::arch::arm64::Arm64Reg;

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

fn parse_operands_text(instruction: &Insn) -> Vec<String> {
    instruction
        .op_str()
        .unwrap_or("")
        .split(',')
        .map(|part| part.trim().to_string())
        .filter(|part| !part.is_empty())
        .collect()
}

fn register_bits_from_name(name: &str) -> Option<u16> {
    match name.chars().next()? {
        'w' => Some(32),
        'x' => Some(64),
        'b' => Some(8),
        'h' => Some(16),
        's' => Some(32),
        'd' => Some(64),
        'q' => Some(128),
        'v' => Some(128),
        _ => {
            if name == "sp" || name == "wsp" || name == "fp" || name == "lr" {
                Some(64)
            } else {
                None
            }
        }
    }
}

fn semantic_register_name_from_text(name: &str) -> Option<String> {
    let reg = match name.trim().to_ascii_lowercase().as_str() {
        "w0" => Arm64Reg::ARM64_REG_W0,
        "w1" => Arm64Reg::ARM64_REG_W1,
        "w2" => Arm64Reg::ARM64_REG_W2,
        "w3" => Arm64Reg::ARM64_REG_W3,
        "w4" => Arm64Reg::ARM64_REG_W4,
        "w5" => Arm64Reg::ARM64_REG_W5,
        "w6" => Arm64Reg::ARM64_REG_W6,
        "w7" => Arm64Reg::ARM64_REG_W7,
        "w8" => Arm64Reg::ARM64_REG_W8,
        "w9" => Arm64Reg::ARM64_REG_W9,
        "w10" => Arm64Reg::ARM64_REG_W10,
        "w11" => Arm64Reg::ARM64_REG_W11,
        "w12" => Arm64Reg::ARM64_REG_W12,
        "w13" => Arm64Reg::ARM64_REG_W13,
        "w14" => Arm64Reg::ARM64_REG_W14,
        "w15" => Arm64Reg::ARM64_REG_W15,
        "w16" => Arm64Reg::ARM64_REG_W16,
        "w17" => Arm64Reg::ARM64_REG_W17,
        "w18" => Arm64Reg::ARM64_REG_W18,
        "w19" => Arm64Reg::ARM64_REG_W19,
        "w20" => Arm64Reg::ARM64_REG_W20,
        "w21" => Arm64Reg::ARM64_REG_W21,
        "w22" => Arm64Reg::ARM64_REG_W22,
        "w23" => Arm64Reg::ARM64_REG_W23,
        "w24" => Arm64Reg::ARM64_REG_W24,
        "w25" => Arm64Reg::ARM64_REG_W25,
        "w26" => Arm64Reg::ARM64_REG_W26,
        "w27" => Arm64Reg::ARM64_REG_W27,
        "w28" => Arm64Reg::ARM64_REG_W28,
        "w29" => Arm64Reg::ARM64_REG_W29,
        "w30" => Arm64Reg::ARM64_REG_W30,
        "x0" => Arm64Reg::ARM64_REG_X0,
        "x1" => Arm64Reg::ARM64_REG_X1,
        "x2" => Arm64Reg::ARM64_REG_X2,
        "x3" => Arm64Reg::ARM64_REG_X3,
        "x4" => Arm64Reg::ARM64_REG_X4,
        "x5" => Arm64Reg::ARM64_REG_X5,
        "x6" => Arm64Reg::ARM64_REG_X6,
        "x7" => Arm64Reg::ARM64_REG_X7,
        "x8" => Arm64Reg::ARM64_REG_X8,
        "x9" => Arm64Reg::ARM64_REG_X9,
        "x10" => Arm64Reg::ARM64_REG_X10,
        "x11" => Arm64Reg::ARM64_REG_X11,
        "x12" => Arm64Reg::ARM64_REG_X12,
        "x13" => Arm64Reg::ARM64_REG_X13,
        "x14" => Arm64Reg::ARM64_REG_X14,
        "x15" => Arm64Reg::ARM64_REG_X15,
        "x16" => Arm64Reg::ARM64_REG_X16,
        "x17" => Arm64Reg::ARM64_REG_X17,
        "x18" => Arm64Reg::ARM64_REG_X18,
        "x19" => Arm64Reg::ARM64_REG_X19,
        "x20" => Arm64Reg::ARM64_REG_X20,
        "x21" => Arm64Reg::ARM64_REG_X21,
        "x22" => Arm64Reg::ARM64_REG_X22,
        "x23" => Arm64Reg::ARM64_REG_X23,
        "x24" => Arm64Reg::ARM64_REG_X24,
        "x25" => Arm64Reg::ARM64_REG_X25,
        "x26" => Arm64Reg::ARM64_REG_X26,
        "x27" => Arm64Reg::ARM64_REG_X27,
        "x28" => Arm64Reg::ARM64_REG_X28,
        "x29" | "fp" => Arm64Reg::ARM64_REG_X29,
        "x30" | "lr" => Arm64Reg::ARM64_REG_X30,
        "sp" => Arm64Reg::ARM64_REG_SP,
        _ => return None,
    };
    Some(format!("reg_{}", reg as u32))
}

fn register_location_from_text(name: &str) -> Option<SemanticLocation> {
    let normalized_name = name.trim().to_ascii_lowercase();
    Some(SemanticLocation::Register {
        bits: register_bits_from_name(&normalized_name)?,
        name: semantic_register_name_from_text(&normalized_name)?,
    })
}

fn register_expression_from_text(name: &str) -> Option<SemanticExpression> {
    Some(SemanticExpression::Read(Box::new(
        register_location_from_text(name)?,
    )))
}

fn build_mrs(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
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
    let dst = operands
        .first()
        .and_then(|operand| operand_location(machine, operand))
        .or_else(|| {
            let fields = parse_operands_text(instruction);
            register_location_from_text(fields.first()?)
        })?;
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

fn build_msr(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let semantic_name = if instruction_mentions_tpidr_el0(instruction) {
        TPIDR_EL0_SEMANTIC_NAME
    } else if instruction_mentions_fpcr(instruction) {
        FPCR_SEMANTIC_NAME
    } else {
        return build_effect_intrinsic(
            instruction,
            operands,
            Vec::new(),
            String::from("arm64.msr"),
        );
    };
    let _ = machine;
    let src = operands.get(1).and_then(operand_expression).or_else(|| {
        let fields = parse_operands_text(instruction);
        register_expression_from_text(fields.get(1)?)
    })?;
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
        "nop" | "pacibsp" | "autibsp" | "xpaclri" | "csdb" | "dmb" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        "msr" => build_msr(machine, instruction, operands),
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
        "mrs" => build_mrs(machine, instruction, operands),
        "prfm" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        _ => None,
    }
}
