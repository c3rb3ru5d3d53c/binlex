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

pub(super) fn build(instruction: &Insn, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let bits = 64;
    let next = const_u64(
        instruction.address() + instruction.bytes().len() as u64,
        bits,
    );
    match instruction.id().0 {
        id if id == Arm64Insn::ARM64_INS_B as u32 => {
            let target = operand_expression(operands.first()?)?;
            let mnemonic = instruction.mnemonic().unwrap_or("");
            if mnemonic.starts_with("b.") {
                let condition = condition_from_suffix(mnemonic.strip_prefix("b.")?)?;
                Some(complete(
                    SemanticTerminator::Branch {
                        condition,
                        true_target: target,
                        false_target: next,
                    },
                    Vec::new(),
                ))
            } else {
                Some(complete(SemanticTerminator::Jump { target }, Vec::new()))
            }
        }
        id if id == Arm64Insn::ARM64_INS_BL as u32 => {
            let target = operand_expression(operands.first()?)?;
            Some(complete(
                SemanticTerminator::Call {
                    target,
                    return_target: Some(next),
                    does_return: Some(true),
                },
                Vec::new(),
            ))
        }
        id if id == Arm64Insn::ARM64_INS_BR as u32 => {
            let target = operand_expression(operands.first()?)?;
            Some(complete(SemanticTerminator::Jump { target }, Vec::new()))
        }
        id if id == Arm64Insn::ARM64_INS_BLR as u32 => {
            let target = operand_expression(operands.first()?)?;
            Some(complete(
                SemanticTerminator::Call {
                    target,
                    return_target: Some(next),
                    does_return: Some(true),
                },
                Vec::new(),
            ))
        }
        id if id == Arm64Insn::ARM64_INS_RET as u32 => {
            let expression = operands.first().and_then(operand_expression);
            Some(complete(
                SemanticTerminator::Return { expression },
                Vec::new(),
            ))
        }
        id if id == Arm64Insn::ARM64_INS_BRK as u32 => Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Breakpoint,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        id if id == Arm64Insn::ARM64_INS_CBZ as u32 || id == Arm64Insn::ARM64_INS_CBNZ as u32 => {
            let source = operand_expression(operands.first()?)?;
            let target = operand_expression(operands.get(1)?)?;
            let zero = const_u64(0, source.bits());
            let condition = compare(
                if id == Arm64Insn::ARM64_INS_CBZ as u32 {
                    SemanticOperationCompare::Eq
                } else {
                    SemanticOperationCompare::Ne
                },
                source,
                zero,
            );
            Some(complete(
                SemanticTerminator::Branch {
                    condition,
                    true_target: target,
                    false_target: next,
                },
                Vec::new(),
            ))
        }
        id if id == Arm64Insn::ARM64_INS_TBZ as u32 || id == Arm64Insn::ARM64_INS_TBNZ as u32 => {
            let source = operand_expression(operands.first()?)?;
            let bit_index = operand_immediate(operands.get(1)?)? as u16;
            let target = operand_expression(operands.get(2)?)?;
            let bit = SemanticExpression::Extract {
                arg: Box::new(source),
                lsb: bit_index,
                bits: 1,
            };
            let zero = bool_const(id == Arm64Insn::ARM64_INS_TBZ as u32);
            let condition = compare(SemanticOperationCompare::Eq, bit, zero);
            Some(complete(
                SemanticTerminator::Branch {
                    condition,
                    true_target: target,
                    false_target: next,
                },
                Vec::new(),
            ))
        }
        _ => None,
    }
}
