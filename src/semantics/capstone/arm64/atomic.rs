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

pub(super) fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    match instruction.id().0 {
        _ if instruction.mnemonic().unwrap_or("") == "ldaxp" => {
            build_load_pair(machine, instruction, operands)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldxp" => {
            build_load_pair(machine, instruction, operands)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldar" => {
            build_ldr(machine, instruction, operands)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldaxr"
            || instruction.mnemonic().unwrap_or("") == "ldxr" =>
        {
            build_exclusive_load(machine, instruction, operands, LoadKind::FullWidth)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldapr" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
            let mut effects = vec![SemanticEffect::Set {
                dst: dst.clone(),
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(addr),
                    bits: dst.bits(),
                },
            }];
            if let Some(writeback) = writeback_effect(instruction, operands.get(1)?, operands.get(2)) {
                effects.push(writeback);
            }
            Some(complete(SemanticTerminator::FallThrough, effects))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldaprb" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
            let mut effects = vec![SemanticEffect::Set {
                dst: dst.clone(),
                expression: zero_extend_load(addr, 8, dst.bits()),
            }];
            if let Some(writeback) = writeback_effect(instruction, operands.get(1)?, operands.get(2)) {
                effects.push(writeback);
            }
            Some(complete(SemanticTerminator::FallThrough, effects))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldarb" => {
            build_zero_extend_load(machine, instruction, operands, 8)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldaxrb"
            || instruction.mnemonic().unwrap_or("") == "ldxrb" =>
        {
            build_exclusive_load(machine, instruction, operands, LoadKind::ZeroExtend(8))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldarh" => {
            build_zero_extend_load(machine, instruction, operands, 16)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldaxrh"
            || instruction.mnemonic().unwrap_or("") == "ldxrh" =>
        {
            build_exclusive_load(machine, instruction, operands, LoadKind::ZeroExtend(16))
        }
        _ if instruction.mnemonic().unwrap_or("") == "stlrh" => {
            let src = operand_expression(operands.first()?)?;
            let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
            let mut effects = vec![SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: truncate_to_bits(src, 16),
                bits: 16,
            }];
            if let Some(writeback) = writeback_effect(instruction, operands.get(1)?, operands.get(2)) {
                effects.push(writeback);
            }
            Some(complete(SemanticTerminator::FallThrough, effects))
        }
        _ if instruction.mnemonic().unwrap_or("") == "stlr" => {
            let src = operand_expression(operands.first()?)?;
            let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
            let mut effects = vec![SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: src.clone(),
                bits: src.bits(),
            }];
            if let Some(writeback) = writeback_effect(instruction, operands.get(1)?, operands.get(2)) {
                effects.push(writeback);
            }
            Some(complete(SemanticTerminator::FallThrough, effects))
        }
        _ if instruction.mnemonic().unwrap_or("") == "stlrb" => {
            let src = operand_expression(operands.first()?)?;
            let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
            let mut effects = vec![SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: truncate_to_bits(src, 8),
                bits: 8,
            }];
            if let Some(writeback) = writeback_effect(instruction, operands.get(1)?, operands.get(2)) {
                effects.push(writeback);
            }
            Some(complete(SemanticTerminator::FallThrough, effects))
        }
        _ if matches!(
            instruction.mnemonic().unwrap_or(""),
            "stlxr" | "stlxrb" | "stlxrh" | "stxr" | "stxrb" | "stxrh" | "stxp" | "stlxp"
        ) =>
        {
            build_effect_intrinsic(
                instruction,
                operands,
                operands
                    .first()
                    .and_then(|operand| operand_location(machine, operand))
                    .map(|dst| vec![dst])
                    .unwrap_or_default(),
                format!("arm64.{}", instruction.mnemonic().unwrap_or("intrinsic")),
            )
        }
        _ if matches!(instruction.mnemonic().unwrap_or(""), "casal" | "cas") => {
            build_intrinsic_fallthrough(
                machine,
                instruction,
                operands,
                operands
                    .first()
                    .and_then(|operand| operand_location(machine, operand))
                    .map(|dst| vec![dst]),
            )
        }
        _ if matches!(instruction.mnemonic().unwrap_or(""), "ldaddal" | "ldset") => {
            build_intrinsic_fallthrough(
                machine,
                instruction,
                operands,
                operands
                    .first()
                    .and_then(|operand| operand_location(machine, operand))
                    .map(|dst| vec![dst]),
            )
        }
        _ => None,
    }
}
