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
            if let Some(writeback) =
                writeback_effect(instruction, operands.get(1)?, operands.get(2))
            {
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
            if let Some(writeback) =
                writeback_effect(instruction, operands.get(1)?, operands.get(2))
            {
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
            if let Some(writeback) =
                writeback_effect(instruction, operands.get(1)?, operands.get(2))
            {
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
            if let Some(writeback) =
                writeback_effect(instruction, operands.get(1)?, operands.get(2))
            {
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
            if let Some(writeback) =
                writeback_effect(instruction, operands.get(1)?, operands.get(2))
            {
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
        _ if matches!(
            instruction.mnemonic().unwrap_or(""),
            "cas"
                | "casa"
                | "casab"
                | "casah"
                | "casal"
                | "casalb"
                | "casalh"
                | "casb"
                | "cash"
                | "casl"
                | "caslb"
                | "caslh"
        ) =>
        {
            build_cas(machine, instruction, operands)
        }
        _ if matches!(
            instruction.mnemonic().unwrap_or(""),
            "casp" | "caspa" | "caspal" | "caspl"
        ) =>
        {
            build_casp(machine, instruction, operands)
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

fn build_cas(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let observed = operand_location(machine, operands.first()?)?;
    let expected = operand_expression(operands.first()?)?;
    let desired = operand_expression(operands.get(1)?)?;
    let addr = effective_memory_address(instruction, operands.get(2)?, operands.get(3))?;
    let bits = match instruction.mnemonic().unwrap_or("") {
        "casab" | "casalb" | "casb" | "caslb" => 8,
        "casah" | "casalh" | "cash" | "caslh" => 16,
        _ => location_bits(&observed).min(64),
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::AtomicCmpXchg {
            space: SemanticAddressSpace::Default,
            addr,
            expected: truncate_to_bits(expected, bits),
            desired: truncate_to_bits(desired, bits),
            bits,
            observed,
        }],
    ))
}

fn build_casp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let observed_low = operand_location(machine, operands.first()?)?;
    let observed_high = operand_location(machine, operands.get(1)?)?;
    let expected_low = operand_expression(operands.first()?)?;
    let expected_high = operand_expression(operands.get(1)?)?;
    let desired_low = operand_expression(operands.get(2)?)?;
    let desired_high = operand_expression(operands.get(3)?)?;
    let addr = effective_memory_address(instruction, operands.get(4)?, operands.get(5))?;
    let element_bits = location_bits(&observed_low);
    let total_bits = element_bits.checked_mul(2)?;
    let temp_id = 0u32;
    let temp_location = SemanticLocation::Temporary {
        id: temp_id,
        bits: total_bits,
    };
    let temp_expr = SemanticExpression::Read(Box::new(temp_location.clone()));
    Some(InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: vec![crate::semantics::SemanticTemporary {
            id: temp_id,
            bits: total_bits,
            name: Some(format!(
                "arm64_{}",
                instruction.mnemonic().unwrap_or("casp")
            )),
        }],
        effects: vec![
            SemanticEffect::AtomicCmpXchg {
                space: SemanticAddressSpace::Default,
                addr,
                expected: SemanticExpression::Concat {
                    parts: vec![expected_high, expected_low],
                    bits: total_bits,
                },
                desired: SemanticExpression::Concat {
                    parts: vec![desired_high, desired_low],
                    bits: total_bits,
                },
                bits: total_bits,
                observed: temp_location,
            },
            SemanticEffect::Set {
                dst: observed_low,
                expression: SemanticExpression::Extract {
                    arg: Box::new(temp_expr.clone()),
                    lsb: 0,
                    bits: element_bits,
                },
            },
            SemanticEffect::Set {
                dst: observed_high,
                expression: SemanticExpression::Extract {
                    arg: Box::new(temp_expr),
                    lsb: element_bits,
                    bits: element_bits,
                },
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}
