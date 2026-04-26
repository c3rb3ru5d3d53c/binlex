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
        id if id == Arm64Insn::ARM64_INS_LDP as u32 => {
            build_load_pair(machine, instruction, operands)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldnp" => {
            build_load_pair(machine, instruction, operands)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldpsw" => {
            build_load_pair_signed_word(machine, instruction, operands)
        }
        id if id == Arm64Insn::ARM64_INS_STP as u32 => {
            build_store_pair(machine, instruction, operands)
        }
        _ if instruction.mnemonic().unwrap_or("") == "stnp" => {
            build_store_pair(machine, instruction, operands)
        }
        id if id == Arm64Insn::ARM64_INS_LDR as u32 => build_ldr(machine, instruction, operands),
        _ if instruction.mnemonic().unwrap_or("") == "ldur" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Set {
                    dst: dst.clone(),
                    expression: SemanticExpression::Load {
                        space: SemanticAddressSpace::Default,
                        addr: Box::new(addr),
                        bits: dst.bits(),
                    },
                }],
            ))
        }
        id if id == Arm64Insn::ARM64_INS_LDRSW as u32 => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
            let mut effects = vec![SemanticEffect::Set {
                dst: dst.clone(),
                expression: sign_extend_load(addr, 32, dst.bits()),
            }];
            if let Some(writeback) =
                writeback_effect(instruction, operands.get(1)?, operands.get(2))
            {
                effects.push(writeback);
            }
            Some(complete(SemanticTerminator::FallThrough, effects))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldrsh" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Set {
                    dst: dst.clone(),
                    expression: sign_extend_load(addr, 16, dst.bits()),
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldtrsh" => {
            build_sign_extend_load_base_immediate(machine, operands, 16)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldursw" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Set {
                    dst: dst.clone(),
                    expression: sign_extend_load(addr, 32, dst.bits()),
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldursh" => {
            build_sign_extend_load_base_immediate(machine, operands, 16)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldtrsw" => {
            build_sign_extend_load_base_immediate(machine, operands, 32)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldrsb" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Set {
                    dst: dst.clone(),
                    expression: sign_extend_load(addr, 8, dst.bits()),
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldtrsb" => {
            build_sign_extend_load_base_immediate(machine, operands, 8)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldursb" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Set {
                    dst: dst.clone(),
                    expression: sign_extend_load(addr, 8, dst.bits()),
                }],
            ))
        }
        id if id == Arm64Insn::ARM64_INS_LDRH as u32 => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = effective_memory_address(instruction, operands.get(1)?, operands.get(2))?;
            let mut effects = vec![SemanticEffect::Set {
                dst: dst.clone(),
                expression: zero_extend_load(addr, 16, dst.bits()),
            }];
            if let Some(writeback) =
                writeback_effect(instruction, operands.get(1)?, operands.get(2))
            {
                effects.push(writeback);
            }
            Some(complete(SemanticTerminator::FallThrough, effects))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldurh" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Set {
                    dst: dst.clone(),
                    expression: zero_extend_load(addr, 16, dst.bits()),
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldtrh" => {
            build_zero_extend_load_base_immediate(machine, operands, 16)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldtr" => {
            build_plain_load_base_immediate(machine, operands)
        }
        _ if instruction.mnemonic().unwrap_or("") == "ldtrb" => {
            build_zero_extend_load_base_immediate(machine, operands, 8)
        }
        id if id == Arm64Insn::ARM64_INS_STR as u32 => {
            let src = operand_expression(operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: src.clone(),
                    bits: src.bits(),
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "stur" => {
            let src = operand_expression(operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: src.clone(),
                    bits: src.bits(),
                }],
            ))
        }
        id if id == Arm64Insn::ARM64_INS_LDRB as u32 => {
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
        _ if instruction.mnemonic().unwrap_or("") == "ldurb" => {
            let dst = operand_location(machine, operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Set {
                    dst: dst.clone(),
                    expression: zero_extend_load(addr, 8, dst.bits()),
                }],
            ))
        }
        id if id == Arm64Insn::ARM64_INS_STRB as u32 => {
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
        _ if instruction.mnemonic().unwrap_or("") == "sturb" => {
            let src = operand_expression(operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: truncate_to_bits(src, 8),
                    bits: 8,
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "sttr" => {
            let src = operand_expression(operands.first()?)?;
            let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: src.clone(),
                    bits: src.bits(),
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "sttrb" => {
            let src = operand_expression(operands.first()?)?;
            let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: truncate_to_bits(src, 8),
                    bits: 8,
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "sttrh" => {
            let src = operand_expression(operands.first()?)?;
            let addr = base_immediate_load_address(operands.get(1)?, operands.get(2))?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: truncate_to_bits(src, 16),
                    bits: 16,
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "sturh" => {
            let src = operand_expression(operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: truncate_to_bits(src, 16),
                    bits: 16,
                }],
            ))
        }
        _ if instruction.mnemonic().unwrap_or("") == "strh" => {
            let src = operand_expression(operands.first()?)?;
            let addr = memory_address(operands.get(1)?)?;
            Some(complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Store {
                    space: SemanticAddressSpace::Default,
                    addr,
                    expression: truncate_to_bits(src, 16),
                    bits: 16,
                }],
            ))
        }
        _ => None,
    }
}
