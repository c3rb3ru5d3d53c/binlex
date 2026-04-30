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

use crate::disassemblers::x86::decoded::X86DecodedOperand;
use std::io::{Error, ErrorKind};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum X86PatternOperandKind {
    Immediate,
    MemoryNoIndex,
    MemoryWithIndex,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct X86PatternOperand {
    pub operand_size_bits: usize,
    pub displacement_size_bits: usize,
    pub kind: X86PatternOperandKind,
}

pub(crate) fn is_unsupported_pattern_mnemonic(mnemonic: &str) -> bool {
    matches!(mnemonic, "movups" | "movaps" | "xorps" | "shufps")
}

pub(crate) fn contains_memory_operand(operands: &[X86DecodedOperand]) -> bool {
    operands
        .iter()
        .any(|operand| matches!(operand, X86DecodedOperand::Memory(_)))
}

pub(crate) fn contains_immutable_operand(operands: &[X86DecodedOperand]) -> bool {
    operands
        .iter()
        .any(|operand| matches!(operand, X86DecodedOperand::Immediate(_)))
}

pub(crate) fn is_immutable_instruction_to_pattern(
    mnemonic: &str,
    operands: &[X86DecodedOperand],
) -> bool {
    if !contains_immutable_operand(operands) {
        return false;
    }

    if matches!(mnemonic, "call" | "jmp")
        || mnemonic.starts_with('j')
        || matches!(mnemonic, "loop" | "loope" | "loopne")
    {
        return true;
    }

    if matches!(mnemonic, "mov" | "sub" | "add" | "inc" | "dec") {
        for operand in operands {
            if let X86DecodedOperand::Register(register_name) = operand {
                if matches!(register_name.as_str(), "rsp" | "rbp") {
                    return true;
                }
            }
        }
    }

    false
}

pub(crate) fn displacement_size_bits(displacement: u64) -> usize {
    match displacement {
        0x00..=0xFF => 8,
        0x100..=0xFFFF => 16,
        0x10000..=0xFFFFFFFF => 32,
        _ => 64,
    }
}

pub(crate) fn instruction_chromosome_mask(
    address: u64,
    bytes: &[u8],
    mnemonic: &str,
    wildcard_instruction: bool,
    operands: &[X86PatternOperand],
    decoded_operands: &[X86DecodedOperand],
) -> Result<Vec<u8>, Error> {
    if is_unsupported_pattern_mnemonic(mnemonic) {
        return Ok(vec![0; bytes.len()]);
    }

    if wildcard_instruction {
        return Ok(vec![0xFF; bytes.len()]);
    }

    let has_immutable_operand = contains_immutable_operand(decoded_operands);
    let has_memory_operand = contains_memory_operand(decoded_operands);

    if !has_immutable_operand && !has_memory_operand {
        return Ok(vec![0; bytes.len()]);
    }

    let instruction_size_bits = bytes.len() * 8;
    let mut wildcarded = vec![false; instruction_size_bits];

    let instruction_trailing_null_size_bits = bytes.iter().rev().take_while(|&&b| b == 0).count() * 8;
    let total_operand_size_bits = operands.iter().map(|operand| operand.operand_size_bits).sum::<usize>();

    if total_operand_size_bits > instruction_size_bits {
        return Ok(vec![0; bytes.len()]);
    }

    let is_immutable_signature = is_immutable_instruction_to_pattern(mnemonic, decoded_operands);

    if total_operand_size_bits == 0 && !operands.is_empty() {
        return Err(Error::new(
            ErrorKind::Other,
            format!(
                "Instruction -> 0x{:x}: instruction has operands but missing operand sizes",
                address
            ),
        ));
    }

    for operand in operands {
        let should_wildcard = match operand.kind {
            X86PatternOperandKind::Immediate => is_immutable_signature,
            X86PatternOperandKind::MemoryNoIndex => true,
            X86PatternOperandKind::MemoryWithIndex | X86PatternOperandKind::Other => false,
        };

        let mut op_size_bits = operand.operand_size_bits.max(operand.displacement_size_bits);
        if op_size_bits > instruction_size_bits {
            op_size_bits = operand.operand_size_bits;
        }

        if op_size_bits > instruction_size_bits {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Instruction -> 0x{:x}: instruction operand size exceeds instruction size",
                    address
                ),
            ));
        }

        let operand_offset_bits = instruction_size_bits - op_size_bits;

        if should_wildcard {
            for i in 0..op_size_bits {
                if operand_offset_bits + i >= wildcarded.len() {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "Instruction -> 0x{:x}: instruction wildcard index is out of bounds",
                            address
                        ),
                    ));
                }
                wildcarded[operand_offset_bits + i] = true;
            }
        }
    }

    let mut mask = vec![0u8; bytes.len()];
    for (byte_index, chunk) in wildcarded.chunks(8).enumerate() {
        let mut byte_mask = 0u8;
        for (bit_index, wildcarded_bit) in chunk.iter().enumerate() {
            if *wildcarded_bit {
                byte_mask |= 1 << (7 - bit_index);
            }
        }
        mask[byte_index] = byte_mask;
    }

    if is_immutable_signature && instruction_trailing_null_size_bits > 0 {
        let trailing_start = bytes.len() - (instruction_trailing_null_size_bits / 8);
        for byte_mask in mask.iter_mut().skip(trailing_start) {
            *byte_mask = 0xFF;
        }
    }

    Ok(mask)
}
