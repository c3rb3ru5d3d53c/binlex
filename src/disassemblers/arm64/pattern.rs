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

use crate::disassemblers::arm64::decoded::Arm64DecodedOperand;
use std::io::Error;

pub(crate) fn instruction_chromosome_mask(
    bytes: &[u8],
    wildcard_instruction: bool,
    decoded_operands: &[Arm64DecodedOperand],
    pair_memory_instruction: bool,
) -> Result<Vec<u8>, Error> {
    if wildcard_instruction {
        return Ok(vec![0xFF; bytes.len()]);
    }

    let has_memory_operand = decoded_operands
        .iter()
        .any(|operand| matches!(operand, Arm64DecodedOperand::Memory(_)));

    if !has_memory_operand || bytes.len() != 4 {
        return Ok(vec![0; bytes.len()]);
    }

    let bit_range = if pair_memory_instruction {
        (5usize, 21usize)
    } else {
        (5usize, 20usize)
    };

    Ok(mask_bits(bytes.len(), bit_range.0, bit_range.1))
}

fn mask_bits(byte_len: usize, start_bit: usize, end_bit: usize) -> Vec<u8> {
    let mut mask = vec![0u8; byte_len];
    for bit in start_bit..=end_bit {
        let byte_index = bit / 8;
        let bit_index = bit % 8;
        if byte_index < mask.len() {
            mask[byte_index] |= 1 << bit_index;
        }
    }
    mask
}
