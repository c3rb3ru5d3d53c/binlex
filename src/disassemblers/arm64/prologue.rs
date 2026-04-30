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

pub fn is_function_prologue<F>(decode_operand: F) -> bool
where
    F: Fn(usize, usize) -> Option<Arm64DecodedOperand>,
{
    matches!(decode_operand(0, 0), Some(Arm64DecodedOperand::Register(dst0)) if dst0 == "x29")
        && matches!(decode_operand(0, 1), Some(Arm64DecodedOperand::Register(dst1)) if dst1 == "x30")
        && matches!(decode_operand(0, 2), Some(Arm64DecodedOperand::Memory(_)))
        && matches!(decode_operand(1, 0), Some(Arm64DecodedOperand::Register(dst)) if dst == "x29")
        && matches!(decode_operand(1, 1), Some(Arm64DecodedOperand::Register(src)) if src == "sp")
}
