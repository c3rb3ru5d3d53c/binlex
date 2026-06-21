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

use crate::irs::lir::LirInstruction;

pub mod builders;
pub mod helpers;
pub mod instruction;
pub mod operand;

#[cfg(test)]
mod tests;

pub use instruction::InstructionDetailArm64;
pub use operand::{Arm64MemoryOperandView, Arm64OperandKind, Arm64OperandView};

pub fn build(view: InstructionDetailArm64) -> Option<LirInstruction> {
    if let Some(lir) = builders::control::build(&view) {
        return Some(lir);
    }
    if let Some(lir) = builders::integer::build(&view) {
        return Some(lir);
    }
    if let Some(lir) = builders::multiply::build(&view) {
        return Some(lir);
    }
    if let Some(lir) = builders::fp::build(&view) {
        return Some(lir);
    }
    if let Some(lir) = builders::atomic::build(&view) {
        return Some(lir);
    }
    if let Some(lir) = builders::memory::build(&view) {
        return Some(lir);
    }
    if let Some(lir) = builders::system::build(&view) {
        return Some(lir);
    }
    if let Some(lir) = builders::vector::build(&view) {
        return Some(lir);
    }
    None
}
