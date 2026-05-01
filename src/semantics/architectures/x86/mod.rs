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

use crate::semantics::InstructionSemantics;

pub mod builders;
pub mod flags;
pub mod helpers;
pub mod instruction;
pub mod operand;

pub use instruction::X86InstructionView;
pub use operand::{X86MemoryOperandView, X86OperandKind, X86OperandView};

pub fn build(view: X86InstructionView) -> Option<InstructionSemantics> {
    if let Some(semantics) = builders::control::build(view.machine, &view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::stack::build(&view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::integer::build(view.machine, &view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::logic::build(view.machine, &view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::bit::build(view.machine, &view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::shift::build(view.machine, &view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::fp::build(view.machine, &view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::string::build(view.machine, &view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::system::build(&view) {
        return Some(semantics);
    }
    if let Some(semantics) = builders::vector::build(view.machine, &view) {
        return Some(semantics);
    }
    None
}
