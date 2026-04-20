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

extern crate capstone;

mod atomic;
mod common;
mod control;
mod integer;
mod memory;
mod multiply;
mod system;
mod vector;

use common::*;

use crate::Architecture;
use crate::semantics::{
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticOperationBinary, SemanticOperationCompare, SemanticStatus, SemanticTerminator,
    SemanticTrapKind,
};
use capstone::Insn;
use capstone::arch::ArchOperand;
use capstone::arch::arm64::Arm64Insn;

#[cfg(test)]
mod tests;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
) -> InstructionSemantics {
    if let Some(semantics) = control::build(instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = integer::build(machine, instruction, operands, condition_code) {
        return semantics;
    }
    if let Some(semantics) = multiply::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = memory::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = atomic::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = system::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = vector::build(machine, instruction, operands, condition_code) {
        return semantics;
    }
    unsupported_fallthrough(instruction, "arm64 mnemonic not implemented")
}
