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

pub mod bit;
pub mod common;
pub mod control;
pub mod flags;
pub mod fp;
pub mod integer;
pub mod logic;
pub mod shift;
pub mod stack;
pub mod string;
pub mod system;
pub mod vector;

use crate::Architecture;
use crate::semantics::InstructionSemantics;
use capstone::Insn;
use capstone::arch::ArchOperand;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> InstructionSemantics {
    if let Some(semantics) = control::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = stack::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = integer::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = logic::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = shift::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = bit::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = string::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = system::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = vector::build(machine, instruction, operands) {
        return semantics;
    }
    if let Some(semantics) = fp::build(machine, instruction, operands) {
        return semantics;
    }
    common::unsupported_fallthrough(instruction, "x86 mnemonic not implemented")
}
