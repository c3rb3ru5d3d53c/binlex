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

use crate::Architecture;
use crate::semantics::{InstructionSemantics, SemanticEffect, SemanticTerminator};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::X86Insn;

pub fn build(
    _machine: Architecture,
    instruction: &Insn,
    _operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    if matches!(
        mnemonic,
        "stosb" | "stosw" | "stosd" | "rep stosd" | "rep stosw" | "movsw" | "rep movsb"
    ) {
        return Some(crate::semantics::capstone::x86::common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: format!("x86.{}", mnemonic.replace(' ', "_")),
                args: Vec::new(),
                outputs: Vec::new(),
            }],
        ));
    }

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_SCASD as u32 => {
            Some(crate::semantics::capstone::x86::common::complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Intrinsic {
                    name: "x86.scasd".to_string(),
                    args: Vec::new(),
                    outputs: Vec::new(),
                }],
            ))
        }
        _ => None,
    }
}
