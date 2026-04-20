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
    match instruction.mnemonic().unwrap_or("") {
        "nop" | "pacibsp" | "autibsp" | "xpaclri" | "csdb" | "dmb" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        "msr" => {
            build_effect_intrinsic(instruction, operands, Vec::new(), String::from("arm64.msr"))
        }
        "svc" => Some(InstructionSemantics {
            version: 1,
            status: SemanticStatus::Complete,
            temporaries: Vec::new(),
            effects: vec![SemanticEffect::Trap {
                kind: SemanticTrapKind::Syscall,
            }],
            terminator: SemanticTerminator::Trap,
            diagnostics: Vec::new(),
        }),
        "mrs" => build_intrinsic_fallthrough(
            machine,
            instruction,
            operands,
            Some(vec![operand_location(machine, operands.first()?)?]),
        ),
        "prfm" => Some(complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
        )),
        _ => None,
    }
}
