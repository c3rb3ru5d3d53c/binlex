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
        "madd" => build_madd(machine, operands),
        "smaddl" => build_smaddl(machine, operands),
        "smull" => build_smull(machine, operands),
        "smulh" => build_smulh(machine, operands),
        "smsubl" => build_smsubl(machine, operands),
        "msub" => build_msub(machine, operands),
        "mul" => build_mul(machine, operands),
        "mneg" => build_mneg(machine, operands),
        "umulh" => build_umulh(machine, operands),
        "sdiv" => build_sdiv(machine, operands),
        "udiv" => build_udiv(machine, operands),
        "umull" => build_umull(machine, operands),
        "umaddl" => build_umaddl(machine, operands),
        "umsubl" => build_umsubl(machine, operands),
        "umnegl" => build_umnegl(machine, operands),
        _ => None,
    }
}
