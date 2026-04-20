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
    _condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    match instruction.mnemonic().unwrap_or("") {
        "movi" => build_intrinsic_fallthrough(
            machine,
            instruction,
            operands,
            Some(vec![operand_location(machine, operands.first()?)?]),
        ),
        "fmov" => build_fmov(machine, instruction, operands),
        "fabs" => build_fabs(machine, operands),
        "fneg" => build_fneg(machine, operands),
        "fcmp" | "fcmpe" | "fccmp" => build_fcmp_intrinsic(machine, instruction, operands),
        "fadd" | "fmul" | "fmadd" | "fnmul" | "fmsub" | "fdiv" | "fmin" | "fmax" | "fsub"
        | "scvtf" | "ucvtf" => build_fp_intrinsic_writeback(machine, instruction, operands),
        "fcvtzs" | "fcvtzu" | "cmeq" | "cmhi" | "dup" | "cnt" | "addv" | "ld1" | "sshll"
        | "uaddlv" | "uzp1" | "rev64" | "extr" => build_intrinsic_fallthrough(
            machine,
            instruction,
            operands,
            Some(vec![operand_location(machine, operands.first()?)?]),
        ),
        "ld3" | "ld3r" | "ld4" | "ld4r" => build_effect_intrinsic(
            instruction,
            operands,
            leading_register_outputs(machine, operands),
            format!("arm64.{}", instruction.mnemonic().unwrap_or("intrinsic")),
        ),
        "umov" | "frintm" | "umlsl2" | "ext" => build_intrinsic_fallthrough(
            machine,
            instruction,
            operands,
            operands
                .first()
                .and_then(|operand| operand_location(machine, operand))
                .map(|dst| vec![dst]),
        ),
        _ => None,
    }
}
