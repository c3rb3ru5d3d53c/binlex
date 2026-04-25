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
    condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    match instruction.mnemonic().unwrap_or("") {
        "movi" => build_movi(machine, instruction, operands),
        "fmov" => build_fmov(machine, instruction, operands),
        "fabs" => build_fabs(machine, operands),
        "fneg" => build_fneg(machine, operands),
        "fcmp" | "fcmpe" => build_fcmp_intrinsic(machine, operands),
        "fccmp" => build_fccmp(machine, operands, condition_code),
        "fadd" => build_fp_binary(machine, operands, SemanticOperationBinary::FAdd),
        "fsub" => build_fp_binary(machine, operands, SemanticOperationBinary::FSub),
        "fmul" => build_fp_binary(machine, operands, SemanticOperationBinary::FMul),
        "fdiv" => build_fp_binary(machine, operands, SemanticOperationBinary::FDiv),
        "fnmul" => build_fnmul(machine, operands),
        "fmadd" => build_fmadd(machine, operands),
        "fmsub" => build_fmsub(machine, operands),
        "scvtf" => build_scvtf(machine, operands),
        "ucvtf" => build_ucvtf(machine, operands),
        "fcvtzs" => build_fcvtzs(machine, operands),
        "fcvtzu" => build_fcvtzu(machine, operands),
        "fmin" => build_fp_minmax(machine, operands, SemanticOperationCompare::Olt),
        "fmax" => build_fp_minmax(machine, operands, SemanticOperationCompare::Ogt),
        "sshll" => build_sshll(machine, instruction, operands),
        "cmeq" => build_vector_compare(machine, instruction, operands, SemanticOperationCompare::Eq),
        "cmhi" => build_vector_compare(machine, instruction, operands, SemanticOperationCompare::Ugt),
        "uzp1" => build_uzp1(machine, instruction, operands),
        "addv" => build_addv(machine, instruction, operands),
        "uaddlv" => build_uaddlv(machine, instruction, operands),
        "dup" => build_dup(machine, instruction, operands),
        "cnt" => build_cnt(machine, instruction, operands),
        "rev64" => build_rev64(machine, instruction, operands),
        "extr" => build_extr(machine, operands),
        "ld1" => build_ld1_lane(machine, instruction, operands).or_else(|| {
            build_intrinsic_fallthrough(
                machine,
                instruction,
                operands,
                Some(vec![operand_location(machine, operands.first()?)?]),
            )
        }),
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
