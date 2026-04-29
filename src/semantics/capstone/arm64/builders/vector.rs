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
use super::memory::build_store_pair;

#[path = "vector/arithmetic.rs"]
mod arithmetic_ops;
#[path = "vector/compare.rs"]
mod compare_ops;
#[path = "vector/crypto.rs"]
mod crypto_ops;
#[path = "vector/data.rs"]
mod data_ops;
#[path = "vector/lanes.rs"]
mod lane_ops;
#[path = "vector/logic.rs"]
mod logic_ops;
#[path = "vector/structured.rs"]
mod structured_ops;

use arithmetic_ops::*;
use compare_ops::*;
use crypto_ops::*;
use data_ops::*;
use lane_ops::*;
use logic_ops::*;
use structured_ops::*;

pub(crate) fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    _condition_code: Option<u64>,
) -> Option<InstructionSemantics> {
    match instruction.mnemonic().unwrap_or("") {
        "aesd" | "aese" => build_aes_round(machine, instruction, operands),
        "aesimc" | "aesmc" => build_aes_mix_columns(machine, instruction, operands),
        "bfcvt" | "bfcvtn" | "bfcvtn2" | "bfdot" | "bfmlalb" => build_intrinsic_fallthrough(
            machine,
            instruction,
            operands,
            operands
                .first()
                .and_then(|operand| operand_location(machine, operand))
                .map(|dst| vec![dst]),
        ),
        "bcax" => build_bcax(machine, operands),
        "bsl" => build_bsl(machine, operands),
        "bif" => build_bif(machine, operands),
        "bit" => build_bit(machine, operands),
        "movi" => build_movi(machine, instruction, operands),
        "fmov" => build_fmov(machine, instruction, operands),
        "sshll" => build_sshll(machine, instruction, operands),
        "cmeq" => {
            build_vector_compare(machine, instruction, operands, SemanticOperationCompare::Eq)
        }
        "cmhi" => build_vector_compare(
            machine,
            instruction,
            operands,
            SemanticOperationCompare::Ugt,
        ),
        "uzp1" => build_uzp1(machine, instruction, operands),
        "addv" => build_addv(machine, instruction, operands),
        "addp" => build_addp(machine, instruction, operands),
        "addhn" => build_addhn(machine, instruction, operands),
        "addhn2" => build_addhn2(machine, instruction, operands),
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
        "ld2" => build_structured_load(machine, instruction, operands, 2),
        "ld3" => build_structured_load(machine, instruction, operands, 3),
        "ld4" => build_structured_load(machine, instruction, operands, 4),
        "st1" => build_store_pair(machine, instruction, operands),
        "ld3r" | "ld4r" => build_effect_intrinsic(
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
