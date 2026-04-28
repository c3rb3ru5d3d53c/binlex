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
use crate::semantics::SemanticOperationUnary;

pub(super) fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    condition_code: Option<u64>,
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

fn build_structured_load(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    register_count: usize,
) -> Option<InstructionSemantics> {
    let destinations = operands
        .iter()
        .take(register_count)
        .map(|operand| operand_location(machine, operand))
        .collect::<Option<Vec<_>>>()?;
    let memory_operand = operands.get(register_count)?;
    let writeback_operand = operands.get(register_count + 1);
    let base_addr = effective_memory_address(instruction, memory_operand, writeback_operand)?;
    let (lane_count, lane_bits) = parse_vector_arrangement(instruction.op_str()?)?;
    let lane_bytes = (lane_bits / 8) as u64;

    let mut effects = Vec::with_capacity(register_count + 1);
    for (register_index, dst) in destinations.into_iter().enumerate() {
        let dst_bits = location_bits(&dst);
        let parts = (0..lane_count)
            .rev()
            .map(|lane| {
                let offset =
                    ((lane as usize * register_count) + register_index) as u64 * lane_bytes;
                let addr = binary(
                    SemanticOperationBinary::Add,
                    base_addr.clone(),
                    const_u64(offset, 64),
                    64,
                );
                SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(addr),
                    bits: lane_bits,
                }
            })
            .collect::<Vec<_>>();
        let arrangement_bits = lane_count * lane_bits;
        effects.push(SemanticEffect::Set {
            dst,
            expression: zero_extend_if_needed(
                SemanticExpression::Concat {
                    parts,
                    bits: arrangement_bits,
                },
                arrangement_bits,
                dst_bits,
            ),
        });
    }

    if let Some(writeback) = writeback_effect(instruction, memory_operand, writeback_operand) {
        effects.push(writeback);
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_bcax(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let vn = operand_expression(operands.get(1)?)?;
    let vm = operand_expression(operands.get(2)?)?;
    let va = operand_expression(operands.get(3)?)?;
    let not_va = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(va),
        bits,
    };
    let result = binary(
        SemanticOperationBinary::Xor,
        vn,
        binary(SemanticOperationBinary::And, vm, not_va, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

fn build_bsl(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let mask = SemanticExpression::Read(Box::new(dst.clone()));
    let vn = operand_expression(operands.get(1)?)?;
    let vm = operand_expression(operands.get(2)?)?;
    let result = binary(
        SemanticOperationBinary::Or,
        binary(SemanticOperationBinary::And, mask.clone(), vn, bits),
        binary(
            SemanticOperationBinary::And,
            SemanticExpression::Unary {
                op: SemanticOperationUnary::Not,
                arg: Box::new(mask),
                bits,
            },
            vm,
            bits,
        ),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

fn build_bif(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    build_bit_insert(machine, operands, true)
}

fn build_bit(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    build_bit_insert(machine, operands, false)
}

fn build_bit_insert(
    machine: Architecture,
    operands: &[ArchOperand],
    invert_mask: bool,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(operands.get(1)?)?;
    let mask_input = operand_expression(operands.get(2)?)?;
    let mask = if invert_mask {
        SemanticExpression::Unary {
            op: SemanticOperationUnary::Not,
            arg: Box::new(mask_input),
            bits,
        }
    } else {
        mask_input
    };
    let result = binary(
        SemanticOperationBinary::Xor,
        current.clone(),
        binary(
            SemanticOperationBinary::And,
            binary(SemanticOperationBinary::Xor, current, src, bits),
            mask,
            bits,
        ),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

fn build_aes_round(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let round_key = operand_expression(operands.get(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("aes")),
            args: vec![SemanticExpression::Read(Box::new(dst.clone())), round_key],
            outputs: vec![dst],
        }],
    ))
}

fn build_aes_mix_columns(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("aes")),
            args: vec![src],
            outputs: vec![dst],
        }],
    ))
}
