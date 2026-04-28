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

pub(super) fn packed_widen(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let (src_lane_bits, dst_lane_bits, cast) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBW as u32 => {
            (8, 16, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVSXBW as u32 => {
            (8, 16, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBD as u32 => {
            (8, 32, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVSXBD as u32 => {
            (8, 32, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBQ as u32 => {
            (8, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVSXBQ as u32 => {
            (8, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXWD as u32 => {
            (16, 32, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVSXWD as u32 => {
            (16, 32, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXWQ as u32 => {
            (16, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVSXWQ as u32 => {
            (16, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXDQ as u32 => {
            (32, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVSXDQ as u32 => {
            (32, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBW as u32 => {
            (8, 16, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVZXBW as u32 => {
            (8, 16, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBD as u32 => {
            (8, 32, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVZXBD as u32 => {
            (8, 32, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBQ as u32 => {
            (8, 64, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVZXBQ as u32 => {
            (8, 64, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXWD as u32 => {
            (16, 32, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVZXWD as u32 => {
            (16, 32, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXWQ as u32 => {
            (16, 64, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVZXWQ as u32 => {
            (16, 64, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXDQ as u32 => {
            (32, 64, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMOVZXDQ as u32 => {
            (32, 64, SemanticOperationCast::ZeroExtend)
        }
        _ => return None,
    };
    let lane_count = dst_bits / dst_lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let extracted = extract_lane(&src, src_lane_bits, lane);
        parts.push(SemanticExpression::Cast {
            op: cast,
            arg: Box::new(extracted),
            bits: dst_lane_bits,
        });
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts,
                bits: dst_bits,
            },
        }],
    ))
}

pub(super) fn partial_lane_move(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    if dst_bits < 128 {
        return None;
    }
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVHLPS as u32 => SemanticExpression::Concat {
            parts: vec![extract_range(&left, 64, 64), extract_range(&right, 64, 64)],
            bits: 128,
        },
        InsnId(id) if id == X86Insn::X86_INS_MOVLHPS as u32 => SemanticExpression::Concat {
            parts: vec![extract_range(&right, 0, 64), extract_range(&left, 0, 64)],
            bits: 128,
        },
        InsnId(id)
            if id == X86Insn::X86_INS_MOVHPD as u32 || id == X86Insn::X86_INS_MOVHPS as u32 =>
        {
            SemanticExpression::Concat {
                parts: vec![extract_range(&right, 0, 64), extract_range(&left, 0, 64)],
                bits: 128,
            }
        }
        InsnId(id)
            if id == X86Insn::X86_INS_MOVLPD as u32 || id == X86Insn::X86_INS_MOVLPS as u32 =>
        {
            SemanticExpression::Concat {
                parts: vec![extract_range(&left, 64, 64), extract_range(&right, 0, 64)],
                bits: 128,
            }
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn assign(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let expression = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn movdq2q(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: truncate_to_bits(src, bits),
        }],
    ))
}

pub(super) fn movq2dq(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if bits <= 64 {
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Set {
                dst,
                expression: truncate_to_bits(src, bits),
            }],
        ));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![common::const_u64(0, bits - 64), truncate_to_bits(src, 64)],
                bits,
            },
        }],
    ))
}

pub(super) fn avx_assign(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let expression = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn scalar_single_move(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;

    let expression = if dst_bits <= 32 {
        SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: dst_bits,
        }
    } else if is_memory_operand(operands.get(1)?) {
        SemanticExpression::Concat {
            parts: vec![
                common::const_u64(0, dst_bits - 32),
                extract_range(&src, 0, 32),
            ],
            bits: dst_bits,
        }
    } else {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| extract_range(&current, 32, dst_bits - 32))?;
        SemanticExpression::Concat {
            parts: vec![upper, extract_range(&src, 0, 32)],
            bits: dst_bits,
        }
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(super) fn duplicate_move(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    if dst_bits != 128 {
        return None;
    }

    let parts = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVDDUP as u32 => {
            let low = extract_lane(&src, 64, 0);
            vec![low.clone(), low]
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVSLDUP as u32 => vec![
            extract_lane(&src, 32, 2),
            extract_lane(&src, 32, 2),
            extract_lane(&src, 32, 0),
            extract_lane(&src, 32, 0),
        ],
        InsnId(id) if id == X86Insn::X86_INS_MOVSHDUP as u32 => vec![
            extract_lane(&src, 32, 3),
            extract_lane(&src, 32, 3),
            extract_lane(&src, 32, 1),
            extract_lane(&src, 32, 1),
        ],
        _ => return None,
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts,
                bits: dst_bits,
            },
        }],
    ))
}
