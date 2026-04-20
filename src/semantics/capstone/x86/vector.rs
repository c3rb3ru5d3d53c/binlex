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
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticOperationBinary,
    SemanticOperationCast, SemanticOperationCompare, SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86OperandType};

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    match instruction.id() {
        InsnId(id)
            if [
                X86Insn::X86_INS_MOVUPS as u32,
                X86Insn::X86_INS_MOVUPD as u32,
                X86Insn::X86_INS_MOVAPS as u32,
                X86Insn::X86_INS_MOVAPD as u32,
                X86Insn::X86_INS_MOVDQU as u32,
                X86Insn::X86_INS_MOVDQA as u32,
                X86Insn::X86_INS_LDDQU as u32,
                X86Insn::X86_INS_MOVD as u32,
                X86Insn::X86_INS_MOVQ as u32,
                X86Insn::X86_INS_MOVNTDQ as u32,
                X86Insn::X86_INS_MOVNTPD as u32,
                X86Insn::X86_INS_MOVNTPS as u32,
                X86Insn::X86_INS_MOVNTQ as u32,
                X86Insn::X86_INS_MOVNTI as u32,
            ]
            .contains(&id) =>
        {
            assign(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVDQ2Q as u32 => movdq2q(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_MOVQ2DQ as u32 => movq2dq(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_VMOVUPS as u32,
                X86Insn::X86_INS_VMOVAPS as u32,
                X86Insn::X86_INS_VMOVDQU as u32,
                X86Insn::X86_INS_VMOVDQA as u32,
                X86Insn::X86_INS_VMOVD as u32,
                X86Insn::X86_INS_VMOVQ as u32,
                X86Insn::X86_INS_VMOVNTDQ as u32,
            ]
            .contains(&id) =>
        {
            avx_assign(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MOVSS as u32 => scalar_single_move(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_MOVHLPS as u32,
                X86Insn::X86_INS_MOVLHPS as u32,
                X86Insn::X86_INS_MOVHPD as u32,
                X86Insn::X86_INS_MOVLPD as u32,
                X86Insn::X86_INS_MOVHPS as u32,
                X86Insn::X86_INS_MOVLPS as u32,
            ]
            .contains(&id) =>
        {
            partial_lane_move(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_MOVDDUP as u32,
                X86Insn::X86_INS_MOVSHDUP as u32,
                X86Insn::X86_INS_MOVSLDUP as u32,
            ]
            .contains(&id) =>
        {
            duplicate_move(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PMOVSXBW as u32,
                X86Insn::X86_INS_PMOVSXBD as u32,
                X86Insn::X86_INS_PMOVSXBQ as u32,
                X86Insn::X86_INS_PMOVSXWD as u32,
                X86Insn::X86_INS_PMOVSXWQ as u32,
                X86Insn::X86_INS_PMOVSXDQ as u32,
                X86Insn::X86_INS_PMOVZXBW as u32,
                X86Insn::X86_INS_PMOVZXBD as u32,
                X86Insn::X86_INS_PMOVZXBQ as u32,
                X86Insn::X86_INS_PMOVZXWD as u32,
                X86Insn::X86_INS_PMOVZXWQ as u32,
                X86Insn::X86_INS_PMOVZXDQ as u32,
            ]
            .contains(&id) =>
        {
            packed_widen(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_POR as u32,
                X86Insn::X86_INS_PAND as u32,
                X86Insn::X86_INS_ANDPD as u32,
                X86Insn::X86_INS_PXOR as u32,
                X86Insn::X86_INS_ORPS as u32,
                X86Insn::X86_INS_ORPD as u32,
                X86Insn::X86_INS_XORPD as u32,
            ]
            .contains(&id) =>
        {
            binary(
                machine,
                operands,
                match id {
                    id if id == X86Insn::X86_INS_POR as u32
                        || id == X86Insn::X86_INS_ORPS as u32
                        || id == X86Insn::X86_INS_ORPD as u32 =>
                    {
                        SemanticOperationBinary::Or
                    }
                    id if id == X86Insn::X86_INS_PAND as u32
                        || id == X86Insn::X86_INS_ANDPD as u32 =>
                    {
                        SemanticOperationBinary::And
                    }
                    _ => SemanticOperationBinary::Xor,
                },
            )
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPAND as u32,
                X86Insn::X86_INS_VPOR as u32,
                X86Insn::X86_INS_VPXOR as u32,
                X86Insn::X86_INS_VXORPS as u32,
            ]
            .contains(&id) =>
        {
            avx_binary(
                machine,
                operands,
                match id {
                    id if id == X86Insn::X86_INS_VPOR as u32 => SemanticOperationBinary::Or,
                    id if id == X86Insn::X86_INS_VPAND as u32 => SemanticOperationBinary::And,
                    _ => SemanticOperationBinary::Xor,
                },
            )
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PANDN as u32,
                X86Insn::X86_INS_ANDNPD as u32,
                X86Insn::X86_INS_ANDNPS as u32,
            ]
            .contains(&id) =>
        {
            pandn(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPANDN as u32 => avx_pandn(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_PACKSSDW as u32,
                X86Insn::X86_INS_PACKSSWB as u32,
                X86Insn::X86_INS_PACKUSWB as u32,
                X86Insn::X86_INS_PADDB as u32,
                X86Insn::X86_INS_PADDW as u32,
                X86Insn::X86_INS_PADDD as u32,
                X86Insn::X86_INS_PADDQ as u32,
                X86Insn::X86_INS_PMAXSB as u32,
                X86Insn::X86_INS_PMAXSW as u32,
                X86Insn::X86_INS_PMAXSD as u32,
                X86Insn::X86_INS_PMAXUB as u32,
                X86Insn::X86_INS_PMAXUW as u32,
                X86Insn::X86_INS_PMAXUD as u32,
                X86Insn::X86_INS_PMINSB as u32,
                X86Insn::X86_INS_PMINSW as u32,
                X86Insn::X86_INS_PMINSD as u32,
                X86Insn::X86_INS_PMINUB as u32,
                X86Insn::X86_INS_PMINUW as u32,
                X86Insn::X86_INS_PMINUD as u32,
                X86Insn::X86_INS_PSUBB as u32,
                X86Insn::X86_INS_PSUBW as u32,
                X86Insn::X86_INS_PSUBD as u32,
                X86Insn::X86_INS_PSUBQ as u32,
                X86Insn::X86_INS_PCMPEQB as u32,
                X86Insn::X86_INS_PCMPEQW as u32,
                X86Insn::X86_INS_PCMPEQD as u32,
                X86Insn::X86_INS_PCMPGTB as u32,
                X86Insn::X86_INS_PCMPGTW as u32,
                X86Insn::X86_INS_PCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            if [
                X86Insn::X86_INS_PACKSSDW as u32,
                X86Insn::X86_INS_PACKSSWB as u32,
                X86Insn::X86_INS_PACKUSWB as u32,
            ]
            .contains(&id)
            {
                packed_pack(machine, instruction, operands)
            } else {
                packed_lane_op(machine, instruction, operands)
            }
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDB as u32,
                X86Insn::X86_INS_VPADDW as u32,
                X86Insn::X86_INS_VPADDD as u32,
                X86Insn::X86_INS_VPSUBB as u32,
                X86Insn::X86_INS_VPSUBW as u32,
                X86Insn::X86_INS_VPSUBD as u32,
                X86Insn::X86_INS_VPSUBQ as u32,
                X86Insn::X86_INS_VPCMPEQB as u32,
                X86Insn::X86_INS_VPCMPEQW as u32,
                X86Insn::X86_INS_VPCMPEQD as u32,
                X86Insn::X86_INS_VPCMPEQQ as u32,
                X86Insn::X86_INS_VPCMPGTB as u32,
                X86Insn::X86_INS_VPCMPGTW as u32,
                X86Insn::X86_INS_VPCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            avx_packed_lane_op(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPACKSSDW as u32,
                X86Insn::X86_INS_VPACKSSWB as u32,
                X86Insn::X86_INS_VPACKUSWB as u32,
            ]
            .contains(&id) =>
        {
            avx_packed_pack(machine, instruction, operands)
        }
        InsnId(id)
            if [X86Insn::X86_INS_PAVGB as u32, X86Insn::X86_INS_PAVGW as u32].contains(&id) =>
        {
            packed_average(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMINUB as u32 => {
            avx_binary(machine, operands, SemanticOperationBinary::MinUnsigned)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PMULHW as u32,
                X86Insn::X86_INS_PMULLW as u32,
                X86Insn::X86_INS_PMULLD as u32,
                X86Insn::X86_INS_PMULUDQ as u32,
                X86Insn::X86_INS_PMADDWD as u32,
            ]
            .contains(&id) =>
        {
            packed_multiply(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPMADDWD as u32,
                X86Insn::X86_INS_VPMULHW as u32,
                X86Insn::X86_INS_VPMULLW as u32,
            ]
            .contains(&id) =>
        {
            avx_packed_multiply(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PSLLW as u32,
                X86Insn::X86_INS_PSLLD as u32,
                X86Insn::X86_INS_PSLLQ as u32,
                X86Insn::X86_INS_PSRLW as u32,
                X86Insn::X86_INS_PSRLD as u32,
                X86Insn::X86_INS_PSRLQ as u32,
                X86Insn::X86_INS_PSRAW as u32,
                X86Insn::X86_INS_PSRAD as u32,
                X86Insn::X86_INS_PSLLDQ as u32,
                X86Insn::X86_INS_PSRLDQ as u32,
            ]
            .contains(&id) =>
        {
            packed_shift(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPSLLDQ as u32,
                X86Insn::X86_INS_VPSRLDQ as u32,
            ]
            .contains(&id) =>
        {
            avx_packed_shift(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_PTEST as u32 => ptest(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPTEST as u32 => avx_ptest(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_PALIGNR as u32 => palignr(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_PSHUFB as u32,
                X86Insn::X86_INS_PSHUFD as u32,
                X86Insn::X86_INS_PSHUFHW as u32,
                X86Insn::X86_INS_PSHUFLW as u32,
                X86Insn::X86_INS_PSHUFW as u32,
                X86Insn::X86_INS_UNPCKLPD as u32,
                X86Insn::X86_INS_UNPCKHPD as u32,
                X86Insn::X86_INS_UNPCKLPS as u32,
                X86Insn::X86_INS_UNPCKHPS as u32,
                X86Insn::X86_INS_PUNPCKLBW as u32,
                X86Insn::X86_INS_PUNPCKHBW as u32,
                X86Insn::X86_INS_PUNPCKLWD as u32,
                X86Insn::X86_INS_PUNPCKHWD as u32,
                X86Insn::X86_INS_PUNPCKLDQ as u32,
                X86Insn::X86_INS_PUNPCKHDQ as u32,
                X86Insn::X86_INS_PUNPCKLQDQ as u32,
                X86Insn::X86_INS_PUNPCKHQDQ as u32,
            ]
            .contains(&id) =>
        {
            if id == X86Insn::X86_INS_PSHUFB as u32 {
                pshufb(machine, operands)
            } else if [
                X86Insn::X86_INS_PSHUFD as u32,
                X86Insn::X86_INS_PSHUFHW as u32,
                X86Insn::X86_INS_PSHUFLW as u32,
                X86Insn::X86_INS_PSHUFW as u32,
            ]
            .contains(&id)
            {
                shuffle(machine, instruction, operands)
            } else {
                unpack(machine, instruction, operands)
            }
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPSHUFD as u32,
                X86Insn::X86_INS_VPUNPCKLBW as u32,
                X86Insn::X86_INS_VPUNPCKHBW as u32,
                X86Insn::X86_INS_VPUNPCKLWD as u32,
                X86Insn::X86_INS_VPUNPCKHWD as u32,
                X86Insn::X86_INS_VPUNPCKLDQ as u32,
                X86Insn::X86_INS_VPUNPCKHDQ as u32,
                X86Insn::X86_INS_VPUNPCKLQDQ as u32,
                X86Insn::X86_INS_VPUNPCKHQDQ as u32,
            ]
            .contains(&id) =>
        {
            if id == X86Insn::X86_INS_VPSHUFD as u32 {
                avx_shuffle(machine, instruction, operands)
            } else {
                avx_unpack(machine, instruction, operands)
            }
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PEXTRW as u32,
                X86Insn::X86_INS_PEXTRB as u32,
                X86Insn::X86_INS_PEXTRD as u32,
                X86Insn::X86_INS_PEXTRQ as u32,
                X86Insn::X86_INS_EXTRACTPS as u32,
                X86Insn::X86_INS_VPEXTRB as u32,
                X86Insn::X86_INS_VPEXTRD as u32,
                X86Insn::X86_INS_VPEXTRQ as u32,
                X86Insn::X86_INS_VPEXTRW as u32,
            ]
            .contains(&id) =>
        {
            packed_extract(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PINSRB as u32,
                X86Insn::X86_INS_PINSRD as u32,
                X86Insn::X86_INS_PINSRQ as u32,
                X86Insn::X86_INS_PINSRW as u32,
            ]
            .contains(&id) =>
        {
            packed_insert(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_MOVMSKPS as u32,
                X86Insn::X86_INS_MOVMSKPD as u32,
                X86Insn::X86_INS_PMOVMSKB as u32,
                X86Insn::X86_INS_VPMOVMSKB as u32,
            ]
            .contains(&id) =>
        {
            movemask(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_VEXTRACTI128 as u32 => vextracti128(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPERM2I128 as u32 => vperm2i128(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPERMQ as u32 => vpermq(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPBROADCASTB as u32 => vpbroadcastb(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPSIGNW as u32 => vpsignw(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_XORPS as u32 => {
            binary(machine, operands, SemanticOperationBinary::Xor)
        }
        InsnId(id) if id == X86Insn::X86_INS_ANDPS as u32 => {
            binary(machine, operands, SemanticOperationBinary::And)
        }
        _ => None,
    }
}

fn packed_widen(
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
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBD as u32 => {
            (8, 32, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXBQ as u32 => {
            (8, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXWD as u32 => {
            (16, 32, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXWQ as u32 => {
            (16, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVSXDQ as u32 => {
            (32, 64, SemanticOperationCast::SignExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBW as u32 => {
            (8, 16, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBD as u32 => {
            (8, 32, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXBQ as u32 => {
            (8, 64, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXWD as u32 => {
            (16, 32, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXWQ as u32 => {
            (16, 64, SemanticOperationCast::ZeroExtend)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMOVZXDQ as u32 => {
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

fn partial_lane_move(
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

fn assign(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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

fn movdq2q(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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

fn movq2dq(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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

fn avx_assign(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
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

fn avx_packed_pack(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let (src_lane_bits, dst_lane_bits, pack_kind) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPACKSSDW as u32 => (32, 16, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_VPACKSSWB as u32 => (16, 8, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_VPACKUSWB as u32 => (16, 8, PackKind::UnsignedByte),
        _ => return None,
    };
    let expression = if bits == 256 {
        let mut parts = Vec::new();
        for base_lsb in [128, 0] {
            let left_half = extract_range(&left, base_lsb, 128);
            let right_half = extract_range(&right, base_lsb, 128);
            let half_lane_count = 128 / (dst_lane_bits * 2);
            let mut lanes = Vec::with_capacity((half_lane_count * 2) as usize);
            for lane in 0..half_lane_count {
                lanes.push(saturate_lane(
                    extract_lane(&left_half, src_lane_bits, lane),
                    src_lane_bits,
                    dst_lane_bits,
                    pack_kind,
                ));
            }
            for lane in 0..half_lane_count {
                lanes.push(saturate_lane(
                    extract_lane(&right_half, src_lane_bits, lane),
                    src_lane_bits,
                    dst_lane_bits,
                    pack_kind,
                ));
            }
            let half = lanes.into_iter().rev().collect::<Vec<_>>();
            parts.push(SemanticExpression::Concat {
                parts: half,
                bits: 128,
            });
        }
        parts
    } else {
        let half_lane_count = bits / (dst_lane_bits * 2);
        let mut lanes = Vec::with_capacity((half_lane_count * 2) as usize);
        for lane in 0..half_lane_count {
            lanes.push(saturate_lane(
                extract_lane(&left, src_lane_bits, lane),
                src_lane_bits,
                dst_lane_bits,
                pack_kind,
            ));
        }
        for lane in 0..half_lane_count {
            lanes.push(saturate_lane(
                extract_lane(&right, src_lane_bits, lane),
                src_lane_bits,
                dst_lane_bits,
                pack_kind,
            ));
        }
        lanes.into_iter().rev().collect::<Vec<_>>()
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: expression,
                bits,
            },
        }],
    ))
}

fn avx_packed_shift(
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
    let count = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let left_shift = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPSLLDQ as u32 => true,
        InsnId(id) if id == X86Insn::X86_INS_VPSRLDQ as u32 => false,
        _ => return None,
    };
    let expression = if bits == 256 {
        SemanticExpression::Concat {
            parts: vec![
                shift_bytes(
                    extract_range(&src, 128, 128),
                    count.clone(),
                    128,
                    left_shift,
                ),
                shift_bytes(extract_range(&src, 0, 128), count, 128, left_shift),
            ],
            bits,
        }
    } else {
        shift_bytes(src, count, bits, left_shift)
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn scalar_single_move(
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

fn duplicate_move(
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

fn binary(
    machine: Architecture,
    operands: &[ArchOperand],
    operation: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: operation,
                left: Box::new(left),
                right: Box::new(right),
                bits,
            },
        }],
    ))
}

fn avx_binary(
    machine: Architecture,
    operands: &[ArchOperand],
    operation: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Binary {
                op: operation,
                left: Box::new(left),
                right: Box::new(right),
                bits,
            },
        }],
    ))
}

fn pandn(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::and(common::not(left, bits), right, bits),
        }],
    ))
}

fn avx_pandn(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::and(common::not(left, bits), right, bits),
        }],
    ))
}

fn packed_shift(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let count = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);

    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSLLDQ as u32 => shift_bytes(src, count, bits, true),
        InsnId(id) if id == X86Insn::X86_INS_PSRLDQ as u32 => shift_bytes(src, count, bits, false),
        InsnId(id)
            if [
                X86Insn::X86_INS_PSLLW as u32,
                X86Insn::X86_INS_PSLLD as u32,
                X86Insn::X86_INS_PSLLQ as u32,
                X86Insn::X86_INS_PSRLW as u32,
                X86Insn::X86_INS_PSRLD as u32,
                X86Insn::X86_INS_PSRLQ as u32,
                X86Insn::X86_INS_PSRAW as u32,
                X86Insn::X86_INS_PSRAD as u32,
            ]
            .contains(&id) =>
        {
            packed_lane_shift(instruction, bits, &src, count)?
        }
        _ => return None,
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn shift_bytes(
    src: SemanticExpression,
    count: SemanticExpression,
    bits: u16,
    left: bool,
) -> SemanticExpression {
    let count_bits = bits.max(count.bits());
    let count_bytes = cast_count(count, count_bits);
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(count_bytes.clone()),
        right: Box::new(common::const_u64(8, count_bits)),
        bits: count_bits,
    };
    let shifted = SemanticExpression::Binary {
        op: if left {
            SemanticOperationBinary::Shl
        } else {
            SemanticOperationBinary::LShr
        },
        left: Box::new(cast_to_bits(src, count_bits)),
        right: Box::new(shift_bits),
        bits: count_bits,
    };
    let too_large = common::compare(
        SemanticOperationCompare::Uge,
        count_bytes,
        common::const_u64((bits / 8) as u64, count_bits),
    );
    SemanticExpression::Select {
        condition: Box::new(too_large),
        when_true: Box::new(common::const_u64(0, bits)),
        when_false: Box::new(truncate_to_bits(shifted, bits)),
        bits,
    }
}

fn packed_lane_shift(
    instruction: &Insn,
    bits: u16,
    src: &SemanticExpression,
    count: SemanticExpression,
) -> Option<SemanticExpression> {
    let (lane_bits, op) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSLLW as u32 => (16, SemanticOperationBinary::Shl),
        InsnId(id) if id == X86Insn::X86_INS_PSLLD as u32 => (32, SemanticOperationBinary::Shl),
        InsnId(id) if id == X86Insn::X86_INS_PSLLQ as u32 => (64, SemanticOperationBinary::Shl),
        InsnId(id) if id == X86Insn::X86_INS_PSRLW as u32 => (16, SemanticOperationBinary::LShr),
        InsnId(id) if id == X86Insn::X86_INS_PSRLD as u32 => (32, SemanticOperationBinary::LShr),
        InsnId(id) if id == X86Insn::X86_INS_PSRLQ as u32 => (64, SemanticOperationBinary::LShr),
        InsnId(id) if id == X86Insn::X86_INS_PSRAW as u32 => (16, SemanticOperationBinary::AShr),
        InsnId(id) if id == X86Insn::X86_INS_PSRAD as u32 => (32, SemanticOperationBinary::AShr),
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let count_bits = lane_bits.max(count.bits());
    let raw_count = cast_count(count, count_bits);
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lane_expr = cast_to_bits(extract_lane(src, lane_bits, lane), count_bits);
        let part = match op {
            SemanticOperationBinary::AShr => {
                let saturated = SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Uge,
                        raw_count.clone(),
                        common::const_u64(lane_bits as u64, count_bits),
                    )),
                    when_true: Box::new(common::const_u64((lane_bits - 1) as u64, count_bits)),
                    when_false: Box::new(raw_count.clone()),
                    bits: count_bits,
                };
                truncate_to_bits(
                    SemanticExpression::Binary {
                        op,
                        left: Box::new(lane_expr),
                        right: Box::new(saturated),
                        bits: count_bits,
                    },
                    lane_bits,
                )
            }
            _ => {
                let shifted = SemanticExpression::Binary {
                    op,
                    left: Box::new(lane_expr),
                    right: Box::new(raw_count.clone()),
                    bits: count_bits,
                };
                SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Uge,
                        raw_count.clone(),
                        common::const_u64(lane_bits as u64, count_bits),
                    )),
                    when_true: Box::new(common::const_u64(0, lane_bits)),
                    when_false: Box::new(truncate_to_bits(shifted, lane_bits)),
                    bits: lane_bits,
                }
            }
        };
        parts.push(part);
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn cast_count(count: SemanticExpression, bits: u16) -> SemanticExpression {
    let arg = if count.bits() > bits {
        truncate_to_bits(count, bits)
    } else {
        count
    };
    if arg.bits() == bits {
        arg
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(arg),
            bits,
        }
    }
}

fn cast_to_bits(expr: SemanticExpression, bits: u16) -> SemanticExpression {
    if expr.bits() == bits {
        expr
    } else if expr.bits() > bits {
        truncate_to_bits(expr, bits)
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expr),
            bits,
        }
    }
}

fn truncate_to_bits(expr: SemanticExpression, bits: u16) -> SemanticExpression {
    if expr.bits() == bits {
        expr
    } else {
        SemanticExpression::Extract {
            arg: Box::new(expr),
            lsb: 0,
            bits,
        }
    }
}

fn ptest(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = left.bits().max(right.bits());
    let left = cast_to_bits(left, bits);
    let right = cast_to_bits(right, bits);
    let and_value = common::and(left.clone(), right.clone(), bits);
    let andn_value = common::and(left, common::not(right, bits), bits);

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    and_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    andn_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

fn avx_ptest(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = left.bits().max(right.bits());
    let left = cast_to_bits(left, bits);
    let right = cast_to_bits(right, bits);
    let and_value = common::and(left.clone(), right.clone(), bits);
    let andn_value = common::and(left, common::not(right, bits), bits);

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    and_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    andn_value,
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

fn packed_lane_op(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane_bits = match instruction.id() {
        InsnId(id)
            if [X86Insn::X86_INS_PADDB as u32, X86Insn::X86_INS_PSUBB as u32].contains(&id) =>
        {
            8
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PADDW as u32,
                X86Insn::X86_INS_PSUBW as u32,
                X86Insn::X86_INS_PMAXSW as u32,
                X86Insn::X86_INS_PMAXUW as u32,
                X86Insn::X86_INS_PMINSW as u32,
                X86Insn::X86_INS_PMINUW as u32,
                X86Insn::X86_INS_PCMPEQW as u32,
                X86Insn::X86_INS_PCMPGTW as u32,
            ]
            .contains(&id) =>
        {
            16
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PADDD as u32,
                X86Insn::X86_INS_PSUBD as u32,
                X86Insn::X86_INS_PMAXSD as u32,
                X86Insn::X86_INS_PMAXUD as u32,
                X86Insn::X86_INS_PMINSD as u32,
                X86Insn::X86_INS_PMINUD as u32,
                X86Insn::X86_INS_PCMPEQD as u32,
                X86Insn::X86_INS_PCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            32
        }
        InsnId(id)
            if [X86Insn::X86_INS_PADDQ as u32, X86Insn::X86_INS_PSUBQ as u32].contains(&id) =>
        {
            64
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PMAXSB as u32,
                X86Insn::X86_INS_PMAXUB as u32,
                X86Insn::X86_INS_PMINSB as u32,
                X86Insn::X86_INS_PMINUB as u32,
                X86Insn::X86_INS_PCMPEQB as u32,
                X86Insn::X86_INS_PCMPGTB as u32,
            ]
            .contains(&id) =>
        {
            8
        }
        _ => return None,
    };
    let expression = packed_lanes(
        bits,
        lane_bits,
        &left,
        &right,
        match instruction.id() {
            InsnId(id)
                if [
                    X86Insn::X86_INS_PADDB as u32,
                    X86Insn::X86_INS_PADDW as u32,
                    X86Insn::X86_INS_PADDD as u32,
                    X86Insn::X86_INS_PADDQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Add)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PSUBB as u32,
                    X86Insn::X86_INS_PSUBW as u32,
                    X86Insn::X86_INS_PSUBD as u32,
                    X86Insn::X86_INS_PSUBQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Sub)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMAXSB as u32,
                    X86Insn::X86_INS_PMAXSW as u32,
                    X86Insn::X86_INS_PMAXSD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MaxSigned)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMAXUB as u32,
                    X86Insn::X86_INS_PMAXUW as u32,
                    X86Insn::X86_INS_PMAXUD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MaxUnsigned)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMINSB as u32,
                    X86Insn::X86_INS_PMINSW as u32,
                    X86Insn::X86_INS_PMINSD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MinSigned)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PMINUB as u32,
                    X86Insn::X86_INS_PMINUW as u32,
                    X86Insn::X86_INS_PMINUD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::MinUnsigned)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PCMPEQB as u32,
                    X86Insn::X86_INS_PCMPEQW as u32,
                    X86Insn::X86_INS_PCMPEQD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Compare(SemanticOperationCompare::Eq)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_PCMPGTB as u32,
                    X86Insn::X86_INS_PCMPGTW as u32,
                    X86Insn::X86_INS_PCMPGTD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Compare(SemanticOperationCompare::Sgt)
            }
            _ => return None,
        },
    )?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn avx_packed_lane_op(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let lane_bits = match instruction.id() {
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDB as u32,
                X86Insn::X86_INS_VPSUBB as u32,
                X86Insn::X86_INS_VPCMPEQB as u32,
                X86Insn::X86_INS_VPCMPGTB as u32,
            ]
            .contains(&id) =>
        {
            8
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDW as u32,
                X86Insn::X86_INS_VPSUBW as u32,
                X86Insn::X86_INS_VPCMPEQW as u32,
                X86Insn::X86_INS_VPCMPGTW as u32,
            ]
            .contains(&id) =>
        {
            16
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDD as u32,
                X86Insn::X86_INS_VPSUBD as u32,
                X86Insn::X86_INS_VPCMPEQD as u32,
                X86Insn::X86_INS_VPCMPGTD as u32,
            ]
            .contains(&id) =>
        {
            32
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPSUBQ as u32,
                X86Insn::X86_INS_VPCMPEQQ as u32,
            ]
            .contains(&id) =>
        {
            64
        }
        _ => return None,
    };
    let expression = packed_lanes(
        bits,
        lane_bits,
        &left,
        &right,
        match instruction.id() {
            InsnId(id)
                if [
                    X86Insn::X86_INS_VPADDB as u32,
                    X86Insn::X86_INS_VPADDW as u32,
                    X86Insn::X86_INS_VPADDD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Add)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_VPSUBB as u32,
                    X86Insn::X86_INS_VPSUBW as u32,
                    X86Insn::X86_INS_VPSUBD as u32,
                    X86Insn::X86_INS_VPSUBQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Binary(SemanticOperationBinary::Sub)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_VPCMPEQB as u32,
                    X86Insn::X86_INS_VPCMPEQW as u32,
                    X86Insn::X86_INS_VPCMPEQD as u32,
                    X86Insn::X86_INS_VPCMPEQQ as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Compare(SemanticOperationCompare::Eq)
            }
            InsnId(id)
                if [
                    X86Insn::X86_INS_VPCMPGTB as u32,
                    X86Insn::X86_INS_VPCMPGTW as u32,
                    X86Insn::X86_INS_VPCMPGTD as u32,
                ]
                .contains(&id) =>
            {
                PackedLaneOp::Compare(SemanticOperationCompare::Sgt)
            }
            _ => return None,
        },
    )?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn packed_pack(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let (src_lane_bits, dst_lane_bits, pack_kind) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PACKSSDW as u32 => (32, 16, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_PACKSSWB as u32 => (16, 8, PackKind::Signed),
        InsnId(id) if id == X86Insn::X86_INS_PACKUSWB as u32 => (16, 8, PackKind::UnsignedByte),
        _ => return None,
    };
    if bits == 0 || bits % dst_lane_bits != 0 {
        return None;
    }
    let half_lane_count = bits / (dst_lane_bits * 2);
    let mut lanes = Vec::with_capacity((half_lane_count * 2) as usize);
    for lane in 0..half_lane_count {
        lanes.push(saturate_lane(
            extract_lane(&left, src_lane_bits, lane),
            src_lane_bits,
            dst_lane_bits,
            pack_kind,
        ));
    }
    for lane in 0..half_lane_count {
        lanes.push(saturate_lane(
            extract_lane(&right, src_lane_bits, lane),
            src_lane_bits,
            dst_lane_bits,
            pack_kind,
        ));
    }
    let parts = lanes.into_iter().rev().collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

#[derive(Clone, Copy)]
enum PackKind {
    Signed,
    UnsignedByte,
}

fn saturate_lane(
    lane: SemanticExpression,
    src_lane_bits: u16,
    dst_lane_bits: u16,
    kind: PackKind,
) -> SemanticExpression {
    match kind {
        PackKind::Signed => {
            let min_value = signed_min_value(src_lane_bits, dst_lane_bits);
            let max_value = signed_max_value(dst_lane_bits);
            let min_const = SemanticExpression::Const {
                value: min_value,
                bits: src_lane_bits,
            };
            let max_const = SemanticExpression::Const {
                value: max_value,
                bits: src_lane_bits,
            };
            let truncated = truncate_to_bits(lane.clone(), dst_lane_bits);
            SemanticExpression::Select {
                condition: Box::new(common::compare(
                    SemanticOperationCompare::Slt,
                    lane.clone(),
                    min_const,
                )),
                when_true: Box::new(SemanticExpression::Const {
                    value: signed_min_truncated(dst_lane_bits),
                    bits: dst_lane_bits,
                }),
                when_false: Box::new(SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Sgt,
                        lane.clone(),
                        max_const,
                    )),
                    when_true: Box::new(SemanticExpression::Const {
                        value: max_value,
                        bits: dst_lane_bits,
                    }),
                    when_false: Box::new(truncated),
                    bits: dst_lane_bits,
                }),
                bits: dst_lane_bits,
            }
        }
        PackKind::UnsignedByte => {
            let zero = common::const_u64(0, src_lane_bits);
            let max_const = SemanticExpression::Const {
                value: 0xff,
                bits: src_lane_bits,
            };
            let truncated = truncate_to_bits(lane.clone(), dst_lane_bits);
            SemanticExpression::Select {
                condition: Box::new(common::compare(
                    SemanticOperationCompare::Slt,
                    lane.clone(),
                    zero,
                )),
                when_true: Box::new(common::const_u64(0, dst_lane_bits)),
                when_false: Box::new(SemanticExpression::Select {
                    condition: Box::new(common::compare(
                        SemanticOperationCompare::Sgt,
                        lane,
                        max_const,
                    )),
                    when_true: Box::new(common::const_u64(0xff, dst_lane_bits)),
                    when_false: Box::new(truncated),
                    bits: dst_lane_bits,
                }),
                bits: dst_lane_bits,
            }
        }
    }
}

fn signed_max_value(bits: u16) -> u128 {
    (1u128 << (bits - 1)) - 1
}

fn signed_min_truncated(bits: u16) -> u128 {
    1u128 << (bits - 1)
}

fn signed_min_value(src_bits: u16, dst_bits: u16) -> u128 {
    (1u128 << src_bits) - (1u128 << (dst_bits - 1))
}

fn palignr(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let count = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let wide_bits = bits * 2;
    let combined = SemanticExpression::Concat {
        parts: vec![
            cast_to_bits(left, wide_bits),
            cast_to_bits(right, wide_bits),
        ],
        bits: wide_bits,
    };
    let count_bits = wide_bits.max(count.bits());
    let count_bytes = cast_count(count, count_bits);
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(count_bytes.clone()),
        right: Box::new(common::const_u64(8, count_bits)),
        bits: count_bits,
    };
    let shifted = SemanticExpression::Binary {
        op: SemanticOperationBinary::LShr,
        left: Box::new(cast_to_bits(combined, count_bits)),
        right: Box::new(shift_bits),
        bits: count_bits,
    };
    let expression = SemanticExpression::Select {
        condition: Box::new(common::compare(
            SemanticOperationCompare::Uge,
            count_bytes,
            common::const_u64((bits / 8 * 2) as u64, count_bits),
        )),
        when_true: Box::new(common::const_u64(0, bits)),
        when_false: Box::new(truncate_to_bits(shifted, bits)),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn packed_average(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PAVGB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PAVGW as u32 => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let ext_bits = lane_bits + 1;
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        let rounded = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(sum),
            right: Box::new(common::const_u64(1, ext_bits)),
            bits: ext_bits,
        };
        parts.push(truncate_to_bits(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::LShr,
                left: Box::new(rounded),
                right: Box::new(common::const_u64(1, ext_bits)),
                bits: ext_bits,
            },
            lane_bits,
        ));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

fn packed_multiply(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PMULHW as u32 => packed_mul_high(bits, &left, &right),
        InsnId(id) if id == X86Insn::X86_INS_PMULLW as u32 => {
            packed_mul_low(bits, &left, &right, 16)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMULLD as u32 => {
            packed_mul_low(bits, &left, &right, 32)
        }
        InsnId(id) if id == X86Insn::X86_INS_PMULUDQ as u32 => packed_muludq(bits, &left, &right),
        InsnId(id) if id == X86Insn::X86_INS_PMADDWD as u32 => packed_maddwd(bits, &left, &right),
        _ => return None,
    }?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn avx_packed_multiply(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(|expr| cast_to_bits(expr, bits))?;
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPMULHW as u32 => packed_mul_high(bits, &left, &right),
        InsnId(id) if id == X86Insn::X86_INS_VPMULLW as u32 => {
            packed_mul_low(bits, &left, &right, 16)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMADDWD as u32 => packed_maddwd(bits, &left, &right),
        _ => return None,
    }?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn packed_mul_high(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
) -> Option<SemanticExpression> {
    if bits == 0 || bits % 16 != 0 {
        return None;
    }
    let lane_count = bits / 16;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(left, 16, lane)),
            bits: 32,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(right, 16, lane)),
            bits: 32,
        };
        let product = SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: 32,
        };
        parts.push(SemanticExpression::Extract {
            arg: Box::new(product),
            lsb: 16,
            bits: 16,
        });
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn packed_mul_low(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
    lane_bits: u16,
) -> Option<SemanticExpression> {
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = extract_lane(left, lane_bits, lane);
        let rhs = extract_lane(right, lane_bits, lane);
        parts.push(truncate_to_bits(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::Mul,
                left: Box::new(lhs),
                right: Box::new(rhs),
                bits: lane_bits,
            },
            lane_bits,
        ));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn packed_muludq(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
) -> Option<SemanticExpression> {
    if bits != 64 && bits != 128 {
        return None;
    }
    let lane_count = bits / 64;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let src_lane = lane * 2;
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(left, 32, src_lane)),
            bits: 64,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(right, 32, src_lane)),
            bits: 64,
        };
        parts.push(SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: 64,
        });
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn packed_maddwd(
    bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
) -> Option<SemanticExpression> {
    if bits == 0 || bits % 32 != 0 {
        return None;
    }
    let lane_count = bits / 32;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let base = lane * 2;
        let lhs0 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(left, 16, base)),
            bits: 32,
        };
        let rhs0 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(right, 16, base)),
            bits: 32,
        };
        let lhs1 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(left, 16, base + 1)),
            bits: 32,
        };
        let rhs1 = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(right, 16, base + 1)),
            bits: 32,
        };
        let product0 = SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs0),
            right: Box::new(rhs0),
            bits: 32,
        };
        let product1 = SemanticExpression::Binary {
            op: SemanticOperationBinary::Mul,
            left: Box::new(lhs1),
            right: Box::new(rhs1),
            bits: 32,
        };
        parts.push(SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(product0),
            right: Box::new(product1),
            bits: 32,
        });
    }
    Some(SemanticExpression::Concat { parts, bits })
}

#[derive(Clone, Copy)]
enum PackedLaneOp {
    Binary(SemanticOperationBinary),
    Compare(SemanticOperationCompare),
}

fn packed_lanes(
    bits: u16,
    lane_bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
    op: PackedLaneOp,
) -> Option<SemanticExpression> {
    if bits == 0 || lane_bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lsb = lane * lane_bits;
        let left_lane = SemanticExpression::Extract {
            arg: Box::new(left.clone()),
            lsb,
            bits: lane_bits,
        };
        let right_lane = SemanticExpression::Extract {
            arg: Box::new(right.clone()),
            lsb,
            bits: lane_bits,
        };
        let part = match op {
            PackedLaneOp::Binary(operation) => SemanticExpression::Binary {
                op: operation,
                left: Box::new(left_lane),
                right: Box::new(right_lane),
                bits: lane_bits,
            },
            PackedLaneOp::Compare(compare) => {
                let condition = common::compare(compare, left_lane, right_lane);
                let true_lane = SemanticExpression::Const {
                    value: lane_mask(lane_bits),
                    bits: lane_bits,
                };
                SemanticExpression::Select {
                    condition: Box::new(condition),
                    when_true: Box::new(true_lane),
                    when_false: Box::new(common::const_u64(0, lane_bits)),
                    bits: lane_bits,
                }
            }
        };
        parts.push(part);
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn lane_mask(bits: u16) -> u128 {
    if bits as u32 >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

fn unpack(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let (lane_bits, high_half) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_UNPCKLPD as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKHPD as u32 => (64, true),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKLPS as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKHPS as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLBW as u32 => (8, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLWD as u32 => (16, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLDQ as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLQDQ as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHBW as u32 => (8, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHWD as u32 => (16, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHDQ as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHQDQ as u32 => (64, true),
        _ => return None,
    };
    let expression = if bits == 256 {
        SemanticExpression::Concat {
            parts: vec![
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 128, 128),
                    &extract_range(&right, 128, 128),
                    high_half,
                )?,
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 0, 128),
                    &extract_range(&right, 0, 128),
                    high_half,
                )?,
            ],
            bits,
        }
    } else {
        interleave_lanes(bits, lane_bits, &left, &right, high_half)?
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn avx_unpack(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let (lane_bits, high_half) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLBW as u32 => (8, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLWD as u32 => (16, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLDQ as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLQDQ as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHBW as u32 => (8, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHWD as u32 => (16, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHDQ as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHQDQ as u32 => (64, true),
        _ => return None,
    };
    let expression = if bits == 256 {
        SemanticExpression::Concat {
            parts: vec![
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 128, 128),
                    &extract_range(&right, 128, 128),
                    high_half,
                )?,
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 0, 128),
                    &extract_range(&right, 0, 128),
                    high_half,
                )?,
            ],
            bits,
        }
    } else {
        interleave_lanes(bits, lane_bits, &left, &right, high_half)?
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn packed_extract(
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
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PEXTRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_PEXTRQ as u32 => 64,
        InsnId(id) if id == X86Insn::X86_INS_EXTRACTPS as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_VPEXTRQ as u32 => 64,
        _ => return None,
    };
    let lane = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let shift_bits = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(lane),
        right: Box::new(common::const_u64(lane_bits as u64, dst_bits)),
        bits: dst_bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Binary {
                        op: SemanticOperationBinary::LShr,
                        left: Box::new(src),
                        right: Box::new(shift_bits),
                        bits: 128,
                    }),
                    lsb: 0,
                    bits: lane_bits,
                }),
                bits: dst_bits,
            },
        }],
    ))
}

fn packed_insert(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src_vec = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let inserted = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let lane = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane_bits = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PINSRB as u32 => 8,
        InsnId(id) if id == X86Insn::X86_INS_PINSRW as u32 => 16,
        InsnId(id) if id == X86Insn::X86_INS_PINSRD as u32 => 32,
        InsnId(id) if id == X86Insn::X86_INS_PINSRQ as u32 => 64,
        _ => return None,
    };
    let shift = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(lane),
        right: Box::new(common::const_u64(lane_bits as u64, bits)),
        bits,
    };
    let cleared = common::and(
        src_vec,
        common::not(
            SemanticExpression::Binary {
                op: SemanticOperationBinary::Shl,
                left: Box::new(SemanticExpression::Const {
                    value: lane_mask(lane_bits),
                    bits,
                }),
                right: Box::new(shift.clone()),
                bits,
            },
            bits,
        ),
        bits,
    );
    let inserted_value = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(SemanticExpression::Cast {
            op: crate::semantics::SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(inserted),
                lsb: 0,
                bits: lane_bits,
            }),
            bits,
        }),
        right: Box::new(shift),
        bits,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::or(cleared, inserted_value, bits),
        }],
    ))
}

fn movemask(
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
    let src_bits = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))
        .map(|location| common::location_bits(&location))?;
    let dst_bits = common::location_bits(&dst);
    let (lane_bits, lane_count) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPS as u32 => (32, 4),
        InsnId(id) if id == X86Insn::X86_INS_MOVMSKPD as u32 => (64, 2),
        InsnId(id) if id == X86Insn::X86_INS_PMOVMSKB as u32 => (8, 16),
        InsnId(id) if id == X86Insn::X86_INS_VPMOVMSKB as u32 => (8, src_bits / 8),
        _ => return None,
    };
    let mut value = common::const_u64(0, dst_bits);
    for lane in 0..lane_count {
        let bit = SemanticExpression::Extract {
            arg: Box::new(src.clone()),
            lsb: lane * lane_bits + (lane_bits - 1),
            bits: 1,
        };
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: crate::semantics::SemanticOperationCast::ZeroExtend,
                arg: Box::new(bit),
                bits: dst_bits,
            }),
            right: Box::new(common::const_u64(lane as u64, dst_bits)),
            bits: dst_bits,
        };
        value = common::or(value, shifted, dst_bits);
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: value,
        }],
    ))
}

fn shuffle(
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
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_PSHUFD as u32 => {
            shuffle_dwords(bits, &src, imm as u8)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFHW as u32 => {
            shuffle_words_half(bits, &src, imm as u8, true)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFLW as u32 => {
            shuffle_words_half(bits, &src, imm as u8, false)?
        }
        InsnId(id) if id == X86Insn::X86_INS_PSHUFW as u32 => shuffle_words(bits, &src, imm as u8)?,
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn avx_shuffle(
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
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let bits = common::location_bits(&dst);
    let expression = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPSHUFD as u32 => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shuffle_dwords(128, &extract_range(&src, 128, 128), imm as u8)?,
                        shuffle_dwords(128, &extract_range(&src, 0, 128), imm as u8)?,
                    ],
                    bits,
                }
            } else {
                shuffle_dwords(bits, &src, imm as u8)?
            }
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn pshufb(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let mask = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    if bits != 128 {
        return None;
    }
    let mut parts = Vec::with_capacity(16);
    for lane in (0..16).rev() {
        let control = extract_lane(&mask, 8, lane);
        let zero = common::extract_bit(control.clone(), 7);
        let index = SemanticExpression::Extract {
            arg: Box::new(control),
            lsb: 0,
            bits: 4,
        };
        let mut selected = extract_lane(&src, 8, 0);
        for source_lane in 1..16 {
            selected = SemanticExpression::Select {
                condition: Box::new(common::compare(
                    SemanticOperationCompare::Eq,
                    index.clone(),
                    SemanticExpression::Const {
                        value: source_lane as u128,
                        bits: 4,
                    },
                )),
                when_true: Box::new(extract_lane(&src, 8, source_lane)),
                when_false: Box::new(selected),
                bits: 8,
            };
        }
        parts.push(SemanticExpression::Select {
            condition: Box::new(zero),
            when_true: Box::new(common::const_u64(0, 8)),
            when_false: Box::new(selected),
            bits: 8,
        });
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

fn vextracti128(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let lane = (imm as u8 & 0x1) as u16;
    let extracted = extract_range(&src, lane * 128, 128);
    let dst_bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: if dst_bits == 128 {
                extracted
            } else {
                truncate_to_bits(extracted, dst_bits)
            },
        }],
    ))
}

fn vperm2i128(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(3)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let select_half = |select: u8| match select & 0x3 {
        0 => extract_range(&left, 0, 128),
        1 => extract_range(&left, 128, 128),
        2 => extract_range(&right, 0, 128),
        _ => extract_range(&right, 128, 128),
    };
    let low = if (imm as u8 & 0x08) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half(imm as u8)
    };
    let high = if (imm as u8 & 0x80) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half((imm as u8 >> 4) & 0x3)
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![high, low],
                bits: 256,
            },
        }],
    ))
}

fn vpermq(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let control = operands.get(2)?;
    let ArchOperand::X86Operand(control) = control else {
        return None;
    };
    let X86OperandType::Imm(imm) = control.op_type else {
        return None;
    };
    let mut parts = Vec::with_capacity(4);
    for lane in (0..4).rev() {
        let select = ((imm as u8 >> (lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(&src, 64, select));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits: 256 },
        }],
    ))
}

fn vpbroadcastb(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let lane = extract_range(&src, 0, 8);
    let parts = vec![lane; (bits / 8) as usize];
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

fn vpsignw(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let mut parts = Vec::with_capacity((bits / 16) as usize);
    for lane in (0..(bits / 16)).rev() {
        let value = extract_lane(&left, 16, lane);
        let control = extract_lane(&right, 16, lane);
        let is_zero = common::compare(
            SemanticOperationCompare::Eq,
            control.clone(),
            common::const_u64(0, 16),
        );
        let is_negative = common::extract_bit(control, 15);
        parts.push(SemanticExpression::Select {
            condition: Box::new(is_zero),
            when_true: Box::new(common::const_u64(0, 16)),
            when_false: Box::new(SemanticExpression::Select {
                condition: Box::new(is_negative),
                when_true: Box::new(SemanticExpression::Unary {
                    op: crate::semantics::SemanticOperationUnary::Neg,
                    arg: Box::new(value.clone()),
                    bits: 16,
                }),
                when_false: Box::new(value),
                bits: 16,
            }),
            bits: 16,
        });
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

fn shuffle_dwords(bits: u16, src: &SemanticExpression, imm: u8) -> Option<SemanticExpression> {
    if bits < 128 {
        return None;
    }
    let mut parts = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(src, 32, select));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn shuffle_words_half(
    bits: u16,
    src: &SemanticExpression,
    imm: u8,
    high_half: bool,
) -> Option<SemanticExpression> {
    if bits < 128 {
        return None;
    }
    let base_lane = if high_half { 4 } else { 0 };
    let other_base = if high_half { 0 } else { 4 };
    let mut shuffled_half = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        shuffled_half.push(extract_lane(src, 16, base_lane + select));
    }
    let mut parts = Vec::with_capacity(8);
    if high_half {
        parts.extend(shuffled_half);
        for lane in (0..4).rev() {
            parts.push(extract_lane(src, 16, other_base + lane));
        }
    } else {
        for lane in (0..4).rev() {
            parts.push(extract_lane(src, 16, other_base + lane));
        }
        parts.extend(shuffled_half);
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn shuffle_words(bits: u16, src: &SemanticExpression, imm: u8) -> Option<SemanticExpression> {
    if bits != 64 {
        return None;
    }
    let mut parts = Vec::with_capacity(4);
    for out_lane in (0..4).rev() {
        let select = ((imm >> (out_lane * 2)) & 0x3) as u16;
        parts.push(extract_lane(src, 16, select));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn interleave_lanes(
    bits: u16,
    lane_bits: u16,
    left: &SemanticExpression,
    right: &SemanticExpression,
    high_half: bool,
) -> Option<SemanticExpression> {
    if bits == 0 || lane_bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    let half = lane_count / 2;
    let start = if high_half { half } else { 0 };
    let end = start + half;
    let mut parts = Vec::with_capacity((half * 2) as usize);
    for lane in (start..end).rev() {
        parts.push(extract_lane(right, lane_bits, lane));
        parts.push(extract_lane(left, lane_bits, lane));
    }
    Some(SemanticExpression::Concat { parts, bits })
}

fn extract_lane(vector: &SemanticExpression, lane_bits: u16, lane: u16) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(vector.clone()),
        lsb: lane * lane_bits,
        bits: lane_bits,
    }
}

fn extract_range(vector: &SemanticExpression, lsb: u16, bits: u16) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(vector.clone()),
        lsb,
        bits,
    }
}

fn is_memory_operand(operand: &ArchOperand) -> bool {
    matches!(
        operand,
        ArchOperand::X86Operand(op) if matches!(op.op_type, X86OperandType::Mem(_))
    )
}
