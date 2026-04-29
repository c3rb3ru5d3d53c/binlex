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
    SemanticOperationCast, SemanticOperationCompare, SemanticOperationUnary, SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86OperandType};

use super::common;

#[path = "vector/bitwise.rs"]
mod bitwise_helpers;
#[path = "vector/moves.rs"]
mod move_helpers;
#[path = "vector/pack.rs"]
mod pack_helpers;
#[path = "vector/lane_ops.rs"]
mod lane_ops_helpers;
#[path = "vector/shuffle/mod.rs"]
mod shuffle_helpers;

use bitwise_helpers::*;
use lane_ops_helpers as lane_ops;
use lane_ops_helpers::*;
use move_helpers::*;
use pack_helpers::*;
use shuffle_helpers as shuffle_ops;

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
                X86Insn::X86_INS_VPMOVSXBW as u32,
                X86Insn::X86_INS_PMOVSXBD as u32,
                X86Insn::X86_INS_VPMOVSXBD as u32,
                X86Insn::X86_INS_PMOVSXBQ as u32,
                X86Insn::X86_INS_VPMOVSXBQ as u32,
                X86Insn::X86_INS_PMOVSXWD as u32,
                X86Insn::X86_INS_VPMOVSXWD as u32,
                X86Insn::X86_INS_PMOVSXWQ as u32,
                X86Insn::X86_INS_VPMOVSXWQ as u32,
                X86Insn::X86_INS_PMOVSXDQ as u32,
                X86Insn::X86_INS_VPMOVSXDQ as u32,
                X86Insn::X86_INS_PMOVZXBW as u32,
                X86Insn::X86_INS_VPMOVZXBW as u32,
                X86Insn::X86_INS_PMOVZXBD as u32,
                X86Insn::X86_INS_VPMOVZXBD as u32,
                X86Insn::X86_INS_PMOVZXBQ as u32,
                X86Insn::X86_INS_VPMOVZXBQ as u32,
                X86Insn::X86_INS_PMOVZXWD as u32,
                X86Insn::X86_INS_VPMOVZXWD as u32,
                X86Insn::X86_INS_PMOVZXWQ as u32,
                X86Insn::X86_INS_VPMOVZXWQ as u32,
                X86Insn::X86_INS_PMOVZXDQ as u32,
                X86Insn::X86_INS_VPMOVZXDQ as u32,
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
                X86Insn::X86_INS_PCMPGTQ as u32,
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
                lane_ops::packed_lane_op(machine, instruction, operands)
            }
        }
        InsnId(id)
            if [X86Insn::X86_INS_PADDUSB as u32, X86Insn::X86_INS_PADDUSW as u32].contains(&id) =>
        {
            lane_ops::packed_unsigned_saturating_add(machine, instruction, operands)
        }
        InsnId(id)
            if [X86Insn::X86_INS_VPADDUSB as u32, X86Insn::X86_INS_VPADDUSW as u32]
                .contains(&id) =>
        {
            lane_ops::avx_packed_unsigned_saturating_add(machine, instruction, operands)
        }
        InsnId(id)
            if [X86Insn::X86_INS_PADDSB as u32, X86Insn::X86_INS_PADDSW as u32].contains(&id) =>
        {
            lane_ops::packed_signed_saturating_add(machine, instruction, operands)
        }
        InsnId(id)
            if [X86Insn::X86_INS_VPADDSB as u32, X86Insn::X86_INS_VPADDSW as u32]
                .contains(&id) =>
        {
            lane_ops::avx_packed_signed_saturating_add(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PABSB as u32,
                X86Insn::X86_INS_PABSW as u32,
                X86Insn::X86_INS_PABSD as u32,
            ]
            .contains(&id) =>
        {
            lane_ops::packed_abs(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPADDB as u32,
                X86Insn::X86_INS_VPADDW as u32,
                X86Insn::X86_INS_VPADDD as u32,
                X86Insn::X86_INS_VPADDQ as u32,
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
                X86Insn::X86_INS_VPCMPGTQ as u32,
            ]
            .contains(&id) =>
        {
            lane_ops::avx_packed_lane_op(machine, instruction, operands)
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
            lane_ops::packed_average(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PHADDW as u32,
                X86Insn::X86_INS_PHADDD as u32,
                X86Insn::X86_INS_PHADDSW as u32,
                X86Insn::X86_INS_PHSUBW as u32,
                X86Insn::X86_INS_PHSUBD as u32,
            ]
            .contains(&id) =>
        {
            lane_ops::packed_horizontal(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_VPHADDW as u32,
                X86Insn::X86_INS_VPHADDD as u32,
                X86Insn::X86_INS_VPHADDSW as u32,
            ]
            .contains(&id) =>
        {
            lane_ops::avx_packed_horizontal(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PSIGNB as u32,
                X86Insn::X86_INS_PSIGNW as u32,
                X86Insn::X86_INS_PSIGND as u32,
            ]
            .contains(&id) =>
        {
            lane_ops::packed_sign(machine, instruction, operands)
        }
        InsnId(id)
            if [X86Insn::X86_INS_PSUBUSB as u32, X86Insn::X86_INS_PSUBUSW as u32].contains(&id) =>
        {
            lane_ops::packed_unsigned_saturating_sub(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_VPMINUB as u32 => {
            avx_binary(machine, operands, SemanticOperationBinary::MinUnsigned)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PMULHW as u32,
                X86Insn::X86_INS_PMULHUW as u32,
                X86Insn::X86_INS_PMULLW as u32,
                X86Insn::X86_INS_PMULLD as u32,
                X86Insn::X86_INS_PMULUDQ as u32,
                X86Insn::X86_INS_PMADDWD as u32,
                X86Insn::X86_INS_PMADDUBSW as u32,
                X86Insn::X86_INS_PMULHRSW as u32,
            ]
            .contains(&id) =>
        {
            lane_ops::packed_multiply(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_PSADBW as u32 => lane_ops::psadbw(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_VPMADDWD as u32,
                X86Insn::X86_INS_VPMULHW as u32,
                X86Insn::X86_INS_VPMULLW as u32,
            ]
            .contains(&id) =>
        {
            lane_ops::avx_packed_multiply(machine, instruction, operands)
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
                X86Insn::X86_INS_VPSLLQ as u32,
                X86Insn::X86_INS_VPSRLQ as u32,
            ]
            .contains(&id) =>
        {
            avx_packed_shift(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_PTEST as u32 => ptest(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPTEST as u32 => avx_ptest(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_PALIGNR as u32 => bitwise_helpers::palignr(machine, operands),
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
                shuffle_ops::pshufb(machine, operands)
            } else if [
                X86Insn::X86_INS_PSHUFD as u32,
                X86Insn::X86_INS_PSHUFHW as u32,
                X86Insn::X86_INS_PSHUFLW as u32,
                X86Insn::X86_INS_PSHUFW as u32,
            ]
            .contains(&id)
            {
                shuffle_ops::shuffle(machine, instruction, operands)
            } else {
                shuffle_ops::unpack(machine, instruction, operands)
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
                shuffle_ops::avx_shuffle(machine, instruction, operands)
            } else {
                shuffle_ops::avx_unpack(machine, instruction, operands)
            }
        }
        InsnId(id) if id == X86Insn::X86_INS_KMOVW as u32 => assign(machine, operands),
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
            shuffle_ops::packed_extract(machine, instruction, operands)
        }
        InsnId(id)
            if [
                X86Insn::X86_INS_PINSRB as u32,
                X86Insn::X86_INS_PINSRD as u32,
                X86Insn::X86_INS_PINSRQ as u32,
                X86Insn::X86_INS_PINSRW as u32,
                X86Insn::X86_INS_VPINSRW as u32,
            ]
            .contains(&id) =>
        {
            shuffle_ops::packed_insert(machine, instruction, operands)
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
            shuffle_ops::movemask(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_MASKMOVQ as u32 => shuffle_ops::maskmovq(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VINSERTF128 as u32 => shuffle_ops::vinsertf128(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VEXTRACTI128 as u32 => shuffle_ops::vextracti128(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPERM2I128 as u32 => shuffle_ops::vperm2i128(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPERMQ as u32 => shuffle_ops::vpermq(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPBROADCASTB as u32 => shuffle_ops::vpbroadcastb(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VPSIGNW as u32 => shuffle_ops::vpsignw(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VZEROUPPER as u32 => Some(shuffle_ops::vzeroupper()),
        InsnId(id) if id == X86Insn::X86_INS_XORPS as u32 => {
            binary(machine, operands, SemanticOperationBinary::Xor)
        }
        InsnId(id) if id == X86Insn::X86_INS_ANDPS as u32 => {
            binary(machine, operands, SemanticOperationBinary::And)
        }
        _ if matches!(
            instruction.mnemonic().unwrap_or_default(),
            "vmaskmovps" | "vmaskmovpd"
        ) =>
        {
            shuffle_ops::vmaskmov(machine, instruction, operands)
        }
        _ => None,
    }
}
