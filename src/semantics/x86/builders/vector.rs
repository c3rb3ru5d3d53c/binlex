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

use crate::Architecture;
use crate::semantics::x86::helpers as common;
use crate::semantics::x86::instruction::InstructionDetailX86;
use crate::semantics::x86::operand::{X86OperandKind, X86OperandView};
use crate::semantics::{
    Semantic, SemanticAddressSpace, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticTerminator,
};

pub(crate) fn build(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    match view.mnemonic.as_str() {
        "movups" | "movupd" | "movaps" | "movapd" | "movdqu" | "movdqa" | "lddqu" | "movd"
        | "movq" | "movntdq" | "movntpd" | "movntps" | "movntq" | "movnti" => assign(machine, view),
        "movdq2q" => movdq2q(machine, view),
        "movq2dq" => movq2dq(machine, view),
        "vmovups" | "vmovaps" | "vmovdqu" | "vmovdqa" | "vmovd" | "vmovq" | "vmovntdq" => {
            avx_assign(machine, view)
        }
        "kmovw" => assign(machine, view),
        "movss" => scalar_single_move(machine, view),
        "movhlps" | "movlhps" | "movhpd" | "movlpd" | "movhps" | "movlps" => {
            partial_lane_move(machine, view)
        }
        "movddup" | "movshdup" | "movsldup" => duplicate_move(machine, view),
        "pmovsxbw" | "vpmovsxbw" | "pmovsxbd" | "vpmovsxbd" | "pmovsxbq" | "vpmovsxbq"
        | "pmovsxwd" | "vpmovsxwd" | "pmovsxwq" | "vpmovsxwq" | "pmovsxdq" | "vpmovsxdq"
        | "pmovzxbw" | "vpmovzxbw" | "pmovzxbd" | "vpmovzxbd" | "pmovzxbq" | "vpmovzxbq"
        | "pmovzxwd" | "vpmovzxwd" | "pmovzxwq" | "vpmovzxwq" | "pmovzxdq" | "vpmovzxdq" => {
            packed_widen(machine, view)
        }
        "por" | "pand" | "andpd" | "pxor" | "orps" | "orpd" | "xorpd" | "xorps" | "andps" => {
            binary(
                machine,
                view,
                match view.mnemonic.as_str() {
                    "por" | "orps" | "orpd" => SemanticOperationBinary::Or,
                    "pand" | "andpd" | "andps" => SemanticOperationBinary::And,
                    _ => SemanticOperationBinary::Xor,
                },
            )
        }
        "vpand" | "vpor" | "vpxor" | "vxorps" => avx_binary(
            machine,
            view,
            match view.mnemonic.as_str() {
                "vpor" => SemanticOperationBinary::Or,
                "vpand" => SemanticOperationBinary::And,
                _ => SemanticOperationBinary::Xor,
            },
        ),
        "pandn" | "andnpd" | "andnps" => pandn(machine, view),
        "vpandn" => avx_pandn(machine, view),
        "packssdw" | "packsswb" | "packuswb" => packed_pack(machine, view),
        "vpackssdw" | "vpacksswb" | "vpackuswb" => avx_packed_pack(machine, view),
        "paddb" | "paddw" | "paddd" | "paddq" | "psubb" | "psubw" | "psubd" | "psubq"
        | "pmaxsb" | "pmaxsw" | "pmaxsd" | "pmaxub" | "pmaxuw" | "pmaxud" | "pminsb" | "pminsw"
        | "pminsd" | "pminub" | "pminuw" | "pminud" | "pcmpeqb" | "pcmpeqw" | "pcmpeqd"
        | "pcmpgtb" | "pcmpgtw" | "pcmpgtd" | "pcmpgtq" => packed_lane_op(machine, view),
        "vpaddb" | "vpaddw" | "vpaddd" | "vpaddq" | "vpsubb" | "vpsubw" | "vpsubd" | "vpsubq"
        | "vpcmpeqb" | "vpcmpeqw" | "vpcmpeqd" | "vpcmpeqq" | "vpcmpgtb" | "vpcmpgtw"
        | "vpcmpgtd" | "vpcmpgtq" | "vpminub" | "vpminuw" | "vpminud" => {
            avx_packed_lane_op(machine, view)
        }
        "paddusb" | "paddusw" => packed_unsigned_saturating_add(machine, view),
        "vpaddusb" | "vpaddusw" => avx_packed_unsigned_saturating_add(machine, view),
        "paddsb" | "paddsw" => packed_signed_saturating_add(machine, view),
        "vpaddsb" | "vpaddsw" => avx_packed_signed_saturating_add(machine, view),
        "psubusb" | "psubusw" => packed_unsigned_saturating_sub(machine, view),
        "pabsb" | "pabsw" | "pabsd" => packed_abs(machine, view),
        "pavgb" | "pavgw" => packed_average(machine, view),
        "phaddw" | "phaddd" | "phaddsw" | "phsubw" | "phsubd" => packed_horizontal(machine, view),
        "vphaddw" | "vphaddd" | "vphaddsw" => avx_packed_horizontal(machine, view),
        "psignb" | "psignw" | "psignd" => packed_sign(machine, view),
        "pmulhw" | "pmulhuw" | "pmullw" | "pmulld" | "pmuludq" | "pmaddwd" | "pmaddubsw"
        | "pmulhrsw" => packed_multiply(machine, view),
        "vpmaddwd" | "vpmulhw" | "vpmullw" => avx_packed_multiply(machine, view),
        "psadbw" => psadbw(machine, view),
        "pshufb" => pshufb(machine, view),
        "pshufd" | "pshufhw" | "pshuflw" | "pshufw" => shuffle(machine, view),
        "unpcklpd" | "unpckhpd" | "unpcklps" | "unpckhps" | "punpcklbw" | "punpckhbw"
        | "punpcklwd" | "punpckhwd" | "punpckldq" | "punpckhdq" | "punpcklqdq" | "punpckhqdq" => {
            unpack(machine, view)
        }
        "vpshufd" => avx_shuffle(machine, view),
        "vpunpcklbw" | "vpunpckhbw" | "vpunpcklwd" | "vpunpckhwd" | "vpunpckldq" | "vpunpckhdq"
        | "vpunpcklqdq" | "vpunpckhqdq" => avx_unpack(machine, view),
        "pextrw" | "pextrb" | "pextrd" | "pextrq" | "extractps" | "vpextrb" | "vpextrd"
        | "vpextrq" | "vpextrw" => packed_extract(machine, view),
        "pinsrb" | "pinsrd" | "pinsrq" | "pinsrw" | "vpinsrw" => packed_insert(machine, view),
        "vinsertf128" => vinsertf128(machine, view),
        "vextracti128" => vextracti128(machine, view),
        "movmskps" | "movmskpd" | "pmovmskb" | "vpmovmskb" => movemask(machine, view),
        "maskmovq" => maskmovq(machine, view),
        "vperm2i128" => vperm2i128(machine, view),
        "vpermq" => vpermq(machine, view),
        "vpbroadcastb" => vpbroadcastb(machine, view),
        "vpsignw" => vpsignw(machine, view),
        "vzeroupper" => Some(vzeroupper()),
        "vmaskmovps" | "vmaskmovpd" => vmaskmov(machine, view),
        "psllw" | "pslld" | "psllq" | "psrlw" | "psrld" | "psrlq" | "psraw" | "psrad"
        | "pslldq" | "psrldq" => packed_shift(machine, view),
        "vpslldq" | "vpsrldq" | "vpsllq" | "vpsrlq" => avx_packed_shift(machine, view),
        "ptest" => ptest(machine, view),
        "vptest" => avx_ptest(machine, view),
        "palignr" => palignr(machine, view),
        _ => None,
    }
}

fn assign(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let expression = operand_expr(machine, view.operands().get(1)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn movdq2q(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: truncate_to_bits(src, bits),
        }],
    ))
}

fn movq2dq(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
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

fn avx_assign(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let expression = operand_expr(machine, view.operands().get(1)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn scalar_single_move(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_bits = common::location_bits(&dst);
    let src = operand_expr(machine, view.operands().get(1)?)?;

    let expression = if dst_bits <= 32 {
        SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: dst_bits,
        }
    } else if view
        .operands()
        .get(1)
        .is_some_and(|operand| operand.kind == X86OperandKind::Memory)
    {
        SemanticExpression::Concat {
            parts: vec![
                common::const_u64(0, dst_bits - 32),
                extract_range(&src, 0, 32),
            ],
            bits: dst_bits,
        }
    } else {
        let upper = operand_expr(machine, view.operands().first()?)
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

fn packed_widen(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let dst_bits = common::location_bits(&dst);
    let (src_lane_bits, dst_lane_bits, cast) = match view.mnemonic.as_str() {
        "pmovsxbw" | "vpmovsxbw" => (8, 16, SemanticOperationCast::SignExtend),
        "pmovsxbd" | "vpmovsxbd" => (8, 32, SemanticOperationCast::SignExtend),
        "pmovsxbq" | "vpmovsxbq" => (8, 64, SemanticOperationCast::SignExtend),
        "pmovsxwd" | "vpmovsxwd" => (16, 32, SemanticOperationCast::SignExtend),
        "pmovsxwq" | "vpmovsxwq" => (16, 64, SemanticOperationCast::SignExtend),
        "pmovsxdq" | "vpmovsxdq" => (32, 64, SemanticOperationCast::SignExtend),
        "pmovzxbw" | "vpmovzxbw" => (8, 16, SemanticOperationCast::ZeroExtend),
        "pmovzxbd" | "vpmovzxbd" => (8, 32, SemanticOperationCast::ZeroExtend),
        "pmovzxbq" | "vpmovzxbq" => (8, 64, SemanticOperationCast::ZeroExtend),
        "pmovzxwd" | "vpmovzxwd" => (16, 32, SemanticOperationCast::ZeroExtend),
        "pmovzxwq" | "vpmovzxwq" => (16, 64, SemanticOperationCast::ZeroExtend),
        "pmovzxdq" | "vpmovzxdq" => (32, 64, SemanticOperationCast::ZeroExtend),
        _ => return None,
    };
    let lane_count = dst_bits / dst_lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        parts.push(SemanticExpression::Cast {
            op: cast,
            arg: Box::new(extract_lane(&src, src_lane_bits, lane)),
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

fn partial_lane_move(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_bits = common::location_bits(&dst);
    if dst_bits < 128 {
        return None;
    }
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let expression = match view.mnemonic.as_str() {
        "movhlps" => SemanticExpression::Concat {
            parts: vec![extract_range(&left, 64, 64), extract_range(&right, 64, 64)],
            bits: 128,
        },
        "movlhps" => SemanticExpression::Concat {
            parts: vec![extract_range(&right, 0, 64), extract_range(&left, 0, 64)],
            bits: 128,
        },
        "movhpd" | "movhps" => SemanticExpression::Concat {
            parts: vec![extract_range(&right, 0, 64), extract_range(&left, 0, 64)],
            bits: 128,
        },
        "movlpd" | "movlps" => SemanticExpression::Concat {
            parts: vec![extract_range(&left, 64, 64), extract_range(&right, 0, 64)],
            bits: 128,
        },
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn duplicate_move(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let dst_bits = common::location_bits(&dst);
    if dst_bits != 128 {
        return None;
    }

    let parts = match view.mnemonic.as_str() {
        "movddup" => {
            let low = extract_lane(&src, 64, 0);
            vec![low.clone(), low]
        }
        "movsldup" => vec![
            extract_lane(&src, 32, 2),
            extract_lane(&src, 32, 2),
            extract_lane(&src, 32, 0),
            extract_lane(&src, 32, 0),
        ],
        "movshdup" => vec![
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
    view: &InstructionDetailX86,
    operation: SemanticOperationBinary,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
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
    view: &InstructionDetailX86,
    operation: SemanticOperationBinary,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
    let left = cast_to_bits(left, bits);
    let right = cast_to_bits(right, bits);
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

fn pandn(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::and(common::not(left, bits), right, bits),
        }],
    ))
}

fn avx_pandn(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let left = cast_to_bits(operand_expr(machine, view.operands().get(1)?)?, bits);
    let right = cast_to_bits(operand_expr(machine, view.operands().get(2)?)?, bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: common::and(common::not(left, bits), right, bits),
        }],
    ))
}

fn avx_packed_pack(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let (src_lane_bits, dst_lane_bits, pack_kind) = match view.mnemonic.as_str() {
        "vpackssdw" => (32, 16, PackKind::Signed),
        "vpacksswb" => (16, 8, PackKind::Signed),
        "vpackuswb" => (16, 8, PackKind::UnsignedByte),
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
            parts.push(SemanticExpression::Concat {
                parts: lanes.into_iter().rev().collect(),
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

fn packed_pack(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let (src_lane_bits, dst_lane_bits, pack_kind) = match view.mnemonic.as_str() {
        "packssdw" => (32, 16, PackKind::Signed),
        "packsswb" => (16, 8, PackKind::Signed),
        "packuswb" => (16, 8, PackKind::UnsignedByte),
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
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: lanes.into_iter().rev().collect(),
                bits,
            },
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

fn packed_lane_op(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "paddb" | "psubb" | "pmaxsb" | "pmaxub" | "pminsb" | "pminub" | "pcmpeqb" | "pcmpgtb" => 8,
        "paddw" | "psubw" | "pmaxsw" | "pmaxuw" | "pminsw" | "pminuw" | "pcmpeqw" | "pcmpgtw" => 16,
        "paddd" | "psubd" | "pmaxsd" | "pmaxud" | "pminsd" | "pminud" | "pcmpeqd" | "pcmpgtd" => 32,
        "paddq" | "psubq" | "pcmpgtq" => 64,
        _ => return None,
    };
    let expression = packed_lanes(
        bits,
        lane_bits,
        &left,
        &right,
        match view.mnemonic.as_str() {
            "paddb" | "paddw" | "paddd" | "paddq" => {
                PackedLaneOp::Binary(SemanticOperationBinary::Add)
            }
            "psubb" | "psubw" | "psubd" | "psubq" => {
                PackedLaneOp::Binary(SemanticOperationBinary::Sub)
            }
            "pmaxsb" | "pmaxsw" | "pmaxsd" => {
                PackedLaneOp::Binary(SemanticOperationBinary::MaxSigned)
            }
            "pmaxub" | "pmaxuw" | "pmaxud" => {
                PackedLaneOp::Binary(SemanticOperationBinary::MaxUnsigned)
            }
            "pminsb" | "pminsw" | "pminsd" => {
                PackedLaneOp::Binary(SemanticOperationBinary::MinSigned)
            }
            "pminub" | "pminuw" | "pminud" | "vpminub" | "vpminuw" | "vpminud" => {
                PackedLaneOp::Binary(SemanticOperationBinary::MinUnsigned)
            }
            "pcmpeqb" | "pcmpeqw" | "pcmpeqd" => {
                PackedLaneOp::Compare(SemanticOperationCompare::Eq)
            }
            "pcmpgtb" | "pcmpgtw" | "pcmpgtd" | "pcmpgtq" => {
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

fn avx_packed_lane_op(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let left = cast_to_bits(operand_expr(machine, view.operands().get(1)?)?, bits);
    let right = cast_to_bits(operand_expr(machine, view.operands().get(2)?)?, bits);
    let lane_bits = match view.mnemonic.as_str() {
        "vpaddb" | "vpsubb" | "vpcmpeqb" | "vpcmpgtb" | "vpminub" => 8,
        "vpaddw" | "vpsubw" | "vpcmpeqw" | "vpcmpgtw" | "vpminuw" => 16,
        "vpaddd" | "vpsubd" | "vpcmpeqd" | "vpcmpgtd" | "vpminud" => 32,
        "vpaddq" | "vpsubq" | "vpcmpeqq" | "vpcmpgtq" => 64,
        _ => return None,
    };
    let expression = packed_lanes(
        bits,
        lane_bits,
        &left,
        &right,
        match view.mnemonic.as_str() {
            "vpaddb" | "vpaddw" | "vpaddd" | "vpaddq" => {
                PackedLaneOp::Binary(SemanticOperationBinary::Add)
            }
            "vpsubb" | "vpsubw" | "vpsubd" | "vpsubq" => {
                PackedLaneOp::Binary(SemanticOperationBinary::Sub)
            }
            "vpminub" | "vpminuw" | "vpminud" => {
                PackedLaneOp::Binary(SemanticOperationBinary::MinUnsigned)
            }
            "vpcmpeqb" | "vpcmpeqw" | "vpcmpeqd" | "vpcmpeqq" => {
                PackedLaneOp::Compare(SemanticOperationCompare::Eq)
            }
            "vpcmpgtb" | "vpcmpgtw" | "vpcmpgtd" | "vpcmpgtq" => {
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

fn packed_unsigned_saturating_add(
    machine: Architecture,
    view: &InstructionDetailX86,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "paddusb" => 8,
        "paddusw" => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let ext_bits = lane_bits + 1;
    let max_lane_value = (1u64 << lane_bits) - 1;
    let max_ext = common::const_u64(max_lane_value, ext_bits);
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
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::compare(
                SemanticOperationCompare::Ugt,
                sum.clone(),
                max_ext.clone(),
            )),
            when_true: Box::new(common::const_u64(max_lane_value, lane_bits)),
            when_false: Box::new(truncate_to_bits(sum, lane_bits)),
            bits: lane_bits,
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

fn packed_signed_saturating_add(
    machine: Architecture,
    view: &InstructionDetailX86,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "paddsb" => 8,
        "paddsw" => 16,
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
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        parts.push(saturate_lane(sum, ext_bits, lane_bits, PackKind::Signed));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

fn avx_packed_unsigned_saturating_add(
    machine: Architecture,
    view: &InstructionDetailX86,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "vpaddusb" => 8,
        "vpaddusw" => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let ext_bits = lane_bits + 1;
    let max_lane_value = (1u64 << lane_bits) - 1;
    let max_ext = common::const_u64(max_lane_value, ext_bits);
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
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::compare(
                SemanticOperationCompare::Ugt,
                sum.clone(),
                max_ext.clone(),
            )),
            when_true: Box::new(common::const_u64(max_lane_value, lane_bits)),
            when_false: Box::new(truncate_to_bits(sum, lane_bits)),
            bits: lane_bits,
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

fn avx_packed_signed_saturating_add(
    machine: Architecture,
    view: &InstructionDetailX86,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "vpaddsb" => 8,
        "vpaddsw" => 16,
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
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&left, lane_bits, lane)),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(extract_lane(&right, lane_bits, lane)),
            bits: ext_bits,
        };
        let sum = SemanticExpression::Binary {
            op: SemanticOperationBinary::Add,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        parts.push(saturate_lane(sum, ext_bits, lane_bits, PackKind::Signed));
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat { parts, bits },
        }],
    ))
}

fn packed_abs(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "pabsb" => 8,
        "pabsw" => 16,
        "pabsd" => 32,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let value = extract_lane(&src, lane_bits, lane);
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::extract_bit(value.clone(), lane_bits - 1)),
            when_true: Box::new(SemanticExpression::Unary {
                op: SemanticOperationUnary::Neg,
                arg: Box::new(value.clone()),
                bits: lane_bits,
            }),
            when_false: Box::new(value),
            bits: lane_bits,
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

fn packed_average(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "pavgb" => 8,
        "pavgw" => 16,
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

fn packed_horizontal(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let (lane_bits, op, saturating) = match view.mnemonic.as_str() {
        "phaddw" => (16, SemanticOperationBinary::Add, false),
        "phaddd" => (32, SemanticOperationBinary::Add, false),
        "phaddsw" => (16, SemanticOperationBinary::Add, true),
        "phsubw" => (16, SemanticOperationBinary::Sub, false),
        "phsubd" => (32, SemanticOperationBinary::Sub, false),
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    if lane_count % 2 != 0 {
        return None;
    }
    let pair_count = lane_count / 2;
    let mut lanes = Vec::with_capacity(lane_count as usize);
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &left,
            lane_bits,
            pair * 2,
            op,
            saturating,
        ));
    }
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &right,
            lane_bits,
            pair * 2,
            op,
            saturating,
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

fn avx_packed_horizontal(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let (lane_bits, op, saturating) = match view.mnemonic.as_str() {
        "vphaddw" => (16, SemanticOperationBinary::Add, false),
        "vphaddd" => (32, SemanticOperationBinary::Add, false),
        "vphaddsw" => (16, SemanticOperationBinary::Add, true),
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }
    let lane_count = bits / lane_bits;
    if lane_count % 2 != 0 {
        return None;
    }
    let pair_count = lane_count / 2;
    let mut lanes = Vec::with_capacity(lane_count as usize);
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &left,
            lane_bits,
            pair * 2,
            op,
            saturating,
        ));
    }
    for pair in 0..pair_count {
        lanes.push(horizontal_pair_result(
            &right,
            lane_bits,
            pair * 2,
            op,
            saturating,
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

fn packed_sign(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "psignb" => 8,
        "psignw" => 16,
        "psignd" => 32,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let value = extract_lane(&left, lane_bits, lane);
        let control = extract_lane(&right, lane_bits, lane);
        let is_zero = common::compare(
            SemanticOperationCompare::Eq,
            control.clone(),
            common::const_u64(0, lane_bits),
        );
        let is_negative = common::extract_bit(control, lane_bits - 1);
        parts.push(SemanticExpression::Select {
            condition: Box::new(is_zero),
            when_true: Box::new(common::const_u64(0, lane_bits)),
            when_false: Box::new(SemanticExpression::Select {
                condition: Box::new(is_negative),
                when_true: Box::new(SemanticExpression::Unary {
                    op: SemanticOperationUnary::Neg,
                    arg: Box::new(value.clone()),
                    bits: lane_bits,
                }),
                when_false: Box::new(value),
                bits: lane_bits,
            }),
            bits: lane_bits,
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

fn packed_multiply(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let expression = match view.mnemonic.as_str() {
        "pmulhw" => packed_mul_high(bits, &left, &right),
        "pmulhuw" => packed_mul_high_unsigned(bits, &left, &right),
        "pmullw" => packed_mul_low(bits, &left, &right, 16),
        "pmulld" => packed_mul_low(bits, &left, &right, 32),
        "pmuludq" => packed_muludq(bits, &left, &right),
        "pmaddwd" => packed_maddwd(bits, &left, &right),
        "pmaddubsw" => Some(SemanticExpression::Intrinsic {
            name: "x86.pmaddubsw".to_string(),
            args: vec![left.clone(), right.clone()],
            bits,
        }),
        "pmulhrsw" => Some(SemanticExpression::Intrinsic {
            name: "x86.pmulhrsw".to_string(),
            args: vec![left.clone(), right.clone()],
            bits,
        }),
        _ => return None,
    }?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn avx_packed_multiply(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let left =
        operand_expr(machine, view.operands().get(1)?).map(|expr| cast_to_bits(expr, bits))?;
    let right =
        operand_expr(machine, view.operands().get(2)?).map(|expr| cast_to_bits(expr, bits))?;
    let expression = match view.mnemonic.as_str() {
        "vpmulhw" => packed_mul_high(bits, &left, &right),
        "vpmullw" => packed_mul_low(bits, &left, &right, 16),
        "vpmaddwd" => packed_maddwd(bits, &left, &right),
        _ => return None,
    }?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn psadbw(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Intrinsic {
                name: "x86.psadbw".to_string(),
                args: vec![left, right],
                bits,
            },
        }],
    ))
}

fn packed_unsigned_saturating_sub(
    machine: Architecture,
    view: &InstructionDetailX86,
) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "psubusb" => 8,
        "psubusw" => 16,
        _ => return None,
    };
    if bits == 0 || bits % lane_bits != 0 {
        return None;
    }

    let lane_count = bits / lane_bits;
    let mut parts = Vec::with_capacity(lane_count as usize);
    for lane in (0..lane_count).rev() {
        let lhs = extract_lane(&left, lane_bits, lane);
        let rhs = extract_lane(&right, lane_bits, lane);
        let diff = SemanticExpression::Binary {
            op: SemanticOperationBinary::Sub,
            left: Box::new(lhs.clone()),
            right: Box::new(rhs.clone()),
            bits: lane_bits,
        };
        parts.push(SemanticExpression::Select {
            condition: Box::new(common::compare(SemanticOperationCompare::Ult, lhs, rhs)),
            when_true: Box::new(common::const_u64(0, lane_bits)),
            when_false: Box::new(diff),
            bits: lane_bits,
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

fn shuffle(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let imm = view.operands().get(2)?.immediate_value()? as u8;
    let bits = common::location_bits(&dst);
    let expression = match view.mnemonic.as_str() {
        "pshufd" => shuffle_dwords(bits, &src, imm)?,
        "pshufhw" => shuffle_words_half(bits, &src, imm, true)?,
        "pshuflw" => shuffle_words_half(bits, &src, imm, false)?,
        "pshufw" => shuffle_words(bits, &src, imm)?,
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn avx_shuffle(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let imm = view.operands().get(2)?.immediate_value()? as u8;
    let bits = common::location_bits(&dst);
    let expression = match view.mnemonic.as_str() {
        "vpshufd" => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shuffle_dwords(128, &extract_range(&src, 128, 128), imm)?,
                        shuffle_dwords(128, &extract_range(&src, 0, 128), imm)?,
                    ],
                    bits,
                }
            } else {
                shuffle_dwords(bits, &src, imm)?
            }
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn pshufb(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().first()?)?;
    let mask = operand_expr(machine, view.operands().get(1)?)?;
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

fn unpack(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let (lane_bits, high_half) = match view.mnemonic.as_str() {
        "unpcklpd" => (64, false),
        "unpckhpd" => (64, true),
        "unpcklps" => (32, false),
        "unpckhps" => (32, true),
        "punpcklbw" => (8, false),
        "punpcklwd" => (16, false),
        "punpckldq" => (32, false),
        "punpcklqdq" => (64, false),
        "punpckhbw" => (8, true),
        "punpckhwd" => (16, true),
        "punpckhdq" => (32, true),
        "punpckhqdq" => (64, true),
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

fn avx_unpack(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let (lane_bits, high_half) = match view.mnemonic.as_str() {
        "vpunpcklbw" => (8, false),
        "vpunpcklwd" => (16, false),
        "vpunpckldq" => (32, false),
        "vpunpcklqdq" => (64, false),
        "vpunpckhbw" => (8, true),
        "vpunpckhwd" => (16, true),
        "vpunpckhdq" => (32, true),
        "vpunpckhqdq" => (64, true),
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

fn packed_extract(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let dst_bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "pextrb" | "vpextrb" => 8,
        "pextrw" | "vpextrw" => 16,
        "pextrd" | "extractps" | "vpextrd" => 32,
        "pextrq" | "vpextrq" => 64,
        _ => return None,
    };
    let lane = operand_expr(machine, view.operands().get(2)?)?;
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
                op: SemanticOperationCast::ZeroExtend,
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

fn packed_insert(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src_vec = operand_expr(machine, view.operands().first()?)?;
    let inserted = operand_expr(machine, view.operands().get(1)?)?;
    let lane = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let lane_bits = match view.mnemonic.as_str() {
        "pinsrb" => 8,
        "pinsrw" | "vpinsrw" => 16,
        "pinsrd" => 32,
        "pinsrq" => 64,
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
            op: SemanticOperationCast::ZeroExtend,
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

fn vextracti128(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let lane = (view.operands().get(2)?.immediate_value()? as u8 & 0x1) as u16;
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

fn vinsertf128(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let base = operand_expr(machine, view.operands().get(1)?)?;
    let inserted = operand_expr(machine, view.operands().get(2)?)?;
    let imm = view.operands().get(3)?.immediate_value()? as u8;
    let lower = extract_range(&base, 0, 128);
    let upper = extract_range(&base, 128, 128);
    let expression = if (imm & 0x1) == 0 {
        SemanticExpression::Concat {
            parts: vec![upper, extract_range(&inserted, 0, 128)],
            bits: 256,
        }
    } else {
        SemanticExpression::Concat {
            parts: vec![extract_range(&inserted, 0, 128), lower],
            bits: 256,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn movemask(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let src_bits = view.operands().get(1)?.size_bits;
    let dst_bits = common::location_bits(&dst);
    let (lane_bits, lane_count) = match view.mnemonic.as_str() {
        "movmskps" => (32, 4),
        "movmskpd" => (64, 2),
        "pmovmskb" => (8, 16),
        "vpmovmskb" => (8, src_bits / 8),
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
                op: SemanticOperationCast::ZeroExtend,
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

fn maskmovq(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let mask = operand_expr(machine, view.operands().first()?)?;
    let data = operand_expr(machine, view.operands().get(1)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.maskmovq".to_string(),
            args: vec![mask, data],
            outputs: vec![],
        }],
    ))
}

fn vperm2i128(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
    let imm = view.operands().get(3)?.immediate_value()? as u8;
    let select_half = |select: u8| match select & 0x3 {
        0 => extract_range(&left, 0, 128),
        1 => extract_range(&left, 128, 128),
        2 => extract_range(&right, 0, 128),
        _ => extract_range(&right, 128, 128),
    };
    let low = if (imm & 0x08) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half(imm)
    };
    let high = if (imm & 0x80) != 0 {
        common::const_u64(0, 128)
    } else {
        select_half((imm >> 4) & 0x3)
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

fn vpermq(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let imm = view.operands().get(2)?.immediate_value()? as u8;
    let mut parts = Vec::with_capacity(4);
    for lane in (0..4).rev() {
        let select = ((imm >> (lane * 2)) & 0x3) as u16;
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

fn vpbroadcastb(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
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

fn vpsignw(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().get(1)?)?;
    let right = operand_expr(machine, view.operands().get(2)?)?;
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
                    op: SemanticOperationUnary::Neg,
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

fn vmaskmov(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let mnemonic = view.mnemonic.as_str();
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    if view.operands().first()?.is_memory() {
        let mask = operand_expr(machine, view.operands().get(1)?)?;
        let data = operand_expr(machine, view.operands().get(2)?)?;
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Intrinsic {
                name: format!("x86.{mnemonic}"),
                args: vec![mask, data],
                outputs: vec![dst],
            }],
        ));
    }
    let mask = operand_expr(machine, view.operands().get(1)?)?;
    let src = operand_expr(machine, view.operands().get(2)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Intrinsic {
                name: format!("x86.{mnemonic}"),
                args: vec![mask, src],
                bits,
            },
        }],
    ))
}

fn vzeroupper() -> Semantic {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.vzeroupper".to_string(),
            args: Vec::new(),
            outputs: Vec::new(),
        }],
    )
}

fn packed_shift(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().first()?)?;
    let count = operand_expr(machine, view.operands().get(1)?)?;
    let bits = common::location_bits(&dst);
    let expression = match view.mnemonic.as_str() {
        "pslldq" => shift_bytes(src, count, bits, true),
        "psrldq" => shift_bytes(src, count, bits, false),
        "psllw" | "pslld" | "psllq" | "psrlw" | "psrld" | "psrlq" | "psraw" | "psrad" => {
            packed_lane_shift(view.mnemonic.as_str(), bits, &src, count)?
        }
        _ => return None,
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn avx_packed_shift(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let count = operand_expr(machine, view.operands().get(2)?)?;
    let bits = common::location_bits(&dst);
    let expression = match view.mnemonic.as_str() {
        "vpslldq" => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shift_bytes(extract_range(&src, 128, 128), count.clone(), 128, true),
                        shift_bytes(extract_range(&src, 0, 128), count, 128, true),
                    ],
                    bits,
                }
            } else {
                shift_bytes(src, count, bits, true)
            }
        }
        "vpsrldq" => {
            if bits == 256 {
                SemanticExpression::Concat {
                    parts: vec![
                        shift_bytes(extract_range(&src, 128, 128), count.clone(), 128, false),
                        shift_bytes(extract_range(&src, 0, 128), count, 128, false),
                    ],
                    bits,
                }
            } else {
                shift_bytes(src, count, bits, false)
            }
        }
        "vpsllq" | "vpsrlq" => packed_lane_shift(view.mnemonic.as_str(), bits, &src, count)?,
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
    mnemonic: &str,
    bits: u16,
    src: &SemanticExpression,
    count: SemanticExpression,
) -> Option<SemanticExpression> {
    let (lane_bits, op) = match mnemonic {
        "psllw" => (16, SemanticOperationBinary::Shl),
        "pslld" => (32, SemanticOperationBinary::Shl),
        "psllq" | "vpsllq" => (64, SemanticOperationBinary::Shl),
        "psrlw" => (16, SemanticOperationBinary::LShr),
        "psrld" => (32, SemanticOperationBinary::LShr),
        "psrlq" | "vpsrlq" => (64, SemanticOperationBinary::LShr),
        "psraw" => (16, SemanticOperationBinary::AShr),
        "psrad" => (32, SemanticOperationBinary::AShr),
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

fn ptest(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
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

fn avx_ptest(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
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

fn palignr(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let count = operand_expr(machine, view.operands().get(2)?)?;
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

fn extract_lane(
    vector: &SemanticExpression,
    lane_bits: u16,
    lane_index: u16,
) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(vector.clone()),
        lsb: lane_index * lane_bits,
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

fn horizontal_pair_result(
    vector: &SemanticExpression,
    lane_bits: u16,
    first_lane: u16,
    op: SemanticOperationBinary,
    saturating: bool,
) -> SemanticExpression {
    let left = extract_lane(vector, lane_bits, first_lane);
    let right = extract_lane(vector, lane_bits, first_lane + 1);
    if saturating {
        let ext_bits = lane_bits + 1;
        let lhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(left),
            bits: ext_bits,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(right),
            bits: ext_bits,
        };
        let result = SemanticExpression::Binary {
            op,
            left: Box::new(lhs),
            right: Box::new(rhs),
            bits: ext_bits,
        };
        saturate_lane(result, ext_bits, lane_bits, PackKind::Signed)
    } else {
        SemanticExpression::Binary {
            op,
            left: Box::new(left),
            right: Box::new(right),
            bits: lane_bits,
        }
    }
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

fn packed_mul_high_unsigned(
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
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(extract_lane(left, 16, lane)),
            bits: 32,
        };
        let rhs = SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
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

fn lane_mask(bits: u16) -> u128 {
    if bits as u32 >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

fn operand_expr(machine: Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(SemanticExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(SemanticExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticExpression::Load {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(machine: Architecture, operand: &X86OperandView) -> Option<SemanticLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    SemanticExpression::Read(Box::new(common::reg(
                        name,
                        common::pointer_bits(machine),
                    ))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(SemanticLocation::Memory {
                space: SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}
