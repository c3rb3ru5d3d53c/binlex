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
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare, SemanticTerminator,
};

#[path = "fp/x87.rs"]
mod x87_helpers;

use x87_helpers::x87;
pub(crate) fn build(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    match view.mnemonic.as_str() {
        "movsd" => movsd(machine, view),
        "vmovsd" => vmovsd(machine, view),
        "addsd" | "mulsd" | "divsd" | "subsd" | "minsd" | "maxsd" | "sqrtsd" => {
            scalar_fp(machine, view)
        }
        "comisd" | "ucomisd" | "comiss" | "ucomiss" | "vcomisd" | "vcomiss" | "vucomisd"
        | "vucomiss" => compare_fp(machine, view),
        "cvttsd2si" | "cvtsd2si" | "cvtss2si" | "cvttss2si" => scalar_convert(machine, view),
        "cvtdq2pd" | "cvtdq2ps" | "cvtpd2dq" | "cvtpd2ps" | "cvtpi2pd" | "cvtpi2ps"
        | "cvtps2dq" | "cvtps2pd" | "cvtsd2ss" | "cvtsi2sd" | "cvtsi2ss" | "cvtss2sd"
        | "cvttpd2dq" | "cvttps2dq" => packed_convert(machine, view),
        "addsubpd" | "addsubps" | "addpd" | "addps" | "divpd" | "divps" | "haddpd" | "mulpd"
        | "mulps" | "subpd" | "subps" | "haddps" | "sqrtpd" | "maxps" | "minps" | "shufpd"
        | "shufps" | "vaddsubpd" | "vaddsubps" | "vhaddpd" | "vhaddps" => packed_fp(machine, view),
        mnemonic
            if matches!(
                mnemonic,
                "addss"
                    | "subss"
                    | "divss"
                    | "mulss"
                    | "sqrtss"
                    | "maxss"
                    | "minss"
                    | "cmpss"
                    | "vcmpss"
            ) || mnemonic.ends_with("ss")
                && (mnemonic.starts_with("cmp") || mnemonic.starts_with("vcmp")) =>
        {
            scalar_ss(machine, view)
        }
        "vfmaddsd" | "vfmsubsd" => scalar_vfma(machine, view),
        "pcmpistri" => pcmpistri(machine, view),
        mnemonic
            if matches!(
                mnemonic,
                "fld"
                    | "fst"
                    | "fstp"
                    | "fist"
                    | "fistp"
                    | "fisttp"
                    | "fbld"
                    | "fbstp"
                    | "fild"
                    | "fldz"
                    | "fld1"
                    | "fldl2e"
                    | "fldl2t"
                    | "fldlg2"
                    | "fldln2"
                    | "fldpi"
                    | "fadd"
                    | "faddp"
                    | "fiadd"
                    | "fimul"
                    | "fmul"
                    | "fmulp"
                    | "fdiv"
                    | "fdivp"
                    | "fdivr"
                    | "fdivrp"
                    | "fidiv"
                    | "fidivr"
                    | "fsub"
                    | "fsubp"
                    | "fsubr"
                    | "fsubrp"
                    | "fisub"
                    | "fisubr"
                    | "fcomp"
                    | "fcom"
                    | "fcomi"
                    | "fcompi"
                    | "fcomip"
                    | "fcompp"
                    | "fucom"
                    | "fucomi"
                    | "fucompi"
                    | "fucomip"
                    | "fucomp"
                    | "fucompp"
                    | "fnstsw"
                    | "fninit"
                    | "fabs"
                    | "fchs"
                    | "fxch"
                    | "fnop"
                    | "ffree"
                    | "ffreep"
                    | "fnclex"
                    | "fcos"
                    | "fsin"
                    | "fsincos"
                    | "fscale"
                    | "fprem"
                    | "fprem1"
                    | "f2xm1"
                    | "fptan"
                    | "fpatan"
                    | "fsqrt"
                    | "fdecstp"
                    | "fincstp"
                    | "fxam"
                    | "ftst"
                    | "frndint"
                    | "fyl2x"
                    | "fyl2xp1"
            ) || mnemonic.starts_with("fcmov") =>
        {
            x87(machine, view)
        }
        _ => None,
    }
}

fn movsd(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_bits = common::location_bits(&dst);
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let expression = if dst_bits > 64 {
        let upper = operand_expr(machine, view.operands().first()?).map(|current| {
            SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
            }
        })?;
        let lower = SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: 64,
        };
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Extract {
            arg: Box::new(src),
            lsb: 0,
            bits: dst_bits,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn vmovsd(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    if view.operands().len() == 2 {
        return movsd(machine, view);
    }
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_bits = common::location_bits(&dst);
    let upper_src = operand_expr(machine, view.operands().get(1)?)?;
    let low_src = operand_expr(machine, view.operands().get(2)?)?;
    let expression = if dst_bits > 64 {
        SemanticExpression::Concat {
            parts: vec![
                SemanticExpression::Extract {
                    arg: Box::new(upper_src),
                    lsb: 64,
                    bits: dst_bits - 64,
                },
                SemanticExpression::Extract {
                    arg: Box::new(low_src),
                    lsb: 0,
                    bits: 64,
                },
            ],
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Extract {
            arg: Box::new(low_src),
            lsb: 0,
            bits: dst_bits,
        }
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn compare_fp(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let left = operand_expr(machine, view.operands().first()?)?;
    let right = operand_expr(machine, view.operands().get(1)?)?;
    let (left, right) = match view.mnemonic.as_str() {
        "comiss" | "ucomiss" | "vcomiss" | "vucomiss" => (low_32(left), low_32(right)),
        _ => (low_64(left), low_64(right)),
    };
    let unordered = common::compare(
        SemanticOperationCompare::Unordered,
        left.clone(),
        right.clone(),
    );
    let equal = common::compare(SemanticOperationCompare::Oeq, left.clone(), right.clone());
    let less = common::compare(SemanticOperationCompare::Olt, left.clone(), right.clone());
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::or(equal, unordered.clone(), 1),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: unordered.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::or(less, unordered, 1),
            },
        ],
    ))
}

fn pcmpistri(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let args = view
        .operands()
        .iter()
        .filter_map(|operand| operand_expr(machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.pcmpistri".to_string(),
            args,
            outputs: vec![
                common::reg("ecx", 32),
                common::flag("cf"),
                common::flag("of"),
                common::flag("sf"),
                common::flag("zf"),
                common::flag("af"),
                common::flag("pf"),
            ],
        }],
    ))
}

fn scalar_convert(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let bits = common::location_bits(&dst);
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let expression = match view.mnemonic.as_str() {
        "cvttsd2si" => SemanticExpression::Cast {
            op: SemanticOperationCast::FloatToInt,
            arg: Box::new(low_64(src)),
            bits,
        },
        _ => operation_intrinsic(view, bits, vec![src]),
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn packed_convert(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let src = operand_expr(machine, view.operands().get(1)?)?;
    let dst_bits = common::location_bits(&dst);
    let expression = match view.mnemonic.as_str() {
        "cvtdq2pd" => {
            let lane0 = SemanticExpression::Cast {
                op: SemanticOperationCast::IntToFloat,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src.clone()),
                    lsb: 0,
                    bits: 32,
                }),
                bits: 64,
            };
            let lane1 = SemanticExpression::Cast {
                op: SemanticOperationCast::IntToFloat,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb: 32,
                    bits: 32,
                }),
                bits: 64,
            };
            SemanticExpression::Concat {
                parts: vec![lane1, lane0],
                bits: 128,
            }
        }
        _ => operation_intrinsic(view, dst_bits, vec![src]),
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn scalar_fp(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let args = view
        .operands()
        .iter()
        .filter_map(|operand| operand_expr(machine, operand))
        .collect::<Vec<_>>();
    let dst_bits = common::location_bits(&dst);
    let lower = match view.mnemonic.as_str() {
        "addsd" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FAdd,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        "subsd" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FSub,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        "mulsd" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FMul,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        "divsd" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FDiv,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        "sqrtsd" => operation_intrinsic(view, 64, vec![low_64(args.get(1)?.clone())]),
        "minsd" => {
            let left = low_64(args.first()?.clone());
            let right = low_64(args.get(1)?.clone());
            let unordered = common::compare(
                SemanticOperationCompare::Unordered,
                left.clone(),
                right.clone(),
            );
            let left_is_min =
                common::compare(SemanticOperationCompare::Olt, left.clone(), right.clone());
            SemanticExpression::Select {
                condition: Box::new(unordered),
                when_true: Box::new(right.clone()),
                when_false: Box::new(SemanticExpression::Select {
                    condition: Box::new(left_is_min),
                    when_true: Box::new(left),
                    when_false: Box::new(right),
                    bits: 64,
                }),
                bits: 64,
            }
        }
        "maxsd" => operation_intrinsic(
            view,
            64,
            vec![low_64(args.first()?.clone()), low_64(args.get(1)?.clone())],
        ),
        _ => return None,
    };
    let expression = if dst_bits > 64 {
        let upper = operand_expr(machine, view.operands().first()?).map(|current| {
            SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
            }
        })?;
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        lower
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn packed_fp(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_bits = common::location_bits(&dst);
    let args = view
        .operands()
        .iter()
        .filter_map(|operand| operand_expr(machine, operand))
        .collect::<Vec<_>>();
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: operation_intrinsic(view, dst_bits, args),
        }],
    ))
}

fn scalar_ss(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_bits = common::location_bits(&dst);
    let args = view
        .operands()
        .iter()
        .filter_map(|operand| operand_expr(machine, operand))
        .collect::<Vec<_>>();
    let lower = match view.mnemonic.as_str() {
        "addss" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FAdd,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        "subss" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FSub,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        "mulss" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FMul,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        "divss" => SemanticExpression::Binary {
            op: SemanticOperationBinary::FDiv,
            left: Box::new(low_32(args.first()?.clone())),
            right: Box::new(low_32(args.get(1)?.clone())),
            bits: 32,
        },
        _ => operation_intrinsic(view, 32, args),
    };
    let expression = if dst_bits > 32 {
        let upper = operand_expr(machine, view.operands().first()?).map(|current| {
            SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 32,
                bits: dst_bits - 32,
            }
        })?;
        SemanticExpression::Concat {
            parts: vec![upper, lower],
            bits: dst_bits,
        }
    } else {
        lower
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn scalar_vfma(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let dst = operand_location(machine, view.operands().first()?)?;
    let dst_bits = common::location_bits(&dst);
    let src1 = operand_expr(machine, view.operands().get(1)?)?;
    let src2 = operand_expr(machine, view.operands().get(2)?)?;
    let src3 = operand_expr(machine, view.operands().get(3)?)?;
    let lower = operation_intrinsic(
        view,
        64,
        vec![low_64(src1.clone()), low_64(src2), low_64(src3)],
    );
    let expression = if dst_bits > 64 {
        let preserved = SemanticExpression::Extract {
            arg: Box::new(src1),
            lsb: 64,
            bits: dst_bits - 64,
        };
        SemanticExpression::Concat {
            parts: vec![preserved, lower],
            bits: dst_bits,
        }
    } else {
        lower
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn low_64(expression: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(expression),
        lsb: 0,
        bits: 64,
    }
}

fn low_32(expression: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(expression),
        lsb: 0,
        bits: 32,
    }
}

fn operation_intrinsic(
    view: &InstructionDetailX86,
    bits: u16,
    args: Vec<SemanticExpression>,
) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!("x86.{}", view.mnemonic_lower()),
        args,
        bits,
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
