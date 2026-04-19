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
    InstructionSemantics, SemanticAddressSpace, SemanticEffect, SemanticExpression,
    SemanticLocation, SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticTerminator,
};
use capstone::Insn;
use capstone::InsnId;
use capstone::arch::ArchOperand;
use capstone::arch::x86::{X86Insn, X86OperandType, X86Reg};

use super::common;

pub fn build(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    if matches!(
        mnemonic,
        "fld"
            | "fst"
            | "fstp"
            | "fild"
            | "fldz"
            | "fld1"
            | "fadd"
            | "faddp"
            | "fmul"
            | "fmulp"
            | "fdiv"
            | "fdivr"
            | "fdivrp"
            | "fsub"
            | "fsubp"
            | "fsubr"
            | "fsubrp"
            | "fcomp"
            | "fcom"
            | "fcompp"
            | "fucom"
            | "fucomp"
            | "fnstsw"
            | "fabs"
            | "fchs"
            | "fxch"
    ) {
        return x87(machine, instruction, operands);
    }

    match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_MOVSD as u32 => movsd(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_VMOVSD as u32 => vmovsd(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_MINSD as u32 => {
            scalar_fp(machine, instruction, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_FIMUL as u32 => x87(machine, instruction, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_COMISD as u32,
                X86Insn::X86_INS_UCOMISD as u32,
            ]
            .contains(&id) =>
        {
            compare_sd(machine, operands)
        }
        InsnId(id) if id == X86Insn::X86_INS_CVTTSD2SI as u32 => scalar_convert(machine, operands),
        InsnId(id) if id == X86Insn::X86_INS_CVTDQ2PD as u32 => packed_convert(machine, operands),
        InsnId(id)
            if [
                X86Insn::X86_INS_ADDSD as u32,
                X86Insn::X86_INS_MULSD as u32,
                X86Insn::X86_INS_DIVSD as u32,
                X86Insn::X86_INS_SUBSD as u32,
            ]
            .contains(&id) =>
        {
            scalar_fp(machine, instruction, operands)
        }
        _ => None,
    }
}

fn movsd(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let expression = if dst_bits > 64 {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
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

fn vmovsd(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    if operands.len() == 2 {
        return movsd(machine, operands);
    }
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_bits = common::location_bits(&dst);
    let upper_src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let low_src = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
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

const X87_BITS: u16 = 80;

fn x87(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let mnemonic = instruction.mnemonic().unwrap_or_default();
    let effects = match mnemonic {
        "fld1" => x87_push_effects(x87_const("one")),
        "fldz" => x87_push_effects(x87_const("zero")),
        "fld" => x87_push_effects(x87_float_operand(machine, operands.first()?)?),
        "fild" => x87_push_effects(x87_int_operand(machine, operands.first()?)?),
        "fst" => x87_store_only(machine, operands.first()?, x87_stack_expr(0))?,
        "fstp" => x87_store_pop(machine, operands.first()?, x87_stack_expr(0))?,
        "fabs" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("abs", vec![x87_stack_expr(0)]),
        }],
        "fchs" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("neg", vec![x87_stack_expr(0)]),
        }],
        "fxch" => x87_exchange(operands)?,
        "fnstsw" => vec![SemanticEffect::Set {
            dst: common::operand_location(machine, operands.first()?)?,
            expression: x87_status_word(),
        }],
        "fadd" => x87_binary(machine, operands, "add", BinaryOrder::Normal)?,
        "faddp" => x87_binary_pop(operands, "add", BinaryPopOrder::TargetOpSt0)?,
        "fmul" => x87_binary(machine, operands, "mul", BinaryOrder::Normal)?,
        "fmulp" => x87_binary_pop(operands, "mul", BinaryPopOrder::TargetOpSt0)?,
        "fsub" => x87_binary(machine, operands, "sub", BinaryOrder::Normal)?,
        "fsubr" => x87_binary(machine, operands, "sub", BinaryOrder::Reverse)?,
        "fsubp" => x87_binary_pop(operands, "sub", BinaryPopOrder::TargetOpSt0)?,
        "fsubrp" => x87_binary_pop(operands, "sub", BinaryPopOrder::St0OpTarget)?,
        "fdiv" => x87_binary(machine, operands, "div", BinaryOrder::Normal)?,
        "fdivr" => x87_binary(machine, operands, "div", BinaryOrder::Reverse)?,
        "fdivrp" => x87_binary_pop(operands, "div", BinaryPopOrder::TargetOpSt0)?,
        "fcom" | "fucom" => x87_compare_effects(x87_compare_rhs(machine, operands)?, 0),
        "fcomp" | "fucomp" => x87_compare_effects(x87_compare_rhs(machine, operands)?, 1),
        "fcompp" => x87_compare_effects(x87_stack_expr(1), 2),
        "fimul" => {
            let rhs = x87_int_operand(machine, operands.first()?)?;
            vec![SemanticEffect::Set {
                dst: x87_stack_location(0),
                expression: x87_expr_intrinsic("mul", vec![x87_stack_expr(0), rhs]),
            }]
        }
        _ => return None,
    };
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

#[derive(Clone, Copy)]
enum BinaryOrder {
    Normal,
    Reverse,
}

#[derive(Clone, Copy)]
enum BinaryPopOrder {
    TargetOpSt0,
    St0OpTarget,
}

fn x87_binary(
    machine: Architecture,
    operands: &[ArchOperand],
    op: &str,
    order: BinaryOrder,
) -> Option<Vec<SemanticEffect>> {
    let (dst_index, rhs) = if operands.len() >= 2 {
        (
            x87_stack_index(operands.first()?)?,
            x87_stack_expr(x87_stack_index(operands.get(1)?)?),
        )
    } else {
        (0, x87_float_operand(machine, operands.first()?)?)
    };
    let lhs = x87_stack_expr(dst_index);
    let result = match order {
        BinaryOrder::Normal => x87_expr_intrinsic(op, vec![lhs, rhs]),
        BinaryOrder::Reverse => x87_expr_intrinsic(op, vec![rhs, lhs]),
    };
    Some(vec![SemanticEffect::Set {
        dst: x87_stack_location(dst_index),
        expression: result,
    }])
}

fn x87_binary_pop(
    operands: &[ArchOperand],
    op: &str,
    order: BinaryPopOrder,
) -> Option<Vec<SemanticEffect>> {
    let target_index = if operands.is_empty() {
        1
    } else {
        x87_stack_index(operands.first()?)?
    };
    let target = x87_stack_expr(target_index);
    let st0 = x87_stack_expr(0);
    let result = match order {
        BinaryPopOrder::TargetOpSt0 => x87_expr_intrinsic(op, vec![target, st0]),
        BinaryPopOrder::St0OpTarget => x87_expr_intrinsic(op, vec![st0, target]),
    };
    Some(x87_pop_with_replacement(target_index, result))
}

fn x87_compare_rhs(machine: Architecture, operands: &[ArchOperand]) -> Option<SemanticExpression> {
    if operands.is_empty() {
        return Some(x87_stack_expr(1));
    }
    let operand = operands.first()?;
    if let Some(index) = x87_stack_index(operand) {
        Some(x87_stack_expr(index))
    } else {
        x87_float_operand(machine, operand)
    }
}

fn x87_compare_effects(rhs: SemanticExpression, pop_count: u8) -> Vec<SemanticEffect> {
    let lhs = x87_stack_expr(0);
    let unordered = common::compare(
        SemanticOperationCompare::Unordered,
        lhs.clone(),
        rhs.clone(),
    );
    let equal = common::compare(SemanticOperationCompare::Oeq, lhs.clone(), rhs.clone());
    let less = common::compare(SemanticOperationCompare::Olt, lhs, rhs);
    let mut effects = vec![
        SemanticEffect::Set {
            dst: x87_flag("c0"),
            expression: common::or(less, unordered.clone(), 1),
        },
        SemanticEffect::Set {
            dst: x87_flag("c1"),
            expression: common::bool_const(false),
        },
        SemanticEffect::Set {
            dst: x87_flag("c2"),
            expression: unordered.clone(),
        },
        SemanticEffect::Set {
            dst: x87_flag("c3"),
            expression: common::or(equal, unordered, 1),
        },
    ];
    effects.extend(x87_pop_effects(pop_count));
    effects
}

fn x87_store_only(
    machine: Architecture,
    operand: &ArchOperand,
    value: SemanticExpression,
) -> Option<Vec<SemanticEffect>> {
    Some(vec![x87_store_effect(machine, operand, value)?])
}

fn x87_store_pop(
    machine: Architecture,
    operand: &ArchOperand,
    value: SemanticExpression,
) -> Option<Vec<SemanticEffect>> {
    if let Some(index) = x87_stack_index(operand) {
        return Some(x87_pop_with_replacement(index, value));
    }
    let mut effects = vec![x87_store_effect(machine, operand, value)?];
    effects.extend(x87_pop_effects(1));
    Some(effects)
}

fn x87_store_effect(
    machine: Architecture,
    operand: &ArchOperand,
    value: SemanticExpression,
) -> Option<SemanticEffect> {
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    match op.op_type {
        X86OperandType::Reg(_) => Some(SemanticEffect::Set {
            dst: x87_stack_location(x87_stack_index(operand)?),
            expression: value,
        }),
        _ => {
            let addr = x87_memory_addr(machine, operand)?;
            let bits = common::bits_from_operand_size(op.size, machine);
            Some(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: x87_store_bits(value, bits),
                bits,
            })
        }
    }
}

fn x87_exchange(operands: &[ArchOperand]) -> Option<Vec<SemanticEffect>> {
    let index = if operands.is_empty() {
        1
    } else {
        x87_stack_index(operands.first()?)?
    };
    Some(vec![
        SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_stack_expr(index),
        },
        SemanticEffect::Set {
            dst: x87_stack_location(index),
            expression: x87_stack_expr(0),
        },
    ])
}

fn x87_push_effects(value: SemanticExpression) -> Vec<SemanticEffect> {
    let mut effects = Vec::new();
    for index in (1..8).rev() {
        effects.push(SemanticEffect::Set {
            dst: x87_stack_location(index),
            expression: x87_stack_expr(index - 1),
        });
    }
    effects.push(SemanticEffect::Set {
        dst: x87_stack_location(0),
        expression: value,
    });
    effects.push(SemanticEffect::Set {
        dst: x87_top_location(),
        expression: common::sub(x87_top_expr(), common::const_u64(1, 3), 3),
    });
    effects
}

fn x87_pop_effects(count: u8) -> Vec<SemanticEffect> {
    if count == 0 {
        return Vec::new();
    }
    let mut effects = Vec::new();
    for index in 0..8 {
        let src = index + count as usize;
        let expression = if src < 8 {
            x87_stack_expr(src as u8)
        } else {
            SemanticExpression::Undefined { bits: X87_BITS }
        };
        effects.push(SemanticEffect::Set {
            dst: x87_stack_location(index as u8),
            expression,
        });
    }
    effects.push(SemanticEffect::Set {
        dst: x87_top_location(),
        expression: common::add(x87_top_expr(), common::const_u64(count as u64, 3), 3),
    });
    effects
}

fn x87_pop_with_replacement(
    target_index: u8,
    replacement: SemanticExpression,
) -> Vec<SemanticEffect> {
    let mut effects = Vec::new();
    for index in 0..8u8 {
        let expression = match index {
            i if i + 1 < target_index => x87_stack_expr(i + 1),
            i if i + 1 == target_index => replacement.clone(),
            i => {
                let src = i + 1;
                if src < 8 {
                    x87_stack_expr(src)
                } else {
                    SemanticExpression::Undefined { bits: X87_BITS }
                }
            }
        };
        effects.push(SemanticEffect::Set {
            dst: x87_stack_location(index),
            expression,
        });
    }
    effects.push(SemanticEffect::Set {
        dst: x87_top_location(),
        expression: common::add(x87_top_expr(), common::const_u64(1, 3), 3),
    });
    effects
}

fn x87_float_operand(machine: Architecture, operand: &ArchOperand) -> Option<SemanticExpression> {
    if let Some(index) = x87_stack_index(operand) {
        return Some(x87_stack_expr(index));
    }
    let raw = common::operand_expr(machine, operand)?;
    let bits = x87_operand_bits(machine, operand)?;
    Some(match bits {
        32 => x87_expr_intrinsic("load_f32", vec![raw]),
        64 => x87_expr_intrinsic("load_f64", vec![raw]),
        80 => raw,
        _ => return None,
    })
}

fn x87_int_operand(machine: Architecture, operand: &ArchOperand) -> Option<SemanticExpression> {
    let raw = common::operand_expr(machine, operand)?;
    let bits = x87_operand_bits(machine, operand)?;
    Some(match bits {
        16 => x87_expr_intrinsic("load_i16", vec![raw]),
        32 => x87_expr_intrinsic("load_i32", vec![raw]),
        64 => x87_expr_intrinsic("load_i64", vec![raw]),
        _ => return None,
    })
}

fn x87_store_bits(value: SemanticExpression, bits: u16) -> SemanticExpression {
    match bits {
        32 => x87_expr_intrinsic("store_f32", vec![value]),
        64 => x87_expr_intrinsic("store_f64", vec![value]),
        80 => value,
        _ => SemanticExpression::Undefined { bits },
    }
}

fn x87_memory_addr(machine: Architecture, operand: &ArchOperand) -> Option<SemanticExpression> {
    let location = common::operand_location(machine, operand)?;
    match location {
        SemanticLocation::Memory { addr, .. } => Some(*addr),
        _ => None,
    }
}

fn x87_operand_bits(machine: Architecture, operand: &ArchOperand) -> Option<u16> {
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    Some(common::bits_from_operand_size(op.size, machine))
}

fn x87_stack_index(operand: &ArchOperand) -> Option<u8> {
    let ArchOperand::X86Operand(op) = operand else {
        return None;
    };
    let X86OperandType::Reg(reg) = op.op_type else {
        return None;
    };
    Some(match reg {
        reg if reg == X86Reg::X86_REG_ST0.into() => 0,
        reg if reg == X86Reg::X86_REG_ST1.into() => 1,
        reg if reg == X86Reg::X86_REG_ST2.into() => 2,
        reg if reg == X86Reg::X86_REG_ST3.into() => 3,
        reg if reg == X86Reg::X86_REG_ST4.into() => 4,
        reg if reg == X86Reg::X86_REG_ST5.into() => 5,
        reg if reg == X86Reg::X86_REG_ST6.into() => 6,
        reg if reg == X86Reg::X86_REG_ST7.into() => 7,
        _ => return None,
    })
}

fn x87_stack_location(index: u8) -> SemanticLocation {
    common::reg(format!("x87_st{index}"), X87_BITS)
}

fn x87_stack_expr(index: u8) -> SemanticExpression {
    SemanticExpression::Read(Box::new(x87_stack_location(index)))
}

fn x87_top_location() -> SemanticLocation {
    common::reg("x87_top", 3)
}

fn x87_top_expr() -> SemanticExpression {
    SemanticExpression::Read(Box::new(x87_top_location()))
}

fn x87_flag(name: &str) -> SemanticLocation {
    common::flag(&format!("x87_{name}"))
}

fn x87_const(name: &str) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!("x86.x87.const_{name}"),
        args: Vec::new(),
        bits: X87_BITS,
    }
}

fn x87_expr_intrinsic(name: &str, args: Vec<SemanticExpression>) -> SemanticExpression {
    SemanticExpression::Intrinsic {
        name: format!("x86.x87.{name}"),
        args,
        bits: X87_BITS,
    }
}

fn x87_status_word() -> SemanticExpression {
    let top_bits = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(x87_top_expr()),
        bits: 16,
    };
    let top_shifted = SemanticExpression::Binary {
        op: SemanticOperationBinary::Shl,
        left: Box::new(top_bits),
        right: Box::new(common::const_u64(11, 16)),
        bits: 16,
    };
    let mut word = common::const_u64(0, 16);
    for (name, bit) in [("c0", 8), ("c1", 9), ("c2", 10), ("c3", 14)] {
        let shifted = SemanticExpression::Binary {
            op: SemanticOperationBinary::Shl,
            left: Box::new(SemanticExpression::Cast {
                op: SemanticOperationCast::ZeroExtend,
                arg: Box::new(SemanticExpression::Read(Box::new(x87_flag(name)))),
                bits: 16,
            }),
            right: Box::new(common::const_u64(bit, 16)),
            bits: 16,
        };
        word = common::or(word, shifted, 16);
    }
    common::or(word, top_shifted, 16)
}

fn compare_sd(_machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(_machine, operand))
        .map(low_64)?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(_machine, operand))
        .map(low_64)?;
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

fn scalar_convert(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))
        .map(low_64)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::FloatToInt,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn packed_convert(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
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
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Concat {
                parts: vec![lane1, lane0],
                bits: 128,
            },
        }],
    ))
}

fn scalar_fp(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let args = operands
        .iter()
        .filter_map(|operand| common::operand_expr(machine, operand))
        .collect::<Vec<_>>();
    let dst_bits = common::location_bits(&dst);
    let lower = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_ADDSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FAdd,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_SUBSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FSub,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_MULSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FMul,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_DIVSD as u32 => SemanticExpression::Binary {
            op: SemanticOperationBinary::FDiv,
            left: Box::new(low_64(args.first()?.clone())),
            right: Box::new(low_64(args.get(1)?.clone())),
            bits: 64,
        },
        InsnId(id) if id == X86Insn::X86_INS_MINSD as u32 => {
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
        _ => return None,
    };
    let expression = if dst_bits > 64 {
        let upper = operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))
            .map(|current| SemanticExpression::Extract {
                arg: Box::new(current),
                lsb: 64,
                bits: dst_bits - 64,
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

fn low_64(expression: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        arg: Box::new(expression),
        lsb: 0,
        bits: 64,
    }
}
