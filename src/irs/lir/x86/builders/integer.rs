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
use crate::irs::lir::x86::InstructionDetailX86;
use crate::irs::lir::x86::helpers as common;
use crate::irs::lir::x86::{X86OperandKind, X86OperandView};
use crate::irs::lir::{
    Lir, LirAddressSpace, LirEffect, LirExpression, LirLocation, LirOperationBinary,
    LirOperationCast, LirOperationCompare, LirOperationUnary, LirStatus, LirTemporary,
    LirTerminator,
};

pub(crate) fn build(machine: Architecture, view: &InstructionDetailX86) -> Option<Lir> {
    match view.mnemonic.as_str() {
        "nop" => Some(common::complete(
            LirTerminator::FallThrough,
            vec![LirEffect::Nop],
        )),
        "mov" | "movabs" => assign(machine, view.operands()),
        "movbe" => movbe(machine, view.operands()),
        "movzx" => movx(machine, view.operands(), false),
        "movsx" | "movsxd" => movx(machine, view.operands(), true),
        "lea" => lea(machine, view.operands()),
        "xchg" => exchange(machine, view.operands()),
        "xadd" => exchange_add(machine, view.operands()),
        "cmpxchg" => compare_exchange(machine, view.operands()),
        "lock cmpxchg8b" => lock_cmpxchg8b(machine, view.operands()),
        "cmpxchg16b" | "lock cmpxchg16b" => lock_cmpxchg16b(machine, view.operands()),
        "aaa" | "aas" | "aad" | "aam" | "daa" => ascii_adjust(machine, view),
        "cbw" | "cwde" | "cdqe" | "cwd" | "cdq" | "cqo" => sign_extension(view),
        "add" => binary(machine, view.operands(), LirOperationBinary::Add),
        "sub" => binary(machine, view.operands(), LirOperationBinary::Sub),
        "adc" => adc(machine, view.operands()),
        "sbb" => sbb(machine, view.operands()),
        "adcx" => adcx_adox(machine, view.operands(), true),
        "adox" => adcx_adox(machine, view.operands(), false),
        "inc" => unary(machine, view.operands(), LirOperationBinary::Add),
        "dec" => unary(machine, view.operands(), LirOperationBinary::Sub),
        "neg" => unary_op(machine, view.operands(), LirOperationUnary::Neg, true),
        "not" => unary_op(machine, view.operands(), LirOperationUnary::Not, false),
        "bswap" => unary_op(machine, view.operands(), LirOperationUnary::ByteSwap, false),
        "popcnt" => popcnt(machine, view.operands()),
        "crc32" => crc32(machine, view.operands()),
        "cmp" => cmp_like(machine, view.operands()),
        "xlatb" => xlat(machine),
        "imul" => imul(machine, view.operands()),
        "mul" => mul(machine, view.operands()),
        "mulx" => mulx(machine, view.operands()),
        "div" => div(machine, view.operands(), false),
        "idiv" => div(machine, view.operands(), true),
        _ => None,
    }
}

fn ascii_adjust(machine: Architecture, view: &InstructionDetailX86) -> Option<Lir> {
    let al_reg = common::reg("al", 8);
    let ah_reg = common::reg("ah", 8);
    let al = LirExpression::Read(Box::new(al_reg.clone()));
    let ah = LirExpression::Read(Box::new(ah_reg.clone()));

    match view.mnemonic.as_str() {
        "aaa" | "aas" => {
            let low_nibble = LirExpression::Extract {
                arg: Box::new(al.clone()),
                lsb: 0,
                bits: 4,
            };
            let decimal_adjust = common::or(
                common::compare(
                    LirOperationCompare::Ugt,
                    low_nibble,
                    LirExpression::Const { value: 9, bits: 4 },
                ),
                common::flag_expr("af"),
                1,
            );
            let adjusted_al = if view.mnemonic == "aaa" {
                common::add(al.clone(), common::const_u64(6, 8), 8)
            } else {
                common::sub(al.clone(), common::const_u64(6, 8), 8)
            };
            let adjusted_ah = if view.mnemonic == "aaa" {
                common::add(ah.clone(), common::const_u64(1, 8), 8)
            } else {
                common::sub(ah.clone(), common::const_u64(1, 8), 8)
            };
            let masked_al = common::and(adjusted_al, common::const_u64(0x0f, 8), 8);
            return Some(common::complete(
                LirTerminator::FallThrough,
                vec![
                    LirEffect::Set {
                        dst: al_reg,
                        expression: LirExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(masked_al),
                            when_false: Box::new(common::and(al, common::const_u64(0x0f, 8), 8)),
                            bits: 8,
                        },
                    },
                    LirEffect::Set {
                        dst: ah_reg,
                        expression: LirExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(adjusted_ah),
                            when_false: Box::new(ah),
                            bits: 8,
                        },
                    },
                    LirEffect::Set {
                        dst: common::flag("af"),
                        expression: decimal_adjust.clone(),
                    },
                    LirEffect::Set {
                        dst: common::flag("cf"),
                        expression: decimal_adjust,
                    },
                    LirEffect::Set {
                        dst: common::flag("of"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                    LirEffect::Set {
                        dst: common::flag("sf"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                    LirEffect::Set {
                        dst: common::flag("zf"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                    LirEffect::Set {
                        dst: common::flag("pf"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        "aad" => {
            let base = view
                .operands()
                .first()
                .and_then(|operand| operand_expr(machine, operand))
                .unwrap_or_else(|| common::const_u64(10, 8));
            let ah_term = LirExpression::Binary {
                op: LirOperationBinary::Mul,
                left: Box::new(ah),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let result = common::add(ah_term, al, 8);
            return Some(common::complete(
                LirTerminator::FallThrough,
                vec![
                    LirEffect::Set {
                        dst: common::reg("al", 8),
                        expression: result.clone(),
                    },
                    LirEffect::Set {
                        dst: common::reg("ah", 8),
                        expression: common::const_u64(0, 8),
                    },
                    LirEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            LirOperationCompare::Eq,
                            result.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    LirEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(result.clone(), 7),
                    },
                    LirEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(result),
                    },
                    LirEffect::Set {
                        dst: common::flag("cf"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                    LirEffect::Set {
                        dst: common::flag("of"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                    LirEffect::Set {
                        dst: common::flag("af"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        "aam" => {
            let base = view
                .operands()
                .first()
                .and_then(|operand| operand_expr(machine, operand))
                .unwrap_or_else(|| common::const_u64(10, 8));
            let quotient = LirExpression::Binary {
                op: LirOperationBinary::UDiv,
                left: Box::new(al.clone()),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let remainder = LirExpression::Binary {
                op: LirOperationBinary::URem,
                left: Box::new(al),
                right: Box::new(base),
                bits: 8,
            };
            return Some(common::complete(
                LirTerminator::FallThrough,
                vec![
                    LirEffect::Set {
                        dst: common::reg("ah", 8),
                        expression: quotient,
                    },
                    LirEffect::Set {
                        dst: common::reg("al", 8),
                        expression: remainder.clone(),
                    },
                    LirEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            LirOperationCompare::Eq,
                            remainder.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    LirEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(remainder.clone(), 7),
                    },
                    LirEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(remainder),
                    },
                    LirEffect::Set {
                        dst: common::flag("cf"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                    LirEffect::Set {
                        dst: common::flag("of"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                    LirEffect::Set {
                        dst: common::flag("af"),
                        expression: LirExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        "daa" => {
            return Some(common::complete(
                LirTerminator::FallThrough,
                vec![LirEffect::Intrinsic {
                    name: "x86.daa".to_string(),
                    args: Vec::new(),
                    outputs: vec![
                        common::reg("al", 8),
                        common::flag("af"),
                        common::flag("cf"),
                        common::flag("of"),
                        common::flag("sf"),
                        common::flag("zf"),
                        common::flag("pf"),
                    ],
                }],
            ));
        }
        _ => {}
    }
    None
}

fn assign(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let expression = operand_expr(machine, operands.get(1)?)?;
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set { dst, expression }],
    ))
}

fn lea(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let mem = operands.get(1)?.memory_operand()?;
    let base = mem.base_register_name.map(|name| {
        LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
    });
    let index = mem.index_register_name.map(|name| {
        (
            LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
            mem.scale,
        )
    });
    let addr = common::memory_addr(machine, base, index, mem.displacement);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: addr,
        }],
    ))
}

fn movbe(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let expression = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    if !matches!(bits, 16 | 32 | 64) {
        return None;
    }
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Unary {
                op: LirOperationUnary::ByteSwap,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

fn movx(machine: Architecture, operands: &[X86OperandView], sign_extend: bool) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expr(machine, operands.get(1)?)?;
    let dst_bits = common::location_bits(&dst);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Cast {
                op: if sign_extend {
                    LirOperationCast::SignExtend
                } else {
                    LirOperationCast::ZeroExtend
                },
                arg: Box::new(src),
                bits: dst_bits,
            },
        }],
    ))
}

fn exchange(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let left_dst = operand_location(machine, operands.first()?)?;
    let right_dst = operand_location(machine, operands.get(1)?)?;
    let left_expr = operand_expr(machine, operands.first()?)?;
    let right_expr = operand_expr(machine, operands.get(1)?)?;
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: left_dst,
                expression: right_expr,
            },
            LirEffect::Set {
                dst: right_dst,
                expression: left_expr,
            },
        ],
    ))
}

fn exchange_add(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let src_dst = operand_location(machine, operands.get(1)?)?;
    let dst_expr = operand_expr(machine, operands.first()?)?;
    let src_expr = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let result = common::add(dst_expr.clone(), src_expr.clone(), bits);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: src_dst,
                expression: dst_expr.clone(),
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    LirOperationCompare::Ult,
                    result.clone(),
                    dst_expr.clone(),
                ),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    dst_expr.clone(),
                    src_expr.clone(),
                    result.clone(),
                    bits,
                ),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(dst_expr, src_expr, result, bits),
            },
        ],
    ))
}

fn compare_exchange(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expr(machine, operands.get(1)?)?;
    let observed = operand_expr(machine, operands.first()?)?;
    let bits = common::location_bits(&dst);
    let (acc_name, acc_bits) = match bits {
        8 => ("al", 8),
        16 => ("ax", 16),
        32 => ("eax", 32),
        64 => ("rax", 64),
        _ => return None,
    };
    let accumulator_location = common::reg(acc_name, acc_bits);
    let accumulator = LirExpression::Read(Box::new(accumulator_location.clone()));
    let equal = common::compare(
        LirOperationCompare::Eq,
        accumulator.clone(),
        observed.clone(),
    );
    let diff = common::sub(accumulator.clone(), observed.clone(), bits);
    let mut effects = vec![LirEffect::Set {
        dst: dst.clone(),
        expression: LirExpression::Select {
            condition: Box::new(equal.clone()),
            when_true: Box::new(src),
            when_false: Box::new(observed.clone()),
            bits,
        },
    }];
    if dst != accumulator_location {
        effects.push(LirEffect::Set {
            dst: accumulator_location,
            expression: LirExpression::Select {
                condition: Box::new(equal.clone()),
                when_true: Box::new(accumulator.clone()),
                when_false: Box::new(observed.clone()),
                bits,
            },
        });
    }
    effects.extend([
        LirEffect::Set {
            dst: common::flag("zf"),
            expression: equal.clone(),
        },
        LirEffect::Set {
            dst: common::flag("cf"),
            expression: common::compare(
                LirOperationCompare::Ult,
                accumulator.clone(),
                observed.clone(),
            ),
        },
        LirEffect::Set {
            dst: common::flag("sf"),
            expression: common::extract_bit(diff.clone(), bits.saturating_sub(1)),
        },
        LirEffect::Set {
            dst: common::flag("of"),
            expression: common::sub_overflow(
                accumulator.clone(),
                observed.clone(),
                diff.clone(),
                bits,
            ),
        },
        LirEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(diff.clone()),
        },
        LirEffect::Set {
            dst: common::flag("af"),
            expression: common::auxiliary_flag(accumulator, observed, diff, bits),
        },
    ]);
    Some(common::complete(LirTerminator::FallThrough, effects))
}

fn lock_cmpxchg8b(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = match dst {
        LirLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    if !matches!(machine, Architecture::I386 | Architecture::AMD64) {
        return None;
    }
    let eax = LirExpression::Read(Box::new(common::reg("eax", 32)));
    let edx = LirExpression::Read(Box::new(common::reg("edx", 32)));
    let ebx = LirExpression::Read(Box::new(common::reg("ebx", 32)));
    let ecx = LirExpression::Read(Box::new(common::reg("ecx", 32)));
    let accumulator = LirExpression::Concat {
        parts: vec![edx.clone(), eax.clone()],
        bits: 64,
    };
    let replacement = LirExpression::Concat {
        parts: vec![ecx, ebx],
        bits: 64,
    };
    let observed_tmp = LirLocation::Temporary { id: 0, bits: 64 };
    let observed_expr = LirExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        LirOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = LirExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 32,
    };
    let observed_high = LirExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 32,
        bits: 32,
    };
    Some(Lir {
        version: 1,
        status: LirStatus::Complete,
        metadata: Default::default(),
        abi: None,
        encoding: None,
        temporaries: vec![LirTemporary {
            id: 0,
            bits: 64,
            name: Some("lock_cmpxchg8b_observed".to_string()),
        }],
        effects: vec![
            LirEffect::AtomicCmpXchg {
                space: LirAddressSpace::Default,
                addr,
                expected: accumulator,
                desired: replacement,
                bits: 64,
                observed: observed_tmp,
            },
            LirEffect::Set {
                dst: common::reg("eax", 32),
                expression: LirExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(eax),
                    when_false: Box::new(observed_low),
                    bits: 32,
                },
            },
            LirEffect::Set {
                dst: common::reg("edx", 32),
                expression: LirExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(edx),
                    when_false: Box::new(observed_high),
                    bits: 32,
                },
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: LirTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn lock_cmpxchg16b(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = match dst {
        LirLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    if !matches!(machine, Architecture::AMD64) {
        return None;
    }
    let rax = LirExpression::Read(Box::new(common::reg("rax", 64)));
    let rdx = LirExpression::Read(Box::new(common::reg("rdx", 64)));
    let rbx = LirExpression::Read(Box::new(common::reg("rbx", 64)));
    let rcx = LirExpression::Read(Box::new(common::reg("rcx", 64)));
    let accumulator = LirExpression::Concat {
        parts: vec![rdx.clone(), rax.clone()],
        bits: 128,
    };
    let replacement = LirExpression::Concat {
        parts: vec![rcx, rbx],
        bits: 128,
    };
    let observed_tmp = LirLocation::Temporary { id: 1, bits: 128 };
    let observed_expr = LirExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        LirOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = LirExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 64,
    };
    let observed_high = LirExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 64,
        bits: 64,
    };
    Some(Lir {
        version: 1,
        status: LirStatus::Complete,
        metadata: Default::default(),
        abi: None,
        encoding: None,
        temporaries: vec![LirTemporary {
            id: 1,
            bits: 128,
            name: Some("lock_cmpxchg16b_observed".to_string()),
        }],
        effects: vec![
            LirEffect::AtomicCmpXchg {
                space: LirAddressSpace::Default,
                addr,
                expected: accumulator,
                desired: replacement,
                bits: 128,
                observed: observed_tmp,
            },
            LirEffect::Set {
                dst: common::reg("rax", 64),
                expression: LirExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rax),
                    when_false: Box::new(observed_low),
                    bits: 64,
                },
            },
            LirEffect::Set {
                dst: common::reg("rdx", 64),
                expression: LirExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rdx),
                    when_false: Box::new(observed_high),
                    bits: 64,
                },
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: LirTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn sign_extension(view: &InstructionDetailX86) -> Option<Lir> {
    let (src_name, src_bits, dst_name, dst_bits, high_only) = match view.mnemonic.as_str() {
        "cbw" => ("al", 8, "ax", 16, false),
        "cwde" => ("ax", 16, "eax", 32, false),
        "cdqe" => ("eax", 32, "rax", 64, false),
        "cwd" => ("ax", 16, "dx", 16, true),
        "cdq" => ("eax", 32, "edx", 32, true),
        "cqo" => ("rax", 64, "rdx", 64, true),
        _ => return None,
    };

    let src = LirExpression::Read(Box::new(common::reg(src_name, src_bits)));
    let expression = if high_only {
        LirExpression::Select {
            condition: Box::new(common::extract_bit(src, src_bits - 1)),
            when_true: Box::new(common::const_u64(u64::MAX, dst_bits)),
            when_false: Box::new(common::const_u64(0, dst_bits)),
            bits: dst_bits,
        }
    } else {
        LirExpression::Cast {
            op: LirOperationCast::SignExtend,
            arg: Box::new(src),
            bits: dst_bits,
        }
    };

    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst: common::reg(dst_name, dst_bits),
            expression,
        }],
    ))
}

fn binary(
    machine: Architecture,
    operands: &[X86OperandView],
    op: LirOperationBinary,
) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let result = LirExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let carry = if op == LirOperationBinary::Add {
        common::compare(LirOperationCompare::Ult, result.clone(), left.clone())
    } else {
        common::compare(LirOperationCompare::Ult, left.clone(), right.clone())
    };
    let overflow = if op == LirOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: carry,
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

fn popcnt(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let result = LirExpression::Unary {
        op: LirOperationUnary::PopCount,
        arg: Box::new(src.clone()),
        bits,
    };
    let src_is_zero = common::compare(LirOperationCompare::Eq, src, common::const_u64(0, bits));
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result,
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: src_is_zero,
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

fn crc32(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expr(machine, operands.get(1)?)?;
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Intrinsic {
            name: "x86.crc32".to_string(),
            args: vec![src],
            outputs: vec![dst],
        }],
    ))
}

fn xlat(machine: Architecture) -> Option<Lir> {
    let pointer_bits = common::pointer_bits(machine);
    let base_name = if matches!(machine, Architecture::AMD64) {
        "rbx"
    } else {
        "ebx"
    };
    let base = LirExpression::Read(Box::new(common::reg(base_name, pointer_bits)));
    let index = LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(LirExpression::Read(Box::new(common::reg("al", 8)))),
        bits: pointer_bits,
    };
    let addr = common::add(base, index, pointer_bits);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst: common::reg("al", 8),
            expression: LirExpression::Load {
                space: crate::irs::lir::LirAddressSpace::Default,
                addr: Box::new(addr),
                bits: 8,
            },
        }],
    ))
}

fn imul(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    match operands.len() {
        2 | 3 => imul_explicit(machine, operands),
        1 => imul_implicit(machine, operands),
        _ => None,
    }
}

fn imul_explicit(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = common::location_bits(&dst);
    let full_bits = bits.saturating_mul(2);
    let left = if operands.len() == 2 {
        operand_expr(machine, operands.first()?)?
    } else {
        operand_expr(machine, operands.get(1)?)?
    };
    let right = operand_expr(machine, operands.last()?)?;
    let wide_product = LirExpression::Binary {
        op: LirOperationBinary::Mul,
        left: Box::new(LirExpression::Cast {
            op: LirOperationCast::SignExtend,
            arg: Box::new(left),
            bits: full_bits,
        }),
        right: Box::new(LirExpression::Cast {
            op: LirOperationCast::SignExtend,
            arg: Box::new(right),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let low = LirExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits,
    };
    let high = LirExpression::Extract {
        arg: Box::new(wide_product),
        lsb: bits,
        bits,
    };
    let sign_fill = signed_extension_fill(low.clone(), bits);
    let overflow = common::compare(LirOperationCompare::Ne, high, sign_fill);

    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: low.clone(),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: overflow.clone(),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(low.clone()),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: LirExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn imul_implicit(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let src = operand_expr(machine, operands.first()?)?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_name, high_name, acc_name, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let acc = LirExpression::Read(Box::new(common::reg(acc_name, bits)));
    let wide_product = LirExpression::Binary {
        op: LirOperationBinary::Mul,
        left: Box::new(LirExpression::Cast {
            op: LirOperationCast::SignExtend,
            arg: Box::new(acc),
            bits: full_bits,
        }),
        right: Box::new(LirExpression::Cast {
            op: LirOperationCast::SignExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let result_low = LirExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits: result_bits,
    };
    let overflow = if bits == 8 {
        common::compare(
            LirOperationCompare::Ne,
            LirExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: 8,
                bits: 8,
            },
            signed_extension_fill(
                LirExpression::Extract {
                    arg: Box::new(result_low.clone()),
                    lsb: 0,
                    bits: 8,
                },
                8,
            ),
        )
    } else {
        let high = LirExpression::Extract {
            arg: Box::new(wide_product.clone()),
            lsb: bits,
            bits,
        };
        common::compare(
            LirOperationCompare::Ne,
            high,
            signed_extension_fill(
                LirExpression::Extract {
                    arg: Box::new(result_low.clone()),
                    lsb: 0,
                    bits,
                },
                bits,
            ),
        )
    };

    let mut effects = vec![LirEffect::Set {
        dst: common::reg(low_name, result_bits),
        expression: result_low.clone(),
    }];
    if bits > 8 {
        effects.push(LirEffect::Set {
            dst: common::reg(high_name, bits),
            expression: LirExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: bits,
                bits,
            },
        });
    }
    effects.extend([
        LirEffect::Set {
            dst: common::flag("cf"),
            expression: overflow.clone(),
        },
        LirEffect::Set {
            dst: common::flag("of"),
            expression: overflow,
        },
        LirEffect::Set {
            dst: common::flag("zf"),
            expression: LirExpression::Undefined { bits: 1 },
        },
        LirEffect::Set {
            dst: common::flag("sf"),
            expression: LirExpression::Undefined { bits: 1 },
        },
        LirEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(result_low),
        },
        LirEffect::Set {
            dst: common::flag("af"),
            expression: LirExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(LirTerminator::FallThrough, effects))
}

fn mul(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let src = operand_expr(machine, operands.first()?)?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_name, high_name, acc_name, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let wide_product = LirExpression::Binary {
        op: LirOperationBinary::Mul,
        left: Box::new(LirExpression::Cast {
            op: LirOperationCast::ZeroExtend,
            arg: Box::new(LirExpression::Read(Box::new(common::reg(acc_name, bits)))),
            bits: full_bits,
        }),
        right: Box::new(LirExpression::Cast {
            op: LirOperationCast::ZeroExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let result_low = LirExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits: result_bits,
    };
    let high_nonzero = if bits == 8 {
        common::compare(
            LirOperationCompare::Ne,
            LirExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: 8,
                bits: 8,
            },
            common::const_u64(0, 8),
        )
    } else {
        common::compare(
            LirOperationCompare::Ne,
            LirExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: bits,
                bits,
            },
            common::const_u64(0, bits),
        )
    };

    let mut effects = vec![LirEffect::Set {
        dst: common::reg(low_name, result_bits),
        expression: result_low.clone(),
    }];
    if bits > 8 {
        effects.push(LirEffect::Set {
            dst: common::reg(high_name, bits),
            expression: LirExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: bits,
                bits,
            },
        });
    }
    effects.extend([
        LirEffect::Set {
            dst: common::flag("cf"),
            expression: high_nonzero.clone(),
        },
        LirEffect::Set {
            dst: common::flag("of"),
            expression: high_nonzero,
        },
        LirEffect::Set {
            dst: common::flag("zf"),
            expression: LirExpression::Undefined { bits: 1 },
        },
        LirEffect::Set {
            dst: common::flag("sf"),
            expression: LirExpression::Undefined { bits: 1 },
        },
        LirEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(result_low),
        },
        LirEffect::Set {
            dst: common::flag("af"),
            expression: LirExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(LirTerminator::FallThrough, effects))
}

fn mulx(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst_low = operand_location(machine, operands.first()?)?;
    let dst_high = operand_location(machine, operands.get(1)?)?;
    let src = operand_expr(machine, operands.get(2)?)?;
    let bits = common::location_bits(&dst_low);
    if common::location_bits(&dst_high) != bits || !matches!(bits, 32 | 64) {
        return None;
    }

    let implicit_name = match bits {
        32 => "edx",
        64 => "rdx",
        _ => return None,
    };
    let full_bits = bits * 2;
    let wide_product = LirExpression::Binary {
        op: LirOperationBinary::Mul,
        left: Box::new(LirExpression::Cast {
            op: LirOperationCast::ZeroExtend,
            arg: Box::new(LirExpression::Read(Box::new(common::reg(
                implicit_name,
                bits,
            )))),
            bits: full_bits,
        }),
        right: Box::new(LirExpression::Cast {
            op: LirOperationCast::ZeroExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };

    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: dst_low,
                expression: LirExpression::Extract {
                    arg: Box::new(wide_product.clone()),
                    lsb: 0,
                    bits,
                },
            },
            LirEffect::Set {
                dst: dst_high,
                expression: LirExpression::Extract {
                    arg: Box::new(wide_product),
                    lsb: bits,
                    bits,
                },
            },
        ],
    ))
}

fn div(machine: Architecture, operands: &[X86OperandView], signed: bool) -> Option<Lir> {
    let divisor = operand_expr(machine, operands.first()?)?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_name, high_name, acc_name, result_bits) = implicit_mul_registers(machine, bits)?;
    let dividend = if bits == 8 {
        LirExpression::Cast {
            op: LirOperationCast::ZeroExtend,
            arg: Box::new(LirExpression::Read(Box::new(common::reg(
                low_name,
                result_bits,
            )))),
            bits: 16,
        }
    } else {
        LirExpression::Concat {
            parts: vec![
                LirExpression::Read(Box::new(common::reg(high_name, bits))),
                LirExpression::Read(Box::new(common::reg(acc_name, bits))),
            ],
            bits: bits * 2,
        }
    };
    let full_bits = bits * 2;
    let divisor_wide = if signed {
        LirExpression::Cast {
            op: LirOperationCast::SignExtend,
            arg: Box::new(divisor),
            bits: full_bits,
        }
    } else {
        LirExpression::Cast {
            op: LirOperationCast::ZeroExtend,
            arg: Box::new(divisor),
            bits: full_bits,
        }
    };
    let quotient = LirExpression::Binary {
        op: if signed {
            LirOperationBinary::SDiv
        } else {
            LirOperationBinary::UDiv
        },
        left: Box::new(dividend.clone()),
        right: Box::new(divisor_wide.clone()),
        bits: full_bits,
    };
    let remainder = LirExpression::Binary {
        op: if signed {
            LirOperationBinary::SRem
        } else {
            LirOperationBinary::URem
        },
        left: Box::new(dividend),
        right: Box::new(divisor_wide),
        bits: full_bits,
    };
    let q_bits = if bits == 8 { 8 } else { bits };
    let r_bits = if bits == 8 { 8 } else { bits };
    let q_name = if bits == 8 { "al" } else { acc_name };
    let r_name = if bits == 8 { "ah" } else { high_name };

    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: common::reg(q_name, q_bits),
                expression: LirExpression::Extract {
                    arg: Box::new(quotient),
                    lsb: 0,
                    bits: q_bits,
                },
            },
            LirEffect::Set {
                dst: common::reg(r_name, r_bits),
                expression: LirExpression::Extract {
                    arg: Box::new(remainder),
                    lsb: 0,
                    bits: r_bits,
                },
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: LirExpression::Undefined { bits: 1 },
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: LirExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn adc(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let carry_in = LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(common::flag_expr("cf")),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in.clone(), bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(LirOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            common::flag_expr("cf"),
            common::compare(LirOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: carry_out,
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    left.clone(),
                    right_with_carry.clone(),
                    result.clone(),
                    bits,
                ),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(left, right_with_carry, result, bits),
            },
        ],
    ))
}

fn sbb(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let borrow_in = LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(common::flag_expr("cf")),
        bits,
    };
    let right_with_borrow = common::add(right.clone(), borrow_in.clone(), bits);
    let result = common::sub(left.clone(), right_with_borrow.clone(), bits);
    let carry_out = common::or(
        common::compare(
            LirOperationCompare::Ult,
            left.clone(),
            right_with_borrow.clone(),
        ),
        common::and(
            common::flag_expr("cf"),
            common::compare(
                LirOperationCompare::Eq,
                left.clone(),
                right_with_borrow.clone(),
            ),
            1,
        ),
        1,
    );
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: carry_out,
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(
                    left.clone(),
                    right_with_borrow.clone(),
                    result.clone(),
                    bits,
                ),
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(left, right_with_borrow, result, bits),
            },
        ],
    ))
}

fn adcx_adox(machine: Architecture, operands: &[X86OperandView], use_cf: bool) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let carry_flag = if use_cf { "cf" } else { "of" };
    let carry_in_flag = common::flag_expr(carry_flag);
    let carry_in = LirExpression::Cast {
        op: LirOperationCast::ZeroExtend,
        arg: Box::new(carry_in_flag.clone()),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in, bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(LirOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            carry_in_flag.clone(),
            common::compare(LirOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    let overflow_out =
        common::add_overflow(left.clone(), right_with_carry.clone(), result.clone(), bits);

    let mut effects = vec![LirEffect::Set {
        dst,
        expression: result,
    }];
    if use_cf {
        effects.push(LirEffect::Set {
            dst: common::flag("cf"),
            expression: carry_out,
        });
        effects.push(LirEffect::Set {
            dst: common::flag("of"),
            expression: common::flag_expr("of"),
        });
    } else {
        effects.push(LirEffect::Set {
            dst: common::flag("cf"),
            expression: common::flag_expr("cf"),
        });
        effects.push(LirEffect::Set {
            dst: common::flag("of"),
            expression: overflow_out,
        });
    }
    for flag in ["zf", "sf", "pf", "af"] {
        effects.push(LirEffect::Set {
            dst: common::flag(flag),
            expression: common::flag_expr(flag),
        });
    }

    Some(common::complete(LirTerminator::FallThrough, effects))
}

fn unary(
    machine: Architecture,
    operands: &[X86OperandView],
    op: LirOperationBinary,
) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let bits = common::location_bits(&dst);
    let right = common::const_u64(1, bits);
    let result = LirExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let overflow = if op == LirOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst,
                expression: result.clone(),
            },
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    LirOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

fn unary_op(
    machine: Architecture,
    operands: &[X86OperandView],
    op: LirOperationUnary,
    is_neg: bool,
) -> Option<Lir> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = common::location_bits(&dst);
    let expression = operand_expr(machine, operands.first()?)?;
    if is_neg {
        let zero = common::const_u64(0, bits);
        let result = LirExpression::Unary {
            op,
            arg: Box::new(expression.clone()),
            bits,
        };
        return Some(common::complete(
            LirTerminator::FallThrough,
            vec![
                LirEffect::Set {
                    dst,
                    expression: result.clone(),
                },
                LirEffect::Set {
                    dst: common::flag("cf"),
                    expression: common::compare(
                        LirOperationCompare::Ne,
                        expression.clone(),
                        zero.clone(),
                    ),
                },
                LirEffect::Set {
                    dst: common::flag("zf"),
                    expression: common::compare(LirOperationCompare::Eq, result.clone(), zero),
                },
                LirEffect::Set {
                    dst: common::flag("sf"),
                    expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
                },
                LirEffect::Set {
                    dst: common::flag("of"),
                    expression: common::compare(
                        LirOperationCompare::Eq,
                        expression.clone(),
                        common::const_u64(1u64 << bits.saturating_sub(1), bits),
                    ),
                },
                LirEffect::Set {
                    dst: common::flag("pf"),
                    expression: common::parity_flag(result.clone()),
                },
                LirEffect::Set {
                    dst: common::flag("af"),
                    expression: common::auxiliary_flag(
                        common::const_u64(0, bits),
                        expression,
                        result,
                        bits,
                    ),
                },
            ],
        ));
    }
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![LirEffect::Set {
            dst,
            expression: LirExpression::Unary {
                op,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

fn cmp_like(machine: Architecture, operands: &[X86OperandView]) -> Option<Lir> {
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = operands
        .first()
        .and_then(|operand| operand_location(machine, operand))
        .map(|location| common::location_bits(&location))
        .unwrap_or_else(|| common::pointer_bits(machine));
    let diff = common::sub(left.clone(), right.clone(), bits);
    let sign_bit = bits.saturating_sub(1);
    let zf = common::compare(LirOperationCompare::Eq, left.clone(), right.clone());
    let cf = common::compare(LirOperationCompare::Ult, left.clone(), right.clone());
    let sf = common::extract_bit(diff.clone(), sign_bit);
    let of = common::sub_overflow(left.clone(), right.clone(), diff.clone(), bits);
    let af = common::auxiliary_flag(left.clone(), right.clone(), diff.clone(), bits);
    Some(common::complete(
        LirTerminator::FallThrough,
        vec![
            LirEffect::Set {
                dst: common::flag("zf"),
                expression: zf,
            },
            LirEffect::Set {
                dst: common::flag("cf"),
                expression: cf,
            },
            LirEffect::Set {
                dst: common::flag("sf"),
                expression: sf,
            },
            LirEffect::Set {
                dst: common::flag("of"),
                expression: of,
            },
            LirEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff),
            },
            LirEffect::Set {
                dst: common::flag("af"),
                expression: af,
            },
        ],
    ))
}

fn operand_expr(machine: Architecture, operand: &X86OperandView) -> Option<LirExpression> {
    match operand.kind {
        X86OperandKind::Register => Some(LirExpression::Read(Box::new(common::reg(
            operand.register_name()?,
            operand.size_bits,
        )))),
        X86OperandKind::Immediate => Some(LirExpression::Const {
            value: operand.immediate_value()? as i128 as u128,
            bits: operand.size_bits,
        }),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(LirExpression::Load {
                space: common::memory_space(mem.segment_register_name),
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn operand_location(machine: Architecture, operand: &X86OperandView) -> Option<LirLocation> {
    match operand.kind {
        X86OperandKind::Register => Some(common::reg(operand.register_name()?, operand.size_bits)),
        X86OperandKind::Memory => {
            let mem = operand.memory_operand()?;
            let base = mem.base_register_name.map(|name| {
                LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
            });
            let index = mem.index_register_name.map(|name| {
                (
                    LirExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
                    mem.scale,
                )
            });
            let addr = common::memory_addr(machine, base, index, mem.displacement);
            Some(LirLocation::Memory {
                space: common::memory_space(mem.segment_register_name),
                addr: Box::new(addr),
                bits: operand.size_bits,
            })
        }
        _ => None,
    }
}

fn implicit_mul_registers(
    machine: Architecture,
    bits: u16,
) -> Option<(&'static str, &'static str, &'static str, u16)> {
    match bits {
        8 => Some(("ax", "ah", "al", 16)),
        16 => Some(("ax", "dx", "ax", 16)),
        32 => Some(("eax", "edx", "eax", 32)),
        64 if machine == Architecture::AMD64 => Some(("rax", "rdx", "rax", 64)),
        _ => None,
    }
}

fn operand_bits(machine: Architecture, operand: &X86OperandView) -> Option<u16> {
    match operand.kind {
        X86OperandKind::Register | X86OperandKind::Memory => Some(operand.size_bits),
        X86OperandKind::Immediate if operand.size_bits != 0 => Some(operand.size_bits),
        X86OperandKind::Immediate => Some(common::pointer_bits(machine)),
        _ => None,
    }
}

fn signed_extension_fill(value: LirExpression, bits: u16) -> LirExpression {
    LirExpression::Select {
        condition: Box::new(common::extract_bit(value, bits - 1)),
        when_true: Box::new(common::const_u64(u64::MAX, bits)),
        when_false: Box::new(common::const_u64(0, bits)),
        bits,
    }
}
