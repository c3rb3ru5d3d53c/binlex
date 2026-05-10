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
use crate::semantics::x86::InstructionDetailX86;
use crate::semantics::x86::helpers as common;
use crate::semantics::x86::{X86OperandKind, X86OperandView};
use crate::semantics::{
    Semantic, SemanticAddressSpace, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticStatus, SemanticTemporary, SemanticTerminator,
};

pub(crate) fn build(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    match view.mnemonic.as_str() {
        "nop" => Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![SemanticEffect::Nop],
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
        "add" => binary(machine, view.operands(), SemanticOperationBinary::Add),
        "sub" => binary(machine, view.operands(), SemanticOperationBinary::Sub),
        "adc" => adc(machine, view.operands()),
        "sbb" => sbb(machine, view.operands()),
        "adcx" => adcx_adox(machine, view.operands(), true),
        "adox" => adcx_adox(machine, view.operands(), false),
        "inc" => unary(machine, view.operands(), SemanticOperationBinary::Add),
        "dec" => unary(machine, view.operands(), SemanticOperationBinary::Sub),
        "neg" => unary_op(machine, view.operands(), SemanticOperationUnary::Neg, true),
        "not" => unary_op(machine, view.operands(), SemanticOperationUnary::Not, false),
        "bswap" => unary_op(
            machine,
            view.operands(),
            SemanticOperationUnary::ByteSwap,
            false,
        ),
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

fn ascii_adjust(machine: Architecture, view: &InstructionDetailX86) -> Option<Semantic> {
    let al_reg = common::reg("al", 8);
    let ah_reg = common::reg("ah", 8);
    let al = SemanticExpression::Read(Box::new(al_reg.clone()));
    let ah = SemanticExpression::Read(Box::new(ah_reg.clone()));

    match view.mnemonic.as_str() {
        "aaa" | "aas" => {
            let low_nibble = SemanticExpression::Extract {
                arg: Box::new(al.clone()),
                lsb: 0,
                bits: 4,
            };
            let decimal_adjust = common::or(
                common::compare(
                    SemanticOperationCompare::Ugt,
                    low_nibble,
                    SemanticExpression::Const { value: 9, bits: 4 },
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
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: al_reg,
                        expression: SemanticExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(masked_al),
                            when_false: Box::new(common::and(al, common::const_u64(0x0f, 8), 8)),
                            bits: 8,
                        },
                    },
                    SemanticEffect::Set {
                        dst: ah_reg,
                        expression: SemanticExpression::Select {
                            condition: Box::new(decimal_adjust.clone()),
                            when_true: Box::new(adjusted_ah),
                            when_false: Box::new(ah),
                            bits: 8,
                        },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: decimal_adjust.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: decimal_adjust,
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
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
            let ah_term = SemanticExpression::Binary {
                op: SemanticOperationBinary::Mul,
                left: Box::new(ah),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let result = common::add(ah_term, al, 8);
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: common::reg("al", 8),
                        expression: result.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::reg("ah", 8),
                        expression: common::const_u64(0, 8),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            SemanticOperationCompare::Eq,
                            result.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(result.clone(), 7),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(result),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: SemanticExpression::Undefined { bits: 1 },
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
            let quotient = SemanticExpression::Binary {
                op: SemanticOperationBinary::UDiv,
                left: Box::new(al.clone()),
                right: Box::new(base.clone()),
                bits: 8,
            };
            let remainder = SemanticExpression::Binary {
                op: SemanticOperationBinary::URem,
                left: Box::new(al),
                right: Box::new(base),
                bits: 8,
            };
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![
                    SemanticEffect::Set {
                        dst: common::reg("ah", 8),
                        expression: quotient,
                    },
                    SemanticEffect::Set {
                        dst: common::reg("al", 8),
                        expression: remainder.clone(),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("zf"),
                        expression: common::compare(
                            SemanticOperationCompare::Eq,
                            remainder.clone(),
                            common::const_u64(0, 8),
                        ),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("sf"),
                        expression: common::extract_bit(remainder.clone(), 7),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("pf"),
                        expression: common::parity_flag(remainder),
                    },
                    SemanticEffect::Set {
                        dst: common::flag("cf"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("of"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                    SemanticEffect::Set {
                        dst: common::flag("af"),
                        expression: SemanticExpression::Undefined { bits: 1 },
                    },
                ],
            ));
        }
        "daa" => {
            return Some(common::complete(
                SemanticTerminator::FallThrough,
                vec![SemanticEffect::Intrinsic {
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

fn assign(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let expression = operand_expr(machine, operands.get(1)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn lea(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let mem = operands.get(1)?.memory_operand()?;
    let base = mem.base_register_name.map(|name| {
        SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine))))
    });
    let index = mem.index_register_name.map(|name| {
        (
            SemanticExpression::Read(Box::new(common::reg(name, common::pointer_bits(machine)))),
            mem.scale,
        )
    });
    let addr = common::memory_addr(machine, base, index, mem.displacement);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: addr,
        }],
    ))
}

fn movbe(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let expression = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    if !matches!(bits, 16 | 32 | 64) {
        return None;
    }
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::ByteSwap,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

fn movx(machine: Architecture, operands: &[X86OperandView], sign_extend: bool) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expr(machine, operands.get(1)?)?;
    let dst_bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: if sign_extend {
                    SemanticOperationCast::SignExtend
                } else {
                    SemanticOperationCast::ZeroExtend
                },
                arg: Box::new(src),
                bits: dst_bits,
            },
        }],
    ))
}

fn exchange(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let left_dst = operand_location(machine, operands.first()?)?;
    let right_dst = operand_location(machine, operands.get(1)?)?;
    let left_expr = operand_expr(machine, operands.first()?)?;
    let right_expr = operand_expr(machine, operands.get(1)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: left_dst,
                expression: right_expr,
            },
            SemanticEffect::Set {
                dst: right_dst,
                expression: left_expr,
            },
        ],
    ))
}

fn exchange_add(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let src_dst = operand_location(machine, operands.get(1)?)?;
    let dst_expr = operand_expr(machine, operands.first()?)?;
    let src_expr = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let result = common::add(dst_expr.clone(), src_expr.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: src_dst,
                expression: dst_expr.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::compare(
                    SemanticOperationCompare::Ult,
                    result.clone(),
                    dst_expr.clone(),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    dst_expr.clone(),
                    src_expr.clone(),
                    result.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(dst_expr, src_expr, result, bits),
            },
        ],
    ))
}

fn compare_exchange(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
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
    let accumulator = SemanticExpression::Read(Box::new(accumulator_location.clone()));
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed.clone(),
    );
    let diff = common::sub(accumulator.clone(), observed.clone(), bits);
    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: SemanticExpression::Select {
            condition: Box::new(equal.clone()),
            when_true: Box::new(src),
            when_false: Box::new(observed.clone()),
            bits,
        },
    }];
    if dst != accumulator_location {
        effects.push(SemanticEffect::Set {
            dst: accumulator_location,
            expression: SemanticExpression::Select {
                condition: Box::new(equal.clone()),
                when_true: Box::new(accumulator.clone()),
                when_false: Box::new(observed.clone()),
                bits,
            },
        });
    }
    effects.extend([
        SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: equal.clone(),
        },
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: common::compare(
                SemanticOperationCompare::Ult,
                accumulator.clone(),
                observed.clone(),
            ),
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: common::extract_bit(diff.clone(), bits.saturating_sub(1)),
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: common::sub_overflow(
                accumulator.clone(),
                observed.clone(),
                diff.clone(),
                bits,
            ),
        },
        SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(diff.clone()),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: common::auxiliary_flag(accumulator, observed, diff, bits),
        },
    ]);
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn lock_cmpxchg8b(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = match dst {
        SemanticLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    if !matches!(machine, Architecture::I386 | Architecture::AMD64) {
        return None;
    }
    let eax = SemanticExpression::Read(Box::new(common::reg("eax", 32)));
    let edx = SemanticExpression::Read(Box::new(common::reg("edx", 32)));
    let ebx = SemanticExpression::Read(Box::new(common::reg("ebx", 32)));
    let ecx = SemanticExpression::Read(Box::new(common::reg("ecx", 32)));
    let accumulator = SemanticExpression::Concat {
        parts: vec![edx.clone(), eax.clone()],
        bits: 64,
    };
    let replacement = SemanticExpression::Concat {
        parts: vec![ecx, ebx],
        bits: 64,
    };
    let observed_tmp = SemanticLocation::Temporary { id: 0, bits: 64 };
    let observed_expr = SemanticExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 32,
    };
    let observed_high = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 32,
        bits: 32,
    };
    Some(Semantic {
        version: 1,
        status: SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: vec![SemanticTemporary {
            id: 0,
            bits: 64,
            name: Some("lock_cmpxchg8b_observed".to_string()),
        }],
        effects: vec![
            SemanticEffect::AtomicCmpXchg {
                space: SemanticAddressSpace::Default,
                addr,
                expected: accumulator,
                desired: replacement,
                bits: 64,
                observed: observed_tmp,
            },
            SemanticEffect::Set {
                dst: common::reg("eax", 32),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(eax),
                    when_false: Box::new(observed_low),
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::reg("edx", 32),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(edx),
                    when_false: Box::new(observed_high),
                    bits: 32,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn lock_cmpxchg16b(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let addr = match dst {
        SemanticLocation::Memory { addr, .. } => *addr,
        _ => return None,
    };
    if !matches!(machine, Architecture::AMD64) {
        return None;
    }
    let rax = SemanticExpression::Read(Box::new(common::reg("rax", 64)));
    let rdx = SemanticExpression::Read(Box::new(common::reg("rdx", 64)));
    let rbx = SemanticExpression::Read(Box::new(common::reg("rbx", 64)));
    let rcx = SemanticExpression::Read(Box::new(common::reg("rcx", 64)));
    let accumulator = SemanticExpression::Concat {
        parts: vec![rdx.clone(), rax.clone()],
        bits: 128,
    };
    let replacement = SemanticExpression::Concat {
        parts: vec![rcx, rbx],
        bits: 128,
    };
    let observed_tmp = SemanticLocation::Temporary { id: 1, bits: 128 };
    let observed_expr = SemanticExpression::Read(Box::new(observed_tmp.clone()));
    let equal = common::compare(
        SemanticOperationCompare::Eq,
        accumulator.clone(),
        observed_expr.clone(),
    );
    let observed_low = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 0,
        bits: 64,
    };
    let observed_high = SemanticExpression::Extract {
        arg: Box::new(observed_expr.clone()),
        lsb: 64,
        bits: 64,
    };
    Some(Semantic {
        version: 1,
        status: SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: vec![SemanticTemporary {
            id: 1,
            bits: 128,
            name: Some("lock_cmpxchg16b_observed".to_string()),
        }],
        effects: vec![
            SemanticEffect::AtomicCmpXchg {
                space: SemanticAddressSpace::Default,
                addr,
                expected: accumulator,
                desired: replacement,
                bits: 128,
                observed: observed_tmp,
            },
            SemanticEffect::Set {
                dst: common::reg("rax", 64),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rax),
                    when_false: Box::new(observed_low),
                    bits: 64,
                },
            },
            SemanticEffect::Set {
                dst: common::reg("rdx", 64),
                expression: SemanticExpression::Select {
                    condition: Box::new(equal.clone()),
                    when_true: Box::new(rdx),
                    when_false: Box::new(observed_high),
                    bits: 64,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: equal,
            },
        ],
        terminator: SemanticTerminator::FallThrough,
        diagnostics: Vec::new(),
    })
}

fn sign_extension(view: &InstructionDetailX86) -> Option<Semantic> {
    let (src_name, src_bits, dst_name, dst_bits, high_only) = match view.mnemonic.as_str() {
        "cbw" => ("al", 8, "ax", 16, false),
        "cwde" => ("ax", 16, "eax", 32, false),
        "cdqe" => ("eax", 32, "rax", 64, false),
        "cwd" => ("ax", 16, "dx", 16, true),
        "cdq" => ("eax", 32, "edx", 32, true),
        "cqo" => ("rax", 64, "rdx", 64, true),
        _ => return None,
    };

    let src = SemanticExpression::Read(Box::new(common::reg(src_name, src_bits)));
    let expression = if high_only {
        SemanticExpression::Select {
            condition: Box::new(common::extract_bit(src, src_bits - 1)),
            when_true: Box::new(common::const_u64(u64::MAX, dst_bits)),
            when_false: Box::new(common::const_u64(0, dst_bits)),
            bits: dst_bits,
        }
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(src),
            bits: dst_bits,
        }
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg(dst_name, dst_bits),
            expression,
        }],
    ))
}

fn binary(
    machine: Architecture,
    operands: &[X86OperandView],
    op: SemanticOperationBinary,
) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let carry = if op == SemanticOperationBinary::Add {
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone())
    } else {
        common::compare(SemanticOperationCompare::Ult, left.clone(), right.clone())
    };
    let overflow = if op == SemanticOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

fn popcnt(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let result = SemanticExpression::Unary {
        op: SemanticOperationUnary::PopCount,
        arg: Box::new(src.clone()),
        bits,
    };
    let src_is_zero = common::compare(
        SemanticOperationCompare::Eq,
        src,
        common::const_u64(0, bits),
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result,
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: src_is_zero,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::bool_const(false),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::bool_const(false),
            },
        ],
    ))
}

fn crc32(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expr(machine, operands.get(1)?)?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.crc32".to_string(),
            args: vec![src],
            outputs: vec![dst],
        }],
    ))
}

fn xlat(machine: Architecture) -> Option<Semantic> {
    let pointer_bits = common::pointer_bits(machine);
    let base_name = if matches!(machine, Architecture::AMD64) {
        "rbx"
    } else {
        "ebx"
    };
    let base = SemanticExpression::Read(Box::new(common::reg(base_name, pointer_bits)));
    let index = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(SemanticExpression::Read(Box::new(common::reg("al", 8)))),
        bits: pointer_bits,
    };
    let addr = common::add(base, index, pointer_bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg("al", 8),
            expression: SemanticExpression::Load {
                space: crate::semantics::SemanticAddressSpace::Default,
                addr: Box::new(addr),
                bits: 8,
            },
        }],
    ))
}

fn imul(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    match operands.len() {
        2 | 3 => imul_explicit(machine, operands),
        1 => imul_implicit(machine, operands),
        _ => None,
    }
}

fn imul_explicit(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = common::location_bits(&dst);
    let full_bits = bits.saturating_mul(2);
    let left = if operands.len() == 2 {
        operand_expr(machine, operands.first()?)?
    } else {
        operand_expr(machine, operands.get(1)?)?
    };
    let right = operand_expr(machine, operands.last()?)?;
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(left),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(right),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let low = SemanticExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits,
    };
    let high = SemanticExpression::Extract {
        arg: Box::new(wide_product),
        lsb: bits,
        bits,
    };
    let sign_fill = signed_extension_fill(low.clone(), bits);
    let overflow = common::compare(SemanticOperationCompare::Ne, high, sign_fill);

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: low.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: overflow.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(low.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn imul_implicit(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let src = operand_expr(machine, operands.first()?)?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_name, high_name, acc_name, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let acc = SemanticExpression::Read(Box::new(common::reg(acc_name, bits)));
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(acc),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let result_low = SemanticExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits: result_bits,
    };
    let overflow = if bits == 8 {
        common::compare(
            SemanticOperationCompare::Ne,
            SemanticExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: 8,
                bits: 8,
            },
            signed_extension_fill(
                SemanticExpression::Extract {
                    arg: Box::new(result_low.clone()),
                    lsb: 0,
                    bits: 8,
                },
                8,
            ),
        )
    } else {
        let high = SemanticExpression::Extract {
            arg: Box::new(wide_product.clone()),
            lsb: bits,
            bits,
        };
        common::compare(
            SemanticOperationCompare::Ne,
            high,
            signed_extension_fill(
                SemanticExpression::Extract {
                    arg: Box::new(result_low.clone()),
                    lsb: 0,
                    bits,
                },
                bits,
            ),
        )
    };

    let mut effects = vec![SemanticEffect::Set {
        dst: common::reg(low_name, result_bits),
        expression: result_low.clone(),
    }];
    if bits > 8 {
        effects.push(SemanticEffect::Set {
            dst: common::reg(high_name, bits),
            expression: SemanticExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: bits,
                bits,
            },
        });
    }
    effects.extend([
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: overflow.clone(),
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: overflow,
        },
        SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(result_low),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn mul(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let src = operand_expr(machine, operands.first()?)?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_name, high_name, acc_name, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Read(Box::new(common::reg(
                acc_name, bits,
            )))),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };
    let result_low = SemanticExpression::Extract {
        arg: Box::new(wide_product.clone()),
        lsb: 0,
        bits: result_bits,
    };
    let high_nonzero = if bits == 8 {
        common::compare(
            SemanticOperationCompare::Ne,
            SemanticExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: 8,
                bits: 8,
            },
            common::const_u64(0, 8),
        )
    } else {
        common::compare(
            SemanticOperationCompare::Ne,
            SemanticExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: bits,
                bits,
            },
            common::const_u64(0, bits),
        )
    };

    let mut effects = vec![SemanticEffect::Set {
        dst: common::reg(low_name, result_bits),
        expression: result_low.clone(),
    }];
    if bits > 8 {
        effects.push(SemanticEffect::Set {
            dst: common::reg(high_name, bits),
            expression: SemanticExpression::Extract {
                arg: Box::new(wide_product.clone()),
                lsb: bits,
                bits,
            },
        });
    }
    effects.extend([
        SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: high_nonzero.clone(),
        },
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: high_nonzero,
        },
        SemanticEffect::Set {
            dst: common::flag("zf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
        SemanticEffect::Set {
            dst: common::flag("pf"),
            expression: common::parity_flag(result_low),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn mulx(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
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
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Read(Box::new(common::reg(
                implicit_name,
                bits,
            )))),
            bits: full_bits,
        }),
        right: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(src),
            bits: full_bits,
        }),
        bits: full_bits,
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: dst_low,
                expression: SemanticExpression::Extract {
                    arg: Box::new(wide_product.clone()),
                    lsb: 0,
                    bits,
                },
            },
            SemanticEffect::Set {
                dst: dst_high,
                expression: SemanticExpression::Extract {
                    arg: Box::new(wide_product),
                    lsb: bits,
                    bits,
                },
            },
        ],
    ))
}

fn div(machine: Architecture, operands: &[X86OperandView], signed: bool) -> Option<Semantic> {
    let divisor = operand_expr(machine, operands.first()?)?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_name, high_name, acc_name, result_bits) = implicit_mul_registers(machine, bits)?;
    let dividend = if bits == 8 {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Read(Box::new(common::reg(
                low_name,
                result_bits,
            )))),
            bits: 16,
        }
    } else {
        SemanticExpression::Concat {
            parts: vec![
                SemanticExpression::Read(Box::new(common::reg(high_name, bits))),
                SemanticExpression::Read(Box::new(common::reg(acc_name, bits))),
            ],
            bits: bits * 2,
        }
    };
    let full_bits = bits * 2;
    let divisor_wide = if signed {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(divisor),
            bits: full_bits,
        }
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(divisor),
            bits: full_bits,
        }
    };
    let quotient = SemanticExpression::Binary {
        op: if signed {
            SemanticOperationBinary::SDiv
        } else {
            SemanticOperationBinary::UDiv
        },
        left: Box::new(dividend.clone()),
        right: Box::new(divisor_wide.clone()),
        bits: full_bits,
    };
    let remainder = SemanticExpression::Binary {
        op: if signed {
            SemanticOperationBinary::SRem
        } else {
            SemanticOperationBinary::URem
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
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::reg(q_name, q_bits),
                expression: SemanticExpression::Extract {
                    arg: Box::new(quotient),
                    lsb: 0,
                    bits: q_bits,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(r_name, r_bits),
                expression: SemanticExpression::Extract {
                    arg: Box::new(remainder),
                    lsb: 0,
                    bits: r_bits,
                },
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn adc(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let carry_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(common::flag_expr("cf")),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in.clone(), bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            common::flag_expr("cf"),
            common::compare(SemanticOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry_out,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::add_overflow(
                    left.clone(),
                    right_with_carry.clone(),
                    result.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(left, right_with_carry, result, bits),
            },
        ],
    ))
}

fn sbb(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let borrow_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(common::flag_expr("cf")),
        bits,
    };
    let right_with_borrow = common::add(right.clone(), borrow_in.clone(), bits);
    let result = common::sub(left.clone(), right_with_borrow.clone(), bits);
    let carry_out = common::or(
        common::compare(
            SemanticOperationCompare::Ult,
            left.clone(),
            right_with_borrow.clone(),
        ),
        common::and(
            common::flag_expr("cf"),
            common::compare(
                SemanticOperationCompare::Eq,
                left.clone(),
                right_with_borrow.clone(),
            ),
            1,
        ),
        1,
    );
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: carry_out,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: common::sub_overflow(
                    left.clone(),
                    right_with_borrow.clone(),
                    result.clone(),
                    bits,
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result.clone()),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: common::auxiliary_flag(left, right_with_borrow, result, bits),
            },
        ],
    ))
}

fn adcx_adox(machine: Architecture, operands: &[X86OperandView], use_cf: bool) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = common::location_bits(&dst);
    let carry_flag = if use_cf { "cf" } else { "of" };
    let carry_in_flag = common::flag_expr(carry_flag);
    let carry_in = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(carry_in_flag.clone()),
        bits,
    };
    let right_with_carry = common::add(right.clone(), carry_in, bits);
    let result = common::add(left.clone(), right_with_carry.clone(), bits);
    let carry_out = common::or(
        common::compare(SemanticOperationCompare::Ult, result.clone(), left.clone()),
        common::and(
            carry_in_flag.clone(),
            common::compare(SemanticOperationCompare::Eq, result.clone(), left.clone()),
            1,
        ),
        1,
    );
    let overflow_out =
        common::add_overflow(left.clone(), right_with_carry.clone(), result.clone(), bits);

    let mut effects = vec![SemanticEffect::Set {
        dst,
        expression: result,
    }];
    if use_cf {
        effects.push(SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: carry_out,
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("of"),
            expression: common::flag_expr("of"),
        });
    } else {
        effects.push(SemanticEffect::Set {
            dst: common::flag("cf"),
            expression: common::flag_expr("cf"),
        });
        effects.push(SemanticEffect::Set {
            dst: common::flag("of"),
            expression: overflow_out,
        });
    }
    for flag in ["zf", "sf", "pf", "af"] {
        effects.push(SemanticEffect::Set {
            dst: common::flag(flag),
            expression: common::flag_expr(flag),
        });
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn unary(
    machine: Architecture,
    operands: &[X86OperandView],
    op: SemanticOperationBinary,
) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let left = operand_expr(machine, operands.first()?)?;
    let bits = common::location_bits(&dst);
    let right = common::const_u64(1, bits);
    let result = SemanticExpression::Binary {
        op,
        left: Box::new(left.clone()),
        right: Box::new(right.clone()),
        bits,
    };
    let overflow = if op == SemanticOperationBinary::Add {
        common::add_overflow(left.clone(), right.clone(), result.clone(), bits)
    } else {
        common::sub_overflow(left.clone(), right.clone(), result.clone(), bits)
    };
    let auxiliary = common::auxiliary_flag(left.clone(), right.clone(), result.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: common::compare(
                    SemanticOperationCompare::Eq,
                    result.clone(),
                    common::const_u64(0, bits),
                ),
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: overflow,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(result),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: auxiliary,
            },
        ],
    ))
}

fn unary_op(
    machine: Architecture,
    operands: &[X86OperandView],
    op: SemanticOperationUnary,
    is_neg: bool,
) -> Option<Semantic> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = common::location_bits(&dst);
    let expression = operand_expr(machine, operands.first()?)?;
    if is_neg {
        let zero = common::const_u64(0, bits);
        let result = SemanticExpression::Unary {
            op,
            arg: Box::new(expression.clone()),
            bits,
        };
        return Some(common::complete(
            SemanticTerminator::FallThrough,
            vec![
                SemanticEffect::Set {
                    dst,
                    expression: result.clone(),
                },
                SemanticEffect::Set {
                    dst: common::flag("cf"),
                    expression: common::compare(
                        SemanticOperationCompare::Ne,
                        expression.clone(),
                        zero.clone(),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("zf"),
                    expression: common::compare(SemanticOperationCompare::Eq, result.clone(), zero),
                },
                SemanticEffect::Set {
                    dst: common::flag("sf"),
                    expression: common::extract_bit(result.clone(), bits.saturating_sub(1)),
                },
                SemanticEffect::Set {
                    dst: common::flag("of"),
                    expression: common::compare(
                        SemanticOperationCompare::Eq,
                        expression.clone(),
                        common::const_u64(1u64 << bits.saturating_sub(1), bits),
                    ),
                },
                SemanticEffect::Set {
                    dst: common::flag("pf"),
                    expression: common::parity_flag(result.clone()),
                },
                SemanticEffect::Set {
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
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op,
                arg: Box::new(expression),
                bits,
            },
        }],
    ))
}

fn cmp_like(machine: Architecture, operands: &[X86OperandView]) -> Option<Semantic> {
    let left = operand_expr(machine, operands.first()?)?;
    let right = operand_expr(machine, operands.get(1)?)?;
    let bits = operands
        .first()
        .and_then(|operand| operand_location(machine, operand))
        .map(|location| common::location_bits(&location))
        .unwrap_or_else(|| common::pointer_bits(machine));
    let diff = common::sub(left.clone(), right.clone(), bits);
    let sign_bit = bits.saturating_sub(1);
    let zf = common::compare(SemanticOperationCompare::Eq, left.clone(), right.clone());
    let cf = common::compare(SemanticOperationCompare::Ult, left.clone(), right.clone());
    let sf = common::extract_bit(diff.clone(), sign_bit);
    let of = common::sub_overflow(left.clone(), right.clone(), diff.clone(), bits);
    let af = common::auxiliary_flag(left.clone(), right.clone(), diff.clone(), bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::flag("zf"),
                expression: zf,
            },
            SemanticEffect::Set {
                dst: common::flag("cf"),
                expression: cf,
            },
            SemanticEffect::Set {
                dst: common::flag("sf"),
                expression: sf,
            },
            SemanticEffect::Set {
                dst: common::flag("of"),
                expression: of,
            },
            SemanticEffect::Set {
                dst: common::flag("pf"),
                expression: common::parity_flag(diff),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: af,
            },
        ],
    ))
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
                space: crate::semantics::SemanticAddressSpace::Default,
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
                space: crate::semantics::SemanticAddressSpace::Default,
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

fn signed_extension_fill(value: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Select {
        condition: Box::new(common::extract_bit(value, bits - 1)),
        when_true: Box::new(common::const_u64(u64::MAX, bits)),
        when_false: Box::new(common::const_u64(0, bits)),
        bits,
    }
}
