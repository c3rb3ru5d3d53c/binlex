use super::*;

pub(super) const X87_BITS: u16 = 80;

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

pub(super) fn x87(
    machine: Architecture,
    view: &X86InstructionView,
) -> Option<InstructionSemantics> {
    let mnemonic = view.mnemonic.as_str();
    let operands = view.operands();
    let effects = match mnemonic {
        "fld1" => x87_push_effects(x87_const("one")),
        "fldl2t" => x87_push_effects(x87_const("l2t")),
        "fldl2e" => x87_push_effects(x87_const("l2e")),
        "fldpi" => x87_push_effects(x87_const("pi")),
        "fldlg2" => x87_push_effects(x87_const("lg2")),
        "fldln2" => x87_push_effects(x87_const("ln2")),
        "fldz" => x87_push_effects(x87_const("zero")),
        "fld" => x87_push_effects(x87_float_operand(machine, operands.first()?)?),
        "fild" => x87_push_effects(x87_int_operand(machine, operands.first()?)?),
        "fbld" => x87_push_effects(x87_bcd_operand(machine, operands.first()?)?),
        "fst" => x87_store_only(machine, operands.first()?, x87_stack_expr(0))?,
        "fstp" => x87_store_pop(machine, operands.first()?, x87_stack_expr(0))?,
        "fist" => x87_store_int(machine, operands.first()?, false, false)?,
        "fistp" => x87_store_int(machine, operands.first()?, true, false)?,
        "fisttp" => x87_store_int(machine, operands.first()?, true, true)?,
        "fbstp" => x87_store_pop(machine, operands.first()?, x87_bcd_store(x87_stack_expr(0)))?,
        "fabs" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("abs", vec![x87_stack_expr(0)]),
        }],
        "fchs" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("neg", vec![x87_stack_expr(0)]),
        }],
        "fnop" | "fnclex" => vec![SemanticEffect::Nop],
        "ffree" => vec![SemanticEffect::Set {
            dst: x87_stack_location(x87_stack_index(operands.first()?)?),
            expression: SemanticExpression::Undefined { bits: X87_BITS },
        }],
        "ffreep" => x87_pop_effects(1),
        "fcos" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("cos", vec![x87_stack_expr(0)]),
        }],
        "fsin" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("sin", vec![x87_stack_expr(0)]),
        }],
        "fsincos" => x87_push_with_replacement(
            x87_expr_intrinsic("cos", vec![x87_stack_expr(0)]),
            x87_expr_intrinsic("sin", vec![x87_stack_expr(0)]),
        ),
        "fscale" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("scale", vec![x87_stack_expr(0), x87_stack_expr(1)]),
        }],
        "fprem" => {
            x87_intrinsic_with_flag_outputs("fprem", vec![x87_stack_expr(0), x87_stack_expr(1)])
        }
        "fprem1" => {
            x87_intrinsic_with_flag_outputs("fprem1", vec![x87_stack_expr(0), x87_stack_expr(1)])
        }
        "f2xm1" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("f2xm1", vec![x87_stack_expr(0)]),
        }],
        "fptan" => x87_push_with_replacement(
            x87_const("one"),
            x87_expr_intrinsic("tan", vec![x87_stack_expr(0)]),
        ),
        "fpatan" => x87_pop_with_replacement(
            1,
            x87_expr_intrinsic("atan2", vec![x87_stack_expr(1), x87_stack_expr(0)]),
        ),
        "fsqrt" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("sqrt", vec![x87_stack_expr(0)]),
        }],
        "fxam" => x87_flag_only_intrinsic("xam", vec![x87_stack_expr(0)]),
        "ftst" => x87_compare_effects(x87_const("zero"), 0),
        "frndint" => vec![SemanticEffect::Set {
            dst: x87_stack_location(0),
            expression: x87_expr_intrinsic("rint", vec![x87_stack_expr(0)]),
        }],
        "fyl2x" => x87_pop_with_replacement(
            1,
            x87_expr_intrinsic("yl2x", vec![x87_stack_expr(1), x87_stack_expr(0)]),
        ),
        "fyl2xp1" => x87_pop_with_replacement(
            1,
            x87_expr_intrinsic("yl2xp1", vec![x87_stack_expr(1), x87_stack_expr(0)]),
        ),
        "fdecstp" => x87_rotate_top(false),
        "fincstp" => x87_rotate_top(true),
        "fxch" => x87_exchange(operands)?,
        "fninit" => x87_init_effects(),
        "fnstsw" => vec![SemanticEffect::Set {
            dst: operand_location(machine, operands.first()?)?,
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
        "fdivp" => x87_binary_pop(operands, "div", BinaryPopOrder::TargetOpSt0)?,
        "fdivrp" => x87_binary_pop(operands, "div", BinaryPopOrder::TargetOpSt0)?,
        "fcom" | "fucom" => x87_compare_effects(x87_compare_rhs(machine, operands)?, 0),
        "fcomp" | "fucomp" => x87_compare_effects(x87_compare_rhs(machine, operands)?, 1),
        "fcompp" | "fucompp" => x87_compare_effects(x87_stack_expr(1), 2),
        "fcomi" | "fucomi" => x87_compare_to_cpu_flags(x87_compare_rhs(machine, operands)?, 0),
        "fcompi" | "fcomip" | "fucompi" | "fucomip" => {
            x87_compare_to_cpu_flags(x87_compare_rhs(machine, operands)?, 1)
        }
        "fiadd" => x87_binary_int(machine, operands, "add", BinaryOrder::Normal)?,
        "fisub" => x87_binary_int(machine, operands, "sub", BinaryOrder::Normal)?,
        "fisubr" => x87_binary_int(machine, operands, "sub", BinaryOrder::Reverse)?,
        "fidiv" => x87_binary_int(machine, operands, "div", BinaryOrder::Normal)?,
        "fidivr" => x87_binary_int(machine, operands, "div", BinaryOrder::Reverse)?,
        "fimul" => {
            let rhs = x87_int_operand(machine, operands.first()?)?;
            vec![SemanticEffect::Set {
                dst: x87_stack_location(0),
                expression: x87_expr_intrinsic("mul", vec![x87_stack_expr(0), rhs]),
            }]
        }
        mnemonic if mnemonic.starts_with("fcmov") => x87_conditional_move(mnemonic, operands)?,
        _ => return None,
    };
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

fn x87_binary(
    machine: Architecture,
    operands: &[X86OperandView],
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
    operands: &[X86OperandView],
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

fn x87_binary_int(
    machine: Architecture,
    operands: &[X86OperandView],
    op: &str,
    order: BinaryOrder,
) -> Option<Vec<SemanticEffect>> {
    let rhs = x87_int_operand(machine, operands.first()?)?;
    let lhs = x87_stack_expr(0);
    let result = match order {
        BinaryOrder::Normal => x87_expr_intrinsic(op, vec![lhs, rhs]),
        BinaryOrder::Reverse => x87_expr_intrinsic(op, vec![rhs, lhs]),
    };
    Some(vec![SemanticEffect::Set {
        dst: x87_stack_location(0),
        expression: result,
    }])
}

fn x87_compare_rhs(
    machine: Architecture,
    operands: &[X86OperandView],
) -> Option<SemanticExpression> {
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

fn x87_compare_to_cpu_flags(rhs: SemanticExpression, pop_count: u8) -> Vec<SemanticEffect> {
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
        SemanticEffect::Set {
            dst: common::flag("of"),
            expression: common::bool_const(false),
        },
        SemanticEffect::Set {
            dst: common::flag("sf"),
            expression: common::bool_const(false),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: common::bool_const(false),
        },
    ];
    effects.extend(x87_pop_effects(pop_count));
    effects
}

fn x87_store_only(
    machine: Architecture,
    operand: &X86OperandView,
    value: SemanticExpression,
) -> Option<Vec<SemanticEffect>> {
    Some(vec![x87_store_effect(machine, operand, value)?])
}

fn x87_store_pop(
    machine: Architecture,
    operand: &X86OperandView,
    value: SemanticExpression,
) -> Option<Vec<SemanticEffect>> {
    if let Some(index) = x87_stack_index(operand) {
        return Some(x87_pop_with_replacement(index, value));
    }
    let mut effects = vec![x87_store_effect(machine, operand, value)?];
    effects.extend(x87_pop_effects(1));
    Some(effects)
}

fn x87_store_int(
    machine: Architecture,
    operand: &X86OperandView,
    pop: bool,
    trunc: bool,
) -> Option<Vec<SemanticEffect>> {
    if matches!(operand.kind, X86OperandKind::Register) {
        return None;
    }
    let addr = x87_memory_addr(machine, operand)?;
    let bits = x87_operand_bits(operand)?;
    let suffix = if trunc { "_trunc" } else { "" };
    let value = x87_expr_intrinsic(&format!("store_i{bits}{suffix}"), vec![x87_stack_expr(0)]);
    let mut effects = vec![SemanticEffect::Store {
        space: SemanticAddressSpace::Default,
        addr,
        expression: SemanticExpression::Extract {
            arg: Box::new(value),
            lsb: 0,
            bits,
        },
        bits,
    }];
    if pop {
        effects.extend(x87_pop_effects(1));
    }
    Some(effects)
}

fn x87_store_effect(
    machine: Architecture,
    operand: &X86OperandView,
    value: SemanticExpression,
) -> Option<SemanticEffect> {
    match operand.kind {
        X86OperandKind::Register => Some(SemanticEffect::Set {
            dst: x87_stack_location(x87_stack_index(operand)?),
            expression: value,
        }),
        _ => {
            let addr = x87_memory_addr(machine, operand)?;
            let bits = operand.size_bits;
            Some(SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: x87_store_bits(value, bits),
                bits,
            })
        }
    }
}

fn x87_exchange(operands: &[X86OperandView]) -> Option<Vec<SemanticEffect>> {
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

fn x87_push_with_replacement(
    pushed: SemanticExpression,
    replaced_st0: SemanticExpression,
) -> Vec<SemanticEffect> {
    let mut effects = Vec::new();
    for index in (2..8).rev() {
        effects.push(SemanticEffect::Set {
            dst: x87_stack_location(index),
            expression: x87_stack_expr(index - 1),
        });
    }
    effects.push(SemanticEffect::Set {
        dst: x87_stack_location(1),
        expression: replaced_st0,
    });
    effects.push(SemanticEffect::Set {
        dst: x87_stack_location(0),
        expression: pushed,
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

fn x87_rotate_top(increment: bool) -> Vec<SemanticEffect> {
    let mut effects = Vec::new();
    for index in 0..8u8 {
        let source = if increment {
            (index + 1) % 8
        } else {
            (index + 7) % 8
        };
        effects.push(SemanticEffect::Set {
            dst: x87_stack_location(index),
            expression: x87_stack_expr(source),
        });
    }
    effects.push(SemanticEffect::Set {
        dst: x87_top_location(),
        expression: if increment {
            common::add(x87_top_expr(), common::const_u64(1, 3), 3)
        } else {
            common::sub(x87_top_expr(), common::const_u64(1, 3), 3)
        },
    });
    effects
}

fn x87_float_operand(
    machine: Architecture,
    operand: &X86OperandView,
) -> Option<SemanticExpression> {
    if let Some(index) = x87_stack_index(operand) {
        return Some(x87_stack_expr(index));
    }
    let raw = operand_expr(machine, operand)?;
    let bits = x87_operand_bits(operand)?;
    Some(match bits {
        32 => x87_expr_intrinsic("load_f32", vec![raw]),
        64 => x87_expr_intrinsic("load_f64", vec![raw]),
        80 => raw,
        _ => return None,
    })
}

fn x87_int_operand(machine: Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    let raw = operand_expr(machine, operand)?;
    let bits = x87_operand_bits(operand)?;
    Some(match bits {
        16 => x87_expr_intrinsic("load_i16", vec![raw]),
        32 => x87_expr_intrinsic("load_i32", vec![raw]),
        64 => x87_expr_intrinsic("load_i64", vec![raw]),
        _ => return None,
    })
}

fn x87_bcd_operand(machine: Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    let raw = operand_expr(machine, operand)?;
    let bits = x87_operand_bits(operand)?;
    if bits != 80 {
        return None;
    }
    Some(x87_expr_intrinsic("load_bcd", vec![raw]))
}

fn x87_store_bits(value: SemanticExpression, bits: u16) -> SemanticExpression {
    match bits {
        32 => x87_expr_intrinsic("store_f32", vec![value]),
        64 => x87_expr_intrinsic("store_f64", vec![value]),
        80 => value,
        _ => SemanticExpression::Undefined { bits },
    }
}

fn x87_bcd_store(value: SemanticExpression) -> SemanticExpression {
    x87_expr_intrinsic("store_bcd", vec![value])
}

fn x87_memory_addr(machine: Architecture, operand: &X86OperandView) -> Option<SemanticExpression> {
    let location = operand_location(machine, operand)?;
    match location {
        SemanticLocation::Memory { addr, .. } => Some(*addr),
        _ => None,
    }
}

fn x87_operand_bits(operand: &X86OperandView) -> Option<u16> {
    Some(operand.size_bits)
}

fn x87_stack_index(operand: &X86OperandView) -> Option<u8> {
    let name = operand.register_name()?;
    let index = name.strip_prefix("st")?;
    index.parse::<u8>().ok().filter(|value| *value < 8)
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

fn x87_init_effects() -> Vec<SemanticEffect> {
    let mut effects = Vec::new();
    for index in 0..8u8 {
        effects.push(SemanticEffect::Set {
            dst: x87_stack_location(index),
            expression: SemanticExpression::Undefined { bits: X87_BITS },
        });
    }
    effects.push(SemanticEffect::Set {
        dst: x87_top_location(),
        expression: common::const_u64(0, 3),
    });
    for name in ["c0", "c1", "c2", "c3"] {
        effects.push(SemanticEffect::Set {
            dst: x87_flag(name),
            expression: common::bool_const(false),
        });
    }
    effects
}

fn x87_conditional_move(
    mnemonic: &str,
    operands: &[X86OperandView],
) -> Option<Vec<SemanticEffect>> {
    let suffix = mnemonic.strip_prefix("fcmov")?;
    let condition = match suffix {
        "u" => common::condition_from_mnemonic("cmovp"),
        "nu" => common::condition_from_mnemonic("cmovnp"),
        _ => common::condition_from_mnemonic(&format!("cmov{suffix}")),
    }?;
    let target_index = if operands.is_empty() {
        0
    } else {
        x87_stack_index(operands.first()?)?
    };
    let source_index = if operands.len() >= 2 {
        x87_stack_index(operands.get(1)?)?
    } else {
        1
    };
    Some(vec![SemanticEffect::Set {
        dst: x87_stack_location(target_index),
        expression: SemanticExpression::Select {
            condition: Box::new(condition),
            when_true: Box::new(x87_stack_expr(source_index)),
            when_false: Box::new(x87_stack_expr(target_index)),
            bits: X87_BITS,
        },
    }])
}

fn x87_intrinsic_with_flag_outputs(
    name: &str,
    args: Vec<SemanticExpression>,
) -> Vec<SemanticEffect> {
    vec![SemanticEffect::Intrinsic {
        name: format!("x86.x87.{name}"),
        args,
        outputs: vec![
            x87_stack_location(0),
            x87_flag("c0"),
            x87_flag("c1"),
            x87_flag("c2"),
            x87_flag("c3"),
        ],
    }]
}

fn x87_flag_only_intrinsic(name: &str, args: Vec<SemanticExpression>) -> Vec<SemanticEffect> {
    vec![SemanticEffect::Intrinsic {
        name: format!("x86.x87.{name}"),
        args,
        outputs: vec![
            x87_flag("c0"),
            x87_flag("c1"),
            x87_flag("c2"),
            x87_flag("c3"),
        ],
    }]
}
