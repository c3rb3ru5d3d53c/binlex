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

use crate::semantics::architectures::arm64::Arm64InstructionView;
use crate::semantics::architectures::arm64::{Arm64OperandKind, Arm64OperandView};
use crate::semantics::architectures::arm64::helpers::{
    arithmetic_flag_effects, arithmetic_flag_values, binary, bitmask, bool_const, compare,
    complete, condition_from_cc, const_u64, flag, flag_expr, location_bits,
    reverse_bytes_in_chunks, set_flag, sign_bit, truncate_to_bits, zero_extend_to_bits,
};
use crate::semantics::{
    InstructionSemantics, SemanticEffect, SemanticExpression, SemanticLocation,
    SemanticOperationBinary, SemanticOperationCast, SemanticOperationCompare,
    SemanticOperationUnary, SemanticTerminator,
};

pub(crate) fn build(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    match view.mnemonic.as_str() {
        "mov" | "adr" | "adrp" => build_move(view),
        "movk" => build_movk(view),
        "movz" => build_movz(view),
        "movn" => build_movn(view),
        "add" => build_binary_assign(view, SemanticOperationBinary::Add, false),
        "adds" => build_binary_assign(view, SemanticOperationBinary::Add, true),
        "sub" => build_binary_assign(view, SemanticOperationBinary::Sub, false),
        "subs" => build_binary_assign(view, SemanticOperationBinary::Sub, true),
        "and" => build_binary_assign(view, SemanticOperationBinary::And, false),
        "ands" => build_binary_assign(view, SemanticOperationBinary::And, true),
        "orr" => build_binary_assign(view, SemanticOperationBinary::Or, false),
        "eor" => build_binary_assign(view, SemanticOperationBinary::Xor, false),
        "adc" => build_adc(view, false),
        "adcs" => build_adc(view, true),
        "sbc" => build_sbc(view),
        "lsl" => build_shift_assign(view, SemanticOperationBinary::Shl),
        "lsr" => build_shift_assign(view, SemanticOperationBinary::LShr),
        "asr" | "asrv" => build_shift_assign(view, SemanticOperationBinary::AShr),
        "ror" => build_shift_assign(view, SemanticOperationBinary::RotateRight),
        "cmp" => build_compare_flags(view),
        "cmn" => build_compare_add_flags(view),
        "tst" => build_test_flags(view),
        "sxtw" => build_sign_extend_word(view),
        "sxtb" => build_sign_extend_byte(view),
        "sxth" => build_sign_extend_halfword(view),
        "uxtb" => build_zero_extend_byte(view),
        "uxth" => build_zero_extend_halfword(view),
        "abs" => build_abs(view),
        "clz" => build_clz(view),
        "eon" => build_eon(view),
        "orn" => build_orn(view),
        "bic" => build_bic(view),
        "bics" => build_bics(view),
        "mvn" => build_mvn(view),
        "neg" => build_neg(view),
        "rbit" => build_rbit(view),
        "rev" => build_rev(view),
        "rev16" => build_rev16(view),
        "rev32" => build_rev32(view),
        "csel" | "fcsel" => build_conditional_select(view),
        "cset" => build_cset(view),
        "csetm" => build_csetm(view),
        "csinc" => build_conditional_select_increment(view),
        "cinc" => build_conditional_increment(view),
        "cinv" => build_conditional_invert(view),
        "csinv" => build_conditional_select_invert(view),
        "csneg" => build_conditional_select_negate(view),
        "cneg" => build_conditional_negate(view),
        "ccmp" => build_conditional_compare(view, SemanticOperationBinary::Sub),
        "ccmn" => build_conditional_compare(view, SemanticOperationBinary::Add),
        "ubfx" => build_unsigned_bitfield_extract(view),
        "sbfx" => build_signed_bitfield_extract(view),
        "ubfiz" => build_unsigned_bitfield_insert(view),
        "sbfiz" => build_signed_bitfield_insert(view),
        "bfi" => build_bitfield_insert(view),
        "bfxil" => build_bitfield_insert_low(view),
        _ => None,
    }
}

fn build_move(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: src,
        }],
    ))
}

fn build_movk(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let (immediate, shift) = parse_move_wide_immediate(view, bits)?;
    let field_mask = if shift >= bits {
        0
    } else {
        ((0xffffu64) << shift) & bitmask(bits)
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!field_mask) & bitmask(bits), bits),
        bits,
    );
    let inserted = binary(
        SemanticOperationBinary::Shl,
        const_u64(immediate & 0xffff, bits),
        const_u64(shift as u64, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, cleared, inserted, bits),
        }],
    ))
}

fn build_movz(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let (immediate, shift) = parse_move_wide_immediate(view, bits)?;
    let expression = binary(
        SemanticOperationBinary::Shl,
        const_u64(immediate & 0xffff, bits),
        const_u64(shift as u64, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_movn(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let (immediate, shift) = parse_move_wide_immediate(view, bits)?;
    let inserted = binary(
        SemanticOperationBinary::Shl,
        const_u64(immediate & 0xffff, bits),
        const_u64(shift as u64, bits),
        bits,
    );
    let expression = binary(
        SemanticOperationBinary::Xor,
        inserted,
        const_u64(bitmask(bits), bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_binary_assign(
    view: &Arm64InstructionView,
    op: SemanticOperationBinary,
    update_flags: bool,
) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let result = binary(op, left.clone(), right.clone(), bits);

    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: result.clone(),
    }];

    if update_flags {
        effects.extend(arithmetic_flag_effects(op, left, right, result));
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_adc(view: &Arm64InstructionView, update_flags: bool) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let carry = zero_extend_to_bits(flag_expr("c"), bits);
    let right_with_carry = binary(SemanticOperationBinary::Add, right, carry, bits);
    let expression = binary(
        SemanticOperationBinary::Add,
        left.clone(),
        right_with_carry.clone(),
        bits,
    );

    let mut effects = vec![SemanticEffect::Set {
        dst: dst.clone(),
        expression: expression.clone(),
    }];

    if update_flags {
        effects.extend(arithmetic_flag_effects(
            SemanticOperationBinary::Add,
            left,
            right_with_carry,
            expression,
        ));
    }

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_sbc(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let borrow = binary(
        SemanticOperationBinary::Sub,
        const_u64(1, bits),
        zero_extend_to_bits(flag_expr("c"), bits),
        bits,
    );
    let expression = binary(
        SemanticOperationBinary::Sub,
        binary(SemanticOperationBinary::Sub, left, right, bits),
        borrow,
        bits,
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_shift_assign(
    view: &Arm64InstructionView,
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let amount = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(op, src, amount, bits),
        }],
    ))
}

fn build_compare_flags(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let left = operand_expression(view.operand(0)?)?;
    let right = operand_expression(view.operand(1)?)?;
    let result = binary(
        SemanticOperationBinary::Sub,
        left.clone(),
        right.clone(),
        left.bits(),
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        arithmetic_flag_effects(SemanticOperationBinary::Sub, left, right, result),
    ))
}

fn build_compare_add_flags(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let left = operand_expression(view.operand(0)?)?;
    let right = operand_expression(view.operand(1)?)?;
    let result = binary(
        SemanticOperationBinary::Add,
        left.clone(),
        right.clone(),
        left.bits(),
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        arithmetic_flag_effects(SemanticOperationBinary::Add, left, right, result),
    ))
}

fn build_test_flags(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let left = operand_expression(view.operand(0)?)?;
    let right = operand_expression(view.operand(1)?)?;
    let bits = left.bits();
    let result = binary(SemanticOperationBinary::And, left, right, bits);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            set_flag("n", sign_bit(result.clone())),
            set_flag(
                "z",
                compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
            ),
            set_flag("c", bool_const(false)),
            set_flag("v", bool_const(false)),
        ],
    ))
}

fn build_abs(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    let zero = const_u64(0, bits);
    let negative = binary(
        SemanticOperationBinary::Sub,
        zero.clone(),
        src.clone(),
        bits,
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(sign_bit(src.clone())),
                when_true: Box::new(negative),
                when_false: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_clz(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::CountLeadingZeros,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_eon(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Xor,
                left,
                binary(
                    SemanticOperationBinary::Xor,
                    right,
                    const_u64(bitmask(bits), bits),
                    bits,
                ),
                bits,
            ),
        }],
    ))
}

fn build_orn(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, left, not_right, bits),
        }],
    ))
}

fn build_bic(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::And, left, not_right, bits),
        }],
    ))
}

fn build_bics(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let left = operand_expression(view.operand(1)?)?;
    let right = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let not_right = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(right),
        bits,
    };
    let result = binary(SemanticOperationBinary::And, left, not_right, bits);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst,
                expression: result.clone(),
            },
            set_flag("n", sign_bit(result.clone())),
            set_flag(
                "z",
                compare(SemanticOperationCompare::Eq, result, const_u64(0, bits)),
            ),
            set_flag("c", bool_const(false)),
            set_flag("v", bool_const(false)),
        ],
    ))
}

fn build_mvn(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::Not,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_neg(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Sub, const_u64(0, bits), src, bits),
        }],
    ))
}

fn build_rbit(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::BitReverse,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_rev(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Unary {
                op: SemanticOperationUnary::ByteSwap,
                arg: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_rev16(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    let expression = reverse_bytes_in_chunks(src, bits, 16)?;

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_rev32(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    let expression = reverse_bytes_in_chunks(src, bits, 32)?;

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

fn build_conditional_select(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let when_true = operand_expression(view.operand(1)?)?;
    let when_false = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 3)?;

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

fn build_cset(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 1)?;

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(const_u64(1, bits)),
                when_false: Box::new(const_u64(0, bits)),
                bits,
            },
        }],
    ))
}

fn build_csetm(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 1)?;

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(const_u64(bitmask(bits), bits)),
                when_false: Box::new(const_u64(0, bits)),
                bits,
            },
        }],
    ))
}

fn build_conditional_select_increment(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let when_true = operand_expression(view.operand(1)?)?;
    let base_false = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 3)?;
    let when_false = binary(
        SemanticOperationBinary::Add,
        base_false,
        const_u64(1, bits),
        bits,
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

fn build_conditional_increment(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let base = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 2)?;
    let incremented = binary(
        SemanticOperationBinary::Add,
        base.clone(),
        const_u64(1, bits),
        bits,
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(incremented),
                when_false: Box::new(base),
                bits,
            },
        }],
    ))
}

fn build_conditional_invert(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let base = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 2)?;
    let inverted = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(base.clone()),
        bits,
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(inverted),
                when_false: Box::new(base),
                bits,
            },
        }],
    ))
}

fn build_conditional_select_invert(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let when_true = operand_expression(view.operand(1)?)?;
    let false_src = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 3)?;
    let when_false = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(false_src),
        bits,
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

fn build_conditional_negate(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 2)?;
    let negated = binary(
        SemanticOperationBinary::Sub,
        const_u64(0, bits),
        src.clone(),
        bits,
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(negated),
                when_false: Box::new(src),
                bits,
            },
        }],
    ))
}

fn build_conditional_select_negate(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let when_true = operand_expression(view.operand(1)?)?;
    let false_src = operand_expression(view.operand(2)?)?;
    let bits = location_bits(&dst);
    let condition = condition_operand(view, 3)?;
    let when_false = binary(
        SemanticOperationBinary::Sub,
        const_u64(0, bits),
        false_src,
        bits,
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Select {
                condition: Box::new(condition),
                when_true: Box::new(when_true),
                when_false: Box::new(when_false),
                bits,
            },
        }],
    ))
}

fn build_conditional_compare(
    view: &Arm64InstructionView,
    op: SemanticOperationBinary,
) -> Option<InstructionSemantics> {
    let left = operand_expression(view.operand(0)?)?;
    let right = operand_expression(view.operand(1)?)?;
    let fallback_nzcv = view.operand(2)?.immediate_value()? as u64;
    let condition = condition_operand(view, 3)?;
    let result = binary(op, left.clone(), right.clone(), left.bits());
    let compare_flags = arithmetic_flag_values(op, left, right, result);
    let fallback_flags = [
        ((fallback_nzcv >> 3) & 1) != 0,
        ((fallback_nzcv >> 2) & 1) != 0,
        ((fallback_nzcv >> 1) & 1) != 0,
        (fallback_nzcv & 1) != 0,
    ];
    let flag_names = ["n", "z", "c", "v"];
    let effects = flag_names
        .into_iter()
        .zip(compare_flags)
        .zip(fallback_flags)
        .map(|((name, compare_value), fallback_value)| SemanticEffect::Set {
            dst: flag(name),
            expression: SemanticExpression::Select {
                condition: Box::new(condition.clone()),
                when_true: Box::new(compare_value),
                when_false: Box::new(bool_const(fallback_value)),
                bits: 1,
            },
        })
        .collect();

    Some(complete(SemanticTerminator::FallThrough, effects))
}

fn build_unsigned_bitfield_extract(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let lsb = view.operand(2)?.immediate_value()? as u16;
    let width = view.operand(3)?.immediate_value()? as u16;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::ZeroExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb,
                    bits: width,
                }),
                bits,
            },
        }],
    ))
}

fn build_signed_bitfield_extract(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let lsb = view.operand(2)?.immediate_value()? as u16;
    let width = view.operand(3)?.immediate_value()? as u16;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb,
                    bits: width,
                }),
                bits,
            },
        }],
    ))
}

fn build_unsigned_bitfield_insert(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let lsb = view.operand(2)?.immediate_value()? as u16;
    let width = view.operand(3)?.immediate_value()? as u16;
    let bits = location_bits(&dst);
    let extracted = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: width,
    };
    let extended = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(extracted),
        bits,
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Shl,
                extended,
                const_u64(lsb as u64, bits),
                bits,
            ),
        }],
    ))
}

fn build_signed_bitfield_insert(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let lsb = view.operand(2)?.immediate_value()? as u16;
    let width = view.operand(3)?.immediate_value()? as u16;
    let bits = location_bits(&dst);
    let extracted = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: width,
    };
    let extended = SemanticExpression::Cast {
        op: SemanticOperationCast::SignExtend,
        arg: Box::new(extracted),
        bits,
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Shl,
                extended,
                const_u64(lsb as u64, bits),
                bits,
            ),
        }],
    ))
}

fn build_bitfield_insert(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(view.operand(1)?)?;
    let lsb = view.operand(2)?.immediate_value()? as u16;
    let width = view.operand(3)?.immediate_value()? as u16;
    let bits = location_bits(&dst);
    let field_mask = if width == 0 || lsb >= bits {
        0
    } else {
        ((((1u128 << width.min(64)) - 1) as u64) << lsb) & bitmask(bits)
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!field_mask) & bitmask(bits), bits),
        bits,
    );
    let inserted = binary(
        SemanticOperationBinary::Shl,
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src),
                lsb: 0,
                bits: width,
            }),
            bits,
        },
        const_u64(lsb as u64, bits),
        bits,
    );

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, cleared, inserted, bits),
        }],
    ))
}

fn build_bitfield_insert_low(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(view.operand(1)?)?;
    let lsb = view.operand(2)?.immediate_value()? as u16;
    let width = view.operand(3)?.immediate_value()? as u16;
    let bits = location_bits(&dst);
    let mask = if width == 0 {
        0
    } else {
        ((1u128 << width.min(64)) - 1) as u64
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!mask) & bitmask(bits), bits),
        bits,
    );
    let shifted_src = binary(
        SemanticOperationBinary::LShr,
        src,
        const_u64(lsb as u64, bits),
        bits,
    );
    let extracted = SemanticExpression::Extract {
        arg: Box::new(shifted_src),
        lsb: 0,
        bits: width,
    };
    let inserted = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(extracted),
        bits,
    };

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, cleared, inserted, bits),
        }],
    ))
}

fn build_sign_extend_word(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 32)),
                bits,
            },
        }],
    ))
}

fn build_sign_extend_byte(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 8)),
                bits,
            },
        }],
    ))
}

fn build_sign_extend_halfword(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(truncate_to_bits(src, 16)),
                bits,
            },
        }],
    ))
}

fn build_zero_extend_byte(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: zero_extend_to_bits(truncate_to_bits(src, 8), bits),
        }],
    ))
}

fn build_zero_extend_halfword(view: &Arm64InstructionView) -> Option<InstructionSemantics> {
    let dst = register_location(view.operand(0)?)?;
    let src = operand_expression(view.operand(1)?)?;
    let bits = location_bits(&dst);

    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: zero_extend_to_bits(truncate_to_bits(src, 16), bits),
        }],
    ))
}

fn register_location(operand: &Arm64OperandView) -> Option<SemanticLocation> {
    if operand.kind != Arm64OperandKind::Register {
        return None;
    }
    Some(SemanticLocation::Register {
        name: operand.register_name()?.to_string(),
        bits: operand_bits(operand),
    })
}

fn operand_expression(operand: &Arm64OperandView) -> Option<SemanticExpression> {
    match operand.kind {
        Arm64OperandKind::Register => Some(SemanticExpression::Read(Box::new(
            SemanticLocation::Register {
                name: operand.register_name()?.to_string(),
                bits: operand_bits(operand),
            },
        ))),
        Arm64OperandKind::Immediate => Some(const_u64(
            operand.immediate_value()? as i64 as u64,
            operand_bits(operand),
        )),
        _ => None,
    }
}

fn operand_bits(operand: &Arm64OperandView) -> u16 {
    if operand.size_bits == 0 {
        64
    } else {
        operand.size_bits
    }
}

fn parse_move_wide_immediate(view: &Arm64InstructionView, bits: u16) -> Option<(u64, u16)> {
    let mut immediate = None;
    let mut shift = 0u16;

    for operand in view.operands().iter().skip(1) {
        if operand.kind != Arm64OperandKind::Immediate {
            continue;
        }
        let value = operand.immediate_value()? as u64;
        if immediate.is_none() {
            immediate = Some(value);
            if let Some(amount) = operand.shift_amount() {
                shift = amount as u16;
            }
        } else {
            shift = value as u16;
        }
    }

    Some((immediate? & bitmask(bits), shift))
}

fn condition_operand(view: &Arm64InstructionView, index: usize) -> Option<SemanticExpression> {
    let cc = view
        .operand(index)
        .and_then(Arm64OperandView::immediate_value)
        .map(|value| value as u64)
        .or(view.condition_code)?;
    condition_from_cc(cc)
}
