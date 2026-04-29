use super::*;

pub(super) fn imul(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    match operands.len() {
        2 | 3 => imul_explicit(machine, operands),
        1 => imul_implicit(machine, operands),
        _ => None,
    }
}

fn imul_explicit(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let bits = common::location_bits(&dst);
    let full_bits = bits.saturating_mul(2);
    let left = if operands.len() == 2 {
        operands
            .first()
            .and_then(|operand| common::operand_expr(machine, operand))?
    } else {
        operands
            .get(1)
            .and_then(|operand| common::operand_expr(machine, operand))?
    };
    let right = operands
        .last()
        .and_then(|operand| common::operand_expr(machine, operand))?;
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
                expression: common::parity_flag(common::extract_low_byte(low.clone())),
            },
            SemanticEffect::Set {
                dst: common::flag("af"),
                expression: SemanticExpression::Undefined { bits: 1 },
            },
        ],
    ))
}

fn imul_implicit(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_reg, high_reg, acc_reg, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let acc = common::reg_expr(acc_reg, bits);
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
                arg: Box::new(wide_product),
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
            arg: Box::new(wide_product),
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
        dst: common::reg(common::reg_id_name(low_reg), result_bits),
        expression: result_low,
    }];
    if bits > 8 {
        effects.push(SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(high_reg), bits),
            expression: SemanticExpression::Extract {
                arg: Box::new(SemanticExpression::Binary {
                    op: SemanticOperationBinary::Mul,
                    left: Box::new(SemanticExpression::Cast {
                        op: SemanticOperationCast::SignExtend,
                        arg: Box::new(common::reg_expr(acc_reg, bits)),
                        bits: full_bits,
                    }),
                    right: Box::new(SemanticExpression::Cast {
                        op: SemanticOperationCast::SignExtend,
                        arg: Box::new(
                            operands
                                .first()
                                .and_then(|operand| common::operand_expr(machine, operand))
                                .unwrap(),
                        ),
                        bits: full_bits,
                    }),
                    bits: full_bits,
                }),
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
            expression: common::parity_flag(common::extract_low_byte(
                SemanticExpression::Extract {
                    arg: Box::new(SemanticExpression::Binary {
                        op: SemanticOperationBinary::Mul,
                        left: Box::new(SemanticExpression::Cast {
                            op: SemanticOperationCast::SignExtend,
                            arg: Box::new(common::reg_expr(acc_reg, bits)),
                            bits: full_bits,
                        }),
                        right: Box::new(SemanticExpression::Cast {
                            op: SemanticOperationCast::SignExtend,
                            arg: Box::new(
                                operands
                                    .first()
                                    .and_then(|operand| common::operand_expr(machine, operand))
                                    .unwrap(),
                            ),
                            bits: full_bits,
                        }),
                        bits: full_bits,
                    }),
                    lsb: 0,
                    bits: result_bits,
                },
            )),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn mul(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_reg, high_reg, acc_reg, result_bits) = implicit_mul_registers(machine, bits)?;
    let full_bits = bits.saturating_mul(2);
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(common::reg_expr(acc_reg, bits)),
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
        dst: common::reg(common::reg_id_name(low_reg), result_bits),
        expression: result_low,
    }];
    if bits > 8 {
        effects.push(SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(high_reg), bits),
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
            expression: common::parity_flag(common::extract_low_byte(
                SemanticExpression::Extract {
                    arg: Box::new(wide_product.clone()),
                    lsb: 0,
                    bits: result_bits,
                },
            )),
        },
        SemanticEffect::Set {
            dst: common::flag("af"),
            expression: SemanticExpression::Undefined { bits: 1 },
        },
    ]);

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn mulx(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst_low = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let dst_high = operands
        .get(1)
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst_low);
    if common::location_bits(&dst_high) != bits || !matches!(bits, 32 | 64) {
        return None;
    }

    let implicit = match bits {
        32 => common::reg_expr(X86Reg::X86_REG_EDX as u16, 32),
        64 => common::reg_expr(X86Reg::X86_REG_RDX as u16, 64),
        _ => return None,
    };
    let full_bits = bits * 2;
    let wide_product = SemanticExpression::Binary {
        op: SemanticOperationBinary::Mul,
        left: Box::new(SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(implicit),
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

pub(super) fn div(
    machine: Architecture,
    operands: &[ArchOperand],
    signed: bool,
) -> Option<InstructionSemantics> {
    let divisor = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = operand_bits(machine, operands.first()?)?;
    let (low_reg, high_reg, acc_reg, result_bits) = implicit_mul_registers(machine, bits)?;
    let dividend = if bits == 8 {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(common::reg_expr(low_reg, result_bits)),
            bits: 16,
        }
    } else {
        SemanticExpression::Concat {
            parts: vec![
                common::reg_expr(high_reg, bits),
                common::reg_expr(acc_reg, bits),
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
    let q_reg = if bits == 8 {
        X86Reg::X86_REG_AL as u16
    } else {
        acc_reg
    };
    let r_reg = if bits == 8 {
        X86Reg::X86_REG_AH as u16
    } else {
        high_reg
    };

    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(q_reg), q_bits),
                expression: SemanticExpression::Extract {
                    arg: Box::new(quotient),
                    lsb: 0,
                    bits: q_bits,
                },
            },
            SemanticEffect::Set {
                dst: common::reg(common::reg_id_name(r_reg), r_bits),
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

fn implicit_mul_registers(machine: Architecture, bits: u16) -> Option<(u16, u16, u16, u16)> {
    match bits {
        8 => Some((
            X86Reg::X86_REG_AX as u16,
            X86Reg::X86_REG_AH as u16,
            X86Reg::X86_REG_AL as u16,
            16,
        )),
        16 => Some((
            X86Reg::X86_REG_AX as u16,
            X86Reg::X86_REG_DX as u16,
            X86Reg::X86_REG_AX as u16,
            16,
        )),
        32 => Some((
            X86Reg::X86_REG_EAX as u16,
            X86Reg::X86_REG_EDX as u16,
            X86Reg::X86_REG_EAX as u16,
            32,
        )),
        64 if machine == Architecture::AMD64 => Some((
            X86Reg::X86_REG_RAX as u16,
            X86Reg::X86_REG_RDX as u16,
            X86Reg::X86_REG_RAX as u16,
            64,
        )),
        _ => None,
    }
}

fn operand_bits(machine: Architecture, operand: &ArchOperand) -> Option<u16> {
    let location = common::operand_location(machine, operand)?;
    Some(common::location_bits(&location))
}

fn signed_extension_fill(value: SemanticExpression, bits: u16) -> SemanticExpression {
    SemanticExpression::Select {
        condition: Box::new(common::extract_bit(value, bits - 1)),
        when_true: Box::new(common::const_u64(u64::MAX, bits)),
        when_false: Box::new(common::const_u64(0, bits)),
        bits,
    }
}
