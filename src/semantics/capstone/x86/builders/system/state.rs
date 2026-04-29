use super::*;

pub(super) fn ldmxcsr(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let src = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: mxcsr_location(),
            expression: src,
        }],
    ))
}

pub(super) fn stmxcsr(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Read(Box::new(mxcsr_location())),
        }],
    ))
}

pub(super) fn fxsave(
    machine: Architecture,
    operands: &[ArchOperand],
    wide_pointers: bool,
) -> Option<InstructionSemantics> {
    let base = memory_operand_addr(machine, operands.first()?)?;
    let pointer_bits = common::pointer_bits(machine);
    let mut effects = vec![
        store_default(base.clone(), 0, pointer_bits, read_reg("x87_fcw", 16), 16),
        store_default(base.clone(), 2, pointer_bits, x87_status_word_image(), 16),
        store_default(base.clone(), 4, pointer_bits, read_reg("x87_ftw", 8), 8),
        store_default(base.clone(), 5, pointer_bits, undefined(8), 8),
        store_default(base.clone(), 6, pointer_bits, read_reg("x87_fop", 16), 16),
    ];

    if wide_pointers {
        effects.push(store_default(
            base.clone(),
            8,
            pointer_bits,
            read_reg("x87_fip", 64),
            64,
        ));
        effects.push(store_default(
            base.clone(),
            16,
            pointer_bits,
            read_reg("x87_fdp", 64),
            64,
        ));
    } else {
        effects.push(store_default(
            base.clone(),
            8,
            pointer_bits,
            read_reg("x87_fip", 32),
            32,
        ));
        effects.push(store_default(
            base.clone(),
            12,
            pointer_bits,
            read_reg("x87_fcs", 16),
            16,
        ));
        effects.push(store_default(
            base.clone(),
            14,
            pointer_bits,
            undefined(16),
            16,
        ));
        effects.push(store_default(
            base.clone(),
            16,
            pointer_bits,
            read_reg("x87_fdp", 32),
            32,
        ));
        effects.push(store_default(
            base.clone(),
            20,
            pointer_bits,
            read_reg("x87_fds", 16),
            16,
        ));
        effects.push(store_default(
            base.clone(),
            22,
            pointer_bits,
            undefined(16),
            16,
        ));
    }

    effects.push(store_default(
        base.clone(),
        24,
        pointer_bits,
        SemanticExpression::Read(Box::new(mxcsr_location())),
        32,
    ));
    effects.push(store_default(
        base.clone(),
        28,
        pointer_bits,
        read_reg("mxcsr_mask", 32),
        32,
    ));

    for index in 0..8u64 {
        let offset = 32 + index * 16;
        effects.push(store_default(
            base.clone(),
            offset,
            pointer_bits,
            read_reg(&format!("x87_st{index}"), 80),
            80,
        ));
        effects.push(store_default(
            base.clone(),
            offset + 10,
            pointer_bits,
            undefined(48),
            48,
        ));
    }

    let xmm_count = if matches!(machine, Architecture::AMD64) {
        16
    } else {
        8
    };
    for index in 0..xmm_count {
        effects.push(store_default(
            base.clone(),
            160 + (index as u64) * 16,
            pointer_bits,
            read_reg(
                &common::reg_id_name(X86Reg::X86_REG_XMM0 as u16 + index as u16),
                128,
            ),
            128,
        ));
    }

    let used_tail = 160 + (xmm_count as u64) * 16;
    for offset in (used_tail..512).step_by(16) {
        let bits = ((512 - offset).min(16) * 8) as u16;
        effects.push(store_default(
            base.clone(),
            offset,
            pointer_bits,
            undefined(bits),
            bits,
        ));
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}

pub(super) fn fxrstor(
    machine: Architecture,
    operands: &[ArchOperand],
    wide_pointers: bool,
) -> Option<InstructionSemantics> {
    let base = memory_operand_addr(machine, operands.first()?)?;
    let pointer_bits = common::pointer_bits(machine);
    let fsw = load_default(base.clone(), 2, pointer_bits, 16);
    let mut effects = vec![
        set_reg(
            "x87_fcw",
            16,
            load_default(base.clone(), 0, pointer_bits, 16),
        ),
        set_reg("x87_ftw", 8, load_default(base.clone(), 4, pointer_bits, 8)),
        set_reg(
            "x87_fop",
            16,
            load_default(base.clone(), 6, pointer_bits, 16),
        ),
        set_reg(
            "mxcsr_mask",
            32,
            load_default(base.clone(), 28, pointer_bits, 32),
        ),
        SemanticEffect::Set {
            dst: mxcsr_location(),
            expression: load_default(base.clone(), 24, pointer_bits, 32),
        },
        unpack_flag_from_word("x87_c0", fsw.clone(), 8),
        unpack_flag_from_word("x87_c1", fsw.clone(), 9),
        unpack_flag_from_word("x87_c2", fsw.clone(), 10),
        SemanticEffect::Set {
            dst: read_reg_location("x87_top", 3),
            expression: SemanticExpression::Extract {
                arg: Box::new(SemanticExpression::Binary {
                    op: SemanticOperationBinary::LShr,
                    left: Box::new(fsw.clone()),
                    right: Box::new(common::const_u64(11, 16)),
                    bits: 16,
                }),
                lsb: 0,
                bits: 3,
            },
        },
        unpack_flag_from_word("x87_c3", fsw, 14),
    ];

    if wide_pointers {
        effects.push(set_reg(
            "x87_fip",
            64,
            load_default(base.clone(), 8, pointer_bits, 64),
        ));
        effects.push(set_reg(
            "x87_fdp",
            64,
            load_default(base.clone(), 16, pointer_bits, 64),
        ));
    } else {
        effects.push(set_reg(
            "x87_fip",
            32,
            load_default(base.clone(), 8, pointer_bits, 32),
        ));
        effects.push(set_reg(
            "x87_fcs",
            16,
            load_default(base.clone(), 12, pointer_bits, 16),
        ));
        effects.push(set_reg(
            "x87_fdp",
            32,
            load_default(base.clone(), 16, pointer_bits, 32),
        ));
        effects.push(set_reg(
            "x87_fds",
            16,
            load_default(base.clone(), 20, pointer_bits, 16),
        ));
    }

    for index in 0..8u64 {
        let st = load_default(base.clone(), 32 + index * 16, pointer_bits, 80);
        let mm = SemanticExpression::Extract {
            arg: Box::new(st.clone()),
            lsb: 0,
            bits: 64,
        };
        effects.push(set_reg(&format!("x87_st{index}"), 80, st));
        effects.push(set_reg(
            &common::reg_id_name(X86Reg::X86_REG_MM0 as u16 + index as u16),
            64,
            mm,
        ));
    }

    let xmm_count = if matches!(machine, Architecture::AMD64) {
        16
    } else {
        8
    };
    for index in 0..xmm_count {
        effects.push(set_reg(
            &common::reg_id_name(X86Reg::X86_REG_XMM0 as u16 + index as u16),
            128,
            load_default(base.clone(), 160 + (index as u64) * 16, pointer_bits, 128),
        ));
    }

    Some(common::complete(SemanticTerminator::FallThrough, effects))
}
