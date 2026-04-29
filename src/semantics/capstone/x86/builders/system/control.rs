use super::*;

pub(super) fn fence(kind: SemanticFenceKind) -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Fence { kind }],
    )
}

pub(super) fn set_flag(name: &str, value: bool) -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::flag(name),
            expression: common::bool_const(value),
        }],
    )
}

pub(super) fn clts() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.clts".to_string(),
            args: Vec::new(),
            outputs: Vec::new(),
        }],
    )
}

pub(super) fn invlpg(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let addr = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.invlpg".to_string(),
            args: vec![addr],
            outputs: Vec::new(),
        }],
    ))
}

pub(super) fn lahf() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst: common::reg(common::reg_id_name(X86Reg::X86_REG_AH as u16), 8),
            expression: flags_low_byte(),
        }],
    )
}

pub(super) fn sahf() -> InstructionSemantics {
    let ah = SemanticExpression::Read(Box::new(common::reg(
        common::reg_id_name(X86Reg::X86_REG_AH as u16),
        8,
    )));
    common::complete(
        SemanticTerminator::FallThrough,
        vec![
            unpack_flag_from_byte("cf", ah.clone(), 0),
            unpack_flag_from_byte("pf", ah.clone(), 2),
            unpack_flag_from_byte("af", ah.clone(), 4),
            unpack_flag_from_byte("zf", ah.clone(), 6),
            unpack_flag_from_byte("sf", ah, 7),
        ],
    )
}

pub(super) fn lar(machine: Architecture, operands: &[ArchOperand]) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let src = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.lar".to_string(),
            args: vec![src],
            outputs: vec![dst, common::flag("zf")],
        }],
    ))
}

pub(super) fn pushf(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (bits / 8) as u64;
    let old_sp = SemanticExpression::Read(Box::new(stack_pointer.clone()));
    let new_sp = common::sub(
        old_sp,
        common::const_u64(slot_bytes, pointer_bits),
        pointer_bits,
    );
    let flags_value = flags_image(bits);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Set {
                dst: stack_pointer.clone(),
                expression: new_sp.clone(),
            },
            SemanticEffect::Store {
                space: SemanticAddressSpace::Stack,
                addr: new_sp,
                expression: flags_value,
                bits,
            },
        ],
    ))
}

pub(super) fn popf(machine: Architecture, bits: u16) -> Option<InstructionSemantics> {
    let stack_pointer = stack_pointer_location(machine);
    let pointer_bits = common::pointer_bits(machine);
    let slot_bytes = (bits / 8) as u64;
    let loaded = SemanticExpression::Load {
        space: SemanticAddressSpace::Stack,
        addr: Box::new(SemanticExpression::Read(Box::new(stack_pointer.clone()))),
        bits,
    };
    let mut effects = vec![
        unpack_flag_from_word("cf", loaded.clone(), 0),
        unpack_flag_from_word("pf", loaded.clone(), 2),
        unpack_flag_from_word("af", loaded.clone(), 4),
        unpack_flag_from_word("zf", loaded.clone(), 6),
        unpack_flag_from_word("sf", loaded.clone(), 7),
        unpack_flag_from_word("if", loaded.clone(), 9),
        unpack_flag_from_word("df", loaded.clone(), 10),
        unpack_flag_from_word("of", loaded.clone(), 11),
    ];
    effects.push(SemanticEffect::Set {
        dst: stack_pointer,
        expression: common::add(
            SemanticExpression::Read(Box::new(stack_pointer_location(machine))),
            common::const_u64(slot_bytes, pointer_bits),
            pointer_bits,
        ),
    });
    Some(common::complete(SemanticTerminator::FallThrough, effects))
}
