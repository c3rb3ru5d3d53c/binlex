use super::*;

pub(super) fn insd(machine: Architecture) -> Option<InstructionSemantics> {
    let di = string_index_location(machine, true);
    let port = io_port_location();
    let addr = SemanticExpression::Read(Box::new(di.clone()));
    let port_addr = SemanticExpression::Read(Box::new(port));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: SemanticAddressSpace::Default,
                addr,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Io,
                    addr: Box::new(port_addr),
                    bits: 32,
                },
                bits: 32,
            },
            SemanticEffect::Set {
                dst: di.clone(),
                expression: next_index_value(di, 4, machine),
            },
        ],
    ))
}

pub(super) fn cpuid() -> InstructionSemantics {
    let leaf = SemanticExpression::Read(Box::new(common::reg(
        common::reg_id_name(X86Reg::X86_REG_EAX as u16),
        32,
    )));
    let subleaf = SemanticExpression::Read(Box::new(common::reg(
        common::reg_id_name(X86Reg::X86_REG_ECX as u16),
        32,
    )));

    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.cpuid".to_string(),
            args: vec![leaf, subleaf],
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EBX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
            ],
        }],
    )
}

pub(super) fn verr_verw(
    machine: Architecture,
    operands: &[ArchOperand],
    name: &str,
) -> Option<InstructionSemantics> {
    let selector = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: name.to_string(),
            args: vec![selector],
            outputs: vec![common::flag("zf")],
        }],
    ))
}

pub(super) fn outsd(machine: Architecture) -> Option<InstructionSemantics> {
    let si = string_index_location(machine, false);
    let port = io_port_location();
    let addr = SemanticExpression::Read(Box::new(si.clone()));
    let port_addr = SemanticExpression::Read(Box::new(port));
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Store {
                space: SemanticAddressSpace::Io,
                addr: port_addr,
                expression: SemanticExpression::Load {
                    space: SemanticAddressSpace::Default,
                    addr: Box::new(addr),
                    bits: 32,
                },
                bits: 32,
            },
            SemanticEffect::Set {
                dst: si.clone(),
                expression: next_index_value(si, 4, machine),
            },
        ],
    ))
}

pub(super) fn rdtsc() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.rdtsc".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
            ],
        }],
    )
}

pub(super) fn rdtscp() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.rdtscp".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_ECX as u16), 32),
            ],
        }],
    )
}

pub(super) fn random_value(
    machine: Architecture,
    name: &str,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let _bits = common::location_bits(&dst);
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![
            SemanticEffect::Intrinsic {
                name: format!("x86.{name}"),
                args: Vec::new(),
                outputs: vec![dst, common::flag("cf")],
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
                dst: common::flag("zf"),
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
        ],
    ))
}

pub(super) fn xgetbv() -> InstructionSemantics {
    common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: "x86.xgetbv".to_string(),
            args: Vec::new(),
            outputs: vec![
                common::reg(common::reg_id_name(X86Reg::X86_REG_EAX as u16), 32),
                common::reg(common::reg_id_name(X86Reg::X86_REG_EDX as u16), 32),
            ],
        }],
    )
}
