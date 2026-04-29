use super::*;

pub(crate) fn zero_extend_load(
    addr: SemanticExpression,
    load_bits: u16,
    dst_bits: u16,
) -> SemanticExpression {
    let load = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(addr),
        bits: load_bits,
    };
    if load_bits == dst_bits {
        load
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(load),
            bits: dst_bits,
        }
    }
}

pub(crate) fn sign_extend_load(
    addr: SemanticExpression,
    load_bits: u16,
    dst_bits: u16,
) -> SemanticExpression {
    let load = SemanticExpression::Load {
        space: SemanticAddressSpace::Default,
        addr: Box::new(addr),
        bits: load_bits,
    };
    if load_bits == dst_bits {
        load
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(load),
            bits: dst_bits,
        }
    }
}

pub(crate) fn zero_extend_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(crate) fn parse_move_wide_immediate<'a, I>(operands: I, bits: u16) -> Option<(u64, u16)>
where
    I: IntoIterator<Item = &'a ArchOperand>,
{
    let mut immediate = None;
    let mut shift = 0u16;
    for operand in operands {
        let ArchOperand::Arm64Operand(op) = operand else {
            continue;
        };
        match op.op_type {
            Arm64OperandType::Imm(imm) | Arm64OperandType::Cimm(imm) => {
                if immediate.is_none() {
                    immediate = Some(imm as u64);
                    if let Arm64Shift::Lsl(value) = op.shift {
                        shift = value as u16;
                    }
                } else {
                    shift = imm as u16;
                }
            }
            _ => {}
        }
    }
    let immediate = immediate?;
    Some((immediate & bitmask(bits), shift))
}

pub(crate) fn reverse_bytes_in_chunks(
    src: SemanticExpression,
    bits: u16,
    chunk_bits: u16,
) -> Option<SemanticExpression> {
    if bits == 0 || chunk_bits == 0 || bits % chunk_bits != 0 || chunk_bits % 8 != 0 {
        return None;
    }
    let bytes_per_chunk = chunk_bits / 8;
    let chunk_count = bits / chunk_bits;
    let mut parts = Vec::with_capacity(bits as usize / 8);
    for chunk in (0..chunk_count).rev() {
        let base_byte = chunk * bytes_per_chunk;
        for byte in 0..bytes_per_chunk {
            parts.push(SemanticExpression::Extract {
                arg: Box::new(src.clone()),
                lsb: (base_byte + byte) * 8,
                bits: 8,
            });
        }
    }
    Some(SemanticExpression::Concat { parts, bits })
}

pub(crate) fn sign_extend_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::SignExtend,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub(crate) fn truncate_to_bits(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    if expression.bits() == bits {
        expression
    } else {
        SemanticExpression::Extract {
            arg: Box::new(expression),
            lsb: 0,
            bits,
        }
    }
}

pub(crate) fn pointer_bits(_machine: Architecture) -> u16 {
    64
}

pub(crate) fn location_bits(location: &SemanticLocation) -> u16 {
    match location {
        SemanticLocation::Register { bits, .. }
        | SemanticLocation::Flag { bits, .. }
        | SemanticLocation::ProgramCounter { bits }
        | SemanticLocation::Temporary { bits, .. }
        | SemanticLocation::Memory { bits, .. } => *bits,
    }
}

pub(crate) fn register_bits(reg: RegId) -> u16 {
    match reg.0 as u32 {
        id if id == Arm64Reg::ARM64_REG_WSP || id == Arm64Reg::ARM64_REG_WZR => 32,
        id if (Arm64Reg::ARM64_REG_W0..=Arm64Reg::ARM64_REG_W30).contains(&id) => 32,
        id if id == Arm64Reg::ARM64_REG_SP
            || id == Arm64Reg::ARM64_REG_FP
            || id == Arm64Reg::ARM64_REG_LR
            || id == Arm64Reg::ARM64_REG_XZR =>
        {
            64
        }
        id if (Arm64Reg::ARM64_REG_X0..=Arm64Reg::ARM64_REG_X28).contains(&id) => 64,
        id if (Arm64Reg::ARM64_REG_B0..=Arm64Reg::ARM64_REG_B31).contains(&id) => 8,
        id if (Arm64Reg::ARM64_REG_H0..=Arm64Reg::ARM64_REG_H31).contains(&id) => 16,
        id if (Arm64Reg::ARM64_REG_S0..=Arm64Reg::ARM64_REG_S31).contains(&id) => 32,
        id if (Arm64Reg::ARM64_REG_D0..=Arm64Reg::ARM64_REG_D31).contains(&id) => 64,
        id if (Arm64Reg::ARM64_REG_Q0..=Arm64Reg::ARM64_REG_Q31).contains(&id) => 128,
        id if (Arm64Reg::ARM64_REG_V0..=Arm64Reg::ARM64_REG_V31).contains(&id) => 128,
        _ => 64,
    }
}

pub(crate) fn reg_location(reg: RegId, bits: u16) -> SemanticLocation {
    SemanticLocation::Register {
        name: format!("reg_{}", reg.0),
        bits,
    }
}

pub(crate) fn reg_expr(reg: RegId, bits: u16) -> SemanticExpression {
    SemanticExpression::Read(Box::new(reg_location(reg, bits)))
}

pub(crate) fn flag(name: &str) -> SemanticLocation {
    SemanticLocation::Flag {
        name: name.to_string(),
        bits: 1,
    }
}

pub(crate) fn flag_expr(name: &str) -> SemanticExpression {
    SemanticExpression::Read(Box::new(flag(name)))
}

pub(crate) fn set_flag(name: &str, expression: SemanticExpression) -> SemanticEffect {
    SemanticEffect::Set {
        dst: flag(name),
        expression,
    }
}

pub(crate) fn const_u64(value: u64, bits: u16) -> SemanticExpression {
    let masked = if bits >= 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    };
    SemanticExpression::Const {
        value: masked as u128,
        bits,
    }
}

pub(crate) fn bitmask(bits: u16) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

pub(crate) fn bool_const(value: bool) -> SemanticExpression {
    const_u64(value as u64, 1)
}

pub(crate) fn binary(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    bits: u16,
) -> SemanticExpression {
    SemanticExpression::Binary {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits,
    }
}

pub(crate) fn compare(
    op: SemanticOperationCompare,
    left: SemanticExpression,
    right: SemanticExpression,
) -> SemanticExpression {
    SemanticExpression::Compare {
        op,
        left: Box::new(left),
        right: Box::new(right),
        bits: 1,
    }
}

pub(crate) fn unary_not(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(crate) fn sign_bit(arg: SemanticExpression) -> SemanticExpression {
    SemanticExpression::Extract {
        lsb: arg.bits() - 1,
        arg: Box::new(arg),
        bits: 1,
    }
}

pub(crate) fn complete(
    terminator: SemanticTerminator,
    effects: Vec<SemanticEffect>,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Complete,
        abi: None,
        encoding: None,
        temporaries: Vec::new(),
        effects,
        terminator,
        diagnostics: Vec::new(),
    }
}

pub(crate) fn unsupported_fallthrough(
    machine: Architecture,
    instruction: &Insn,
    message: &str,
) -> InstructionSemantics {
    InstructionSemantics {
        version: 1,
        status: SemanticStatus::Partial,
        abi: None,
        encoding: Some(instruction_encoding(machine, instruction)),
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: SemanticTerminator::FallThrough,
        diagnostics: vec![diagnostic(
            SemanticDiagnosticKind::UnsupportedInstruction,
            format!(
                "0x{:x}: {} ({})",
                instruction.address(),
                message,
                instruction.mnemonic().unwrap_or("unknown")
            ),
        )],
    }
}

pub(crate) fn instruction_encoding(
    machine: Architecture,
    instruction: &Insn,
) -> InstructionEncoding {
    let mnemonic = instruction.mnemonic().unwrap_or("unknown").to_string();
    let disassembly = match instruction.op_str() {
        Some(op_str) if !op_str.is_empty() => format!("{mnemonic} {op_str}"),
        _ => mnemonic.clone(),
    };
    InstructionEncoding {
        architecture: machine.to_string(),
        mnemonic,
        disassembly,
        address: instruction.address(),
        bytes: instruction.bytes().to_vec(),
    }
}

pub(crate) fn diagnostic(
    kind: SemanticDiagnosticKind,
    message: impl Into<String>,
) -> SemanticDiagnostic {
    SemanticDiagnostic {
        kind,
        message: message.into(),
    }
}
