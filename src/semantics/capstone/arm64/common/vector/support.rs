use super::*;

pub(in crate::semantics::capstone::arm64) fn build_intrinsic_fallthrough(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
    outputs: Option<Vec<SemanticLocation>>,
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    let _ = machine;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("intrinsic")),
            args,
            outputs: outputs.unwrap_or_default(),
        }],
    ))
}

pub(in crate::semantics::capstone::arm64) fn parse_vector_arrangement(
    op_str: &str,
) -> Option<(u16, u16)> {
    if op_str.contains(".16b") {
        Some((16, 8))
    } else if op_str.contains(".8b") {
        Some((8, 8))
    } else if op_str.contains(".8h") {
        Some((8, 16))
    } else if op_str.contains(".4h") {
        Some((4, 16))
    } else if op_str.contains(".4s") {
        Some((4, 32))
    } else if op_str.contains(".2s") {
        Some((2, 32))
    } else if op_str.contains(".2d") {
        Some((2, 64))
    } else {
        None
    }
}

pub(in crate::semantics::capstone::arm64) fn zero_extend_if_needed(
    expression: SemanticExpression,
    src_bits: u16,
    dst_bits: u16,
) -> SemanticExpression {
    if src_bits == dst_bits {
        expression
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits: dst_bits,
        }
    }
}

pub(in crate::semantics::capstone::arm64) fn lane_bits_from_vas(vas: Arm64Vas) -> Option<u16> {
    match vas {
        Arm64Vas::ARM64_VAS_16B
        | Arm64Vas::ARM64_VAS_8B
        | Arm64Vas::ARM64_VAS_4B
        | Arm64Vas::ARM64_VAS_1B => Some(8),
        Arm64Vas::ARM64_VAS_8H
        | Arm64Vas::ARM64_VAS_4H
        | Arm64Vas::ARM64_VAS_2H
        | Arm64Vas::ARM64_VAS_1H => Some(16),
        Arm64Vas::ARM64_VAS_4S | Arm64Vas::ARM64_VAS_2S | Arm64Vas::ARM64_VAS_1S => Some(32),
        Arm64Vas::ARM64_VAS_2D | Arm64Vas::ARM64_VAS_1D => Some(64),
        Arm64Vas::ARM64_VAS_1Q => Some(128),
        _ => None,
    }
}
