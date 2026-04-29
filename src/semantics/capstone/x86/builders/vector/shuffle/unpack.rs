use super::*;

pub(in crate::semantics::capstone::x86::builders::vector) fn unpack(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .first()
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let (lane_bits, high_half) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_UNPCKLPD as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKHPD as u32 => (64, true),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKLPS as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_UNPCKHPS as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLBW as u32 => (8, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLWD as u32 => (16, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLDQ as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKLQDQ as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHBW as u32 => (8, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHWD as u32 => (16, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHDQ as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_PUNPCKHQDQ as u32 => (64, true),
        _ => return None,
    };
    let expression = if bits == 256 {
        SemanticExpression::Concat {
            parts: vec![
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 128, 128),
                    &extract_range(&right, 128, 128),
                    high_half,
                )?,
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 0, 128),
                    &extract_range(&right, 0, 128),
                    high_half,
                )?,
            ],
            bits,
        }
    } else {
        interleave_lanes(bits, lane_bits, &left, &right, high_half)?
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}

pub(in crate::semantics::capstone::x86::builders::vector) fn avx_unpack(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operands
        .first()
        .and_then(|operand| common::operand_location(machine, operand))?;
    let left = operands
        .get(1)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let right = operands
        .get(2)
        .and_then(|operand| common::operand_expr(machine, operand))?;
    let bits = common::location_bits(&dst);
    let (lane_bits, high_half) = match instruction.id() {
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLBW as u32 => (8, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLWD as u32 => (16, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLDQ as u32 => (32, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKLQDQ as u32 => (64, false),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHBW as u32 => (8, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHWD as u32 => (16, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHDQ as u32 => (32, true),
        InsnId(id) if id == X86Insn::X86_INS_VPUNPCKHQDQ as u32 => (64, true),
        _ => return None,
    };
    let expression = if bits == 256 {
        SemanticExpression::Concat {
            parts: vec![
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 128, 128),
                    &extract_range(&right, 128, 128),
                    high_half,
                )?,
                interleave_lanes(
                    128,
                    lane_bits,
                    &extract_range(&left, 0, 128),
                    &extract_range(&right, 0, 128),
                    high_half,
                )?,
            ],
            bits,
        }
    } else {
        interleave_lanes(bits, lane_bits, &left, &right, high_half)?
    };
    Some(common::complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set { dst, expression }],
    ))
}
