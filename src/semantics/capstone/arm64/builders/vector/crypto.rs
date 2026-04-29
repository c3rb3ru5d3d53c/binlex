use super::*;

pub(crate) fn build_aes_round(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let round_key = operand_expression(operands.get(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("aes")),
            args: vec![SemanticExpression::Read(Box::new(dst.clone())), round_key],
            outputs: vec![dst],
        }],
    ))
}

pub(crate) fn build_aes_mix_columns(
    machine: Architecture,
    instruction: &Insn,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name: format!("arm64.{}", instruction.mnemonic().unwrap_or("aes")),
            args: vec![src],
            outputs: vec![dst],
        }],
    ))
}
