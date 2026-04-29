use super::*;

pub(in crate::semantics::capstone::arm64) fn build_effect_intrinsic(
    _instruction: &Insn,
    operands: &[ArchOperand],
    outputs: Vec<SemanticLocation>,
    name: String,
) -> Option<InstructionSemantics> {
    let args = operands
        .iter()
        .filter_map(operand_expression)
        .collect::<Vec<_>>();
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Intrinsic {
            name,
            args,
            outputs,
        }],
    ))
}
