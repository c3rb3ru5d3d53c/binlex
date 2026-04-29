use super::*;
use crate::semantics::SemanticOperationUnary;

pub(crate) fn build_bcax(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let vn = operand_expression(operands.get(1)?)?;
    let vm = operand_expression(operands.get(2)?)?;
    let va = operand_expression(operands.get(3)?)?;
    let not_va = SemanticExpression::Unary {
        op: SemanticOperationUnary::Not,
        arg: Box::new(va),
        bits,
    };
    let result = binary(
        SemanticOperationBinary::Xor,
        vn,
        binary(SemanticOperationBinary::And, vm, not_va, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

pub(crate) fn build_bsl(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let mask = SemanticExpression::Read(Box::new(dst.clone()));
    let vn = operand_expression(operands.get(1)?)?;
    let vm = operand_expression(operands.get(2)?)?;
    let result = binary(
        SemanticOperationBinary::Or,
        binary(SemanticOperationBinary::And, mask.clone(), vn, bits),
        binary(
            SemanticOperationBinary::And,
            SemanticExpression::Unary {
                op: SemanticOperationUnary::Not,
                arg: Box::new(mask),
                bits,
            },
            vm,
            bits,
        ),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}

pub(crate) fn build_bif(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_bit_insert(machine, operands, true)
}

pub(crate) fn build_bit(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    build_bit_insert(machine, operands, false)
}

fn build_bit_insert(
    machine: Architecture,
    operands: &[ArchOperand],
    invert_mask: bool,
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let bits = location_bits(&dst);
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(operands.get(1)?)?;
    let mask_input = operand_expression(operands.get(2)?)?;
    let mask = if invert_mask {
        SemanticExpression::Unary {
            op: SemanticOperationUnary::Not,
            arg: Box::new(mask_input),
            bits,
        }
    } else {
        mask_input
    };
    let result = binary(
        SemanticOperationBinary::Xor,
        current.clone(),
        binary(
            SemanticOperationBinary::And,
            binary(SemanticOperationBinary::Xor, current, src, bits),
            mask,
            bits,
        ),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: result,
        }],
    ))
}
