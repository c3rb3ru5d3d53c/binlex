use super::*;
use crate::semantics::SemanticOperationCast;

pub(crate) fn build_unsigned_bitfield_extract(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::ZeroExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb,
                    bits: width,
                }),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_signed_bitfield_extract(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: SemanticExpression::Cast {
                op: SemanticOperationCast::SignExtend,
                arg: Box::new(SemanticExpression::Extract {
                    arg: Box::new(src),
                    lsb,
                    bits: width,
                }),
                bits,
            },
        }],
    ))
}

pub(crate) fn build_unsigned_bitfield_insert(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let extracted = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: width,
    };
    let extended = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(extracted),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Shl,
                extended,
                const_u64(lsb as u64, bits),
                bits,
            ),
        }],
    ))
}

pub(crate) fn build_bitfield_insert(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let field_mask = if width == 0 || lsb >= bits {
        0
    } else {
        ((((1u128 << width.min(64)) - 1) as u64) << lsb) & bitmask(bits)
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!field_mask) & bitmask(bits), bits),
        bits,
    );
    let inserted = binary(
        SemanticOperationBinary::Shl,
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(SemanticExpression::Extract {
                arg: Box::new(src),
                lsb: 0,
                bits: width,
            }),
            bits,
        },
        const_u64(lsb as u64, bits),
        bits,
    );
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, cleared, inserted, bits),
        }],
    ))
}

pub(crate) fn build_bitfield_insert_low(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let current = SemanticExpression::Read(Box::new(dst.clone()));
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let mask = if width == 0 {
        0
    } else {
        ((1u128 << width.min(64)) - 1) as u64
    };
    let cleared = binary(
        SemanticOperationBinary::And,
        current,
        const_u64((!mask) & bitmask(bits), bits),
        bits,
    );
    let shifted_src = binary(
        SemanticOperationBinary::LShr,
        src,
        const_u64(lsb as u64, bits),
        bits,
    );
    let extracted = SemanticExpression::Extract {
        arg: Box::new(shifted_src),
        lsb: 0,
        bits: width,
    };
    let inserted = SemanticExpression::Cast {
        op: SemanticOperationCast::ZeroExtend,
        arg: Box::new(extracted),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(SemanticOperationBinary::Or, cleared, inserted, bits),
        }],
    ))
}

pub(crate) fn build_signed_bitfield_insert(
    machine: Architecture,
    operands: &[ArchOperand],
) -> Option<InstructionSemantics> {
    let dst = operand_location(machine, operands.first()?)?;
    let src = operand_expression(operands.get(1)?)?;
    let lsb = operand_immediate(operands.get(2)?)? as u16;
    let width = operand_immediate(operands.get(3)?)? as u16;
    let bits = location_bits(&dst);
    let extracted = SemanticExpression::Extract {
        arg: Box::new(src),
        lsb: 0,
        bits: width,
    };
    let extended = SemanticExpression::Cast {
        op: SemanticOperationCast::SignExtend,
        arg: Box::new(extracted),
        bits,
    };
    Some(complete(
        SemanticTerminator::FallThrough,
        vec![SemanticEffect::Set {
            dst,
            expression: binary(
                SemanticOperationBinary::Shl,
                extended,
                const_u64(lsb as u64, bits),
                bits,
            ),
        }],
    ))
}
