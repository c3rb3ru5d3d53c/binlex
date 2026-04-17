use crate::semantics::{SemanticExpression, SemanticOperationBinary, SemanticOperationCast};
use inkwell::builder::Builder;
use inkwell::types::IntType;
use inkwell::values::IntValue;
use std::io::Error;

pub fn coerce_expression_width(expression: SemanticExpression, bits: u16) -> SemanticExpression {
    let current_bits = expression_bits(&expression);
    if current_bits == bits {
        return expression;
    }

    if current_bits < bits {
        SemanticExpression::Cast {
            op: SemanticOperationCast::ZeroExtend,
            arg: Box::new(expression),
            bits,
        }
    } else {
        SemanticExpression::Cast {
            op: SemanticOperationCast::Truncate,
            arg: Box::new(expression),
            bits,
        }
    }
}

pub fn normalize_shift_binary(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    bits: u16,
) -> (SemanticExpression, SemanticExpression) {
    match op {
        SemanticOperationBinary::Shl
        | SemanticOperationBinary::LShr
        | SemanticOperationBinary::AShr => (left, coerce_expression_width(right, bits)),
        _ => (left, right),
    }
}

pub fn coerce_int_value_width<'ctx>(
    builder: &Builder<'ctx>,
    value: IntValue<'ctx>,
    target: IntType<'ctx>,
    zext_name: &str,
    trunc_name: &str,
) -> Result<IntValue<'ctx>, Error> {
    let current = value.get_type().get_bit_width();
    let wanted = target.get_bit_width();
    if current == wanted {
        Ok(value)
    } else if current < wanted {
        builder
            .build_int_z_extend(value, target, zext_name)
            .map_err(|err| Error::other(err.to_string()))
    } else {
        builder
            .build_int_truncate(value, target, trunc_name)
            .map_err(|err| Error::other(err.to_string()))
    }
}

pub fn expression_bits(expression: &SemanticExpression) -> u16 {
    match expression {
        SemanticExpression::Const { bits, .. }
        | SemanticExpression::Load { bits, .. }
        | SemanticExpression::Unary { bits, .. }
        | SemanticExpression::Binary { bits, .. }
        | SemanticExpression::Cast { bits, .. }
        | SemanticExpression::Compare { bits, .. }
        | SemanticExpression::Select { bits, .. }
        | SemanticExpression::Extract { bits, .. }
        | SemanticExpression::Concat { bits, .. }
        | SemanticExpression::Undefined { bits }
        | SemanticExpression::Poison { bits }
        | SemanticExpression::Intrinsic { bits, .. } => *bits,
        SemanticExpression::Read(location) => match location.as_ref() {
            crate::semantics::SemanticLocation::Register { bits, .. }
            | crate::semantics::SemanticLocation::Flag { bits, .. }
            | crate::semantics::SemanticLocation::ProgramCounter { bits }
            | crate::semantics::SemanticLocation::Temporary { bits, .. }
            | crate::semantics::SemanticLocation::Memory { bits, .. } => *bits,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::coerce_expression_width;
    use crate::semantics::{SemanticExpression, SemanticOperationCast};

    #[test]
    fn widens_expression_with_zero_extend() {
        let widened = coerce_expression_width(SemanticExpression::Const { value: 1, bits: 5 }, 32);
        match widened {
            SemanticExpression::Cast { op, bits, .. } => {
                assert_eq!(op, SemanticOperationCast::ZeroExtend);
                assert_eq!(bits, 32);
            }
            other => panic!("unexpected widened expression: {:?}", other),
        }
    }
}
