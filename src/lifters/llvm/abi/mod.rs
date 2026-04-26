use crate::semantics::{SemanticExpression, SemanticOperationBinary, SemanticOperationCast};
use inkwell::builder::Builder;
use inkwell::types::IntType;
use inkwell::values::IntValue;
use std::io::Error;

pub mod arm64;
pub mod x86;

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

pub fn normalize_binary(
    op: SemanticOperationBinary,
    left: SemanticExpression,
    right: SemanticExpression,
    bits: u16,
) -> (SemanticExpression, SemanticExpression) {
    let left = coerce_expression_width(left, bits);
    let right = coerce_expression_width(right, bits);
    normalize_shift_binary(op, left, right, bits)
}

pub fn normalize_compare(
    left: SemanticExpression,
    right: SemanticExpression,
) -> (SemanticExpression, SemanticExpression) {
    let left_bits = expression_bits(&left);
    let right_bits = expression_bits(&right);
    if left_bits == right_bits {
        return (left, right);
    }

    match (&left, &right) {
        (SemanticExpression::Const { .. }, _) => (coerce_expression_width(left, right_bits), right),
        (_, SemanticExpression::Const { .. }) => (left, coerce_expression_width(right, left_bits)),
        _ => (left, coerce_expression_width(right, left_bits)),
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
    use super::{coerce_expression_width, normalize_binary, normalize_compare};
    use crate::{Abi, Architecture};
    use crate::semantics::{SemanticExpression, SemanticOperationBinary, SemanticOperationCast};

    #[test]
    fn abi_support_is_architecture_aware() {
        assert!(Abi::SysV.supports(Architecture::ARM64));
        assert!(Abi::SysV.supports(Architecture::AMD64));
        assert!(Abi::Windows64.supports(Architecture::AMD64));
        assert!(Abi::Cdecl.supports(Architecture::I386));
        assert!(Abi::Stdcall.supports(Architecture::I386));
        assert!(Abi::Fastcall.supports(Architecture::I386));
        assert!(Abi::LinuxSyscall.supports(Architecture::ARM64));
        assert!(Abi::LinuxSyscall.supports(Architecture::AMD64));
        assert!(Abi::LinuxSyscall.supports(Architecture::I386));
        assert!(Abi::WindowsSyscall.supports(Architecture::ARM64));
        assert!(Abi::WindowsSyscall.supports(Architecture::AMD64));
        assert!(Abi::WindowsSyscall.supports(Architecture::I386));
        assert!(!Abi::Stdcall.supports(Architecture::ARM64));
    }

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

    #[test]
    fn normalizes_binary_operands_to_expression_width() {
        let (left, right) = normalize_binary(
            SemanticOperationBinary::Xor,
            SemanticExpression::Const { value: 1, bits: 32 },
            SemanticExpression::Const { value: 1, bits: 64 },
            32,
        );
        assert!(matches!(left, SemanticExpression::Const { bits: 32, .. }));
        match right {
            SemanticExpression::Cast { op, bits, .. } => {
                assert_eq!(op, SemanticOperationCast::Truncate);
                assert_eq!(bits, 32);
            }
            other => panic!("unexpected normalized right operand: {:?}", other),
        }
    }

    #[test]
    fn normalizes_compare_constant_to_non_constant_width() {
        let (left, right) = normalize_compare(
            SemanticExpression::Read(Box::new(crate::semantics::SemanticLocation::Register {
                name: "w0".to_string(),
                bits: 32,
            })),
            SemanticExpression::Const {
                value: 40,
                bits: 64,
            },
        );
        assert!(matches!(left, SemanticExpression::Read(_)));
        match right {
            SemanticExpression::Cast { op, bits, .. } => {
                assert_eq!(op, SemanticOperationCast::Truncate);
                assert_eq!(bits, 32);
            }
            other => panic!("unexpected normalized compare right operand: {:?}", other),
        }
    }
}
