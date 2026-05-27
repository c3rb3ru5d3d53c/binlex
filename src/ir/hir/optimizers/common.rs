use crate::ir::hir::{HirExpression, HirFunction, HirPlace, HirTarget, HirType};

pub(crate) fn next_generated_local_index(function: &HirFunction, prefix: &str) -> usize {
    function
        .locals
        .iter()
        .filter_map(|local| local.name.strip_prefix(prefix))
        .filter_map(|suffix| suffix.parse::<usize>().ok())
        .max()
        .map(|index| index + 1)
        .unwrap_or(0)
}

pub(crate) fn recurse_expression<F>(expression: &mut HirExpression, mut visit: F)
where
    F: FnMut(&mut HirExpression) + Copy,
{
    match expression {
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Deref { pointer: value, .. } => visit(value),
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => {
            visit(lhs);
            visit(rhs);
        }
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            visit(condition);
            visit(when_true);
            visit(when_false);
        }
        HirExpression::Concat { parts, .. } => {
            for part in parts {
                visit(part);
            }
        }
        HirExpression::Load { address, .. } => visit(address),
        HirExpression::Call {
            target, arguments, ..
        } => {
            simplify_target_expressions(target, visit);
            for argument in arguments {
                visit(argument);
            }
        }
        HirExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                visit(argument);
            }
        }
        HirExpression::AddressOf { place, .. } => simplify_place_expressions(place, visit),
        HirExpression::Value(_) => {}
    }
}

pub(crate) fn simplify_target_expressions<F>(target: &mut HirTarget, visit: F)
where
    F: FnMut(&mut HirExpression) + Copy,
{
    if let HirTarget::Indirect(expression) = target {
        let mut visit = visit;
        visit(expression);
    }
}

pub(crate) fn simplify_place_expressions<F>(place: &mut HirPlace, visit: F)
where
    F: FnMut(&mut HirExpression) + Copy,
{
    match place {
        HirPlace::Deref { pointer, .. }
        | HirPlace::Memory {
            address: pointer, ..
        } => {
            let mut visit = visit;
            visit(pointer);
        }
        HirPlace::Index { base, index, .. } => {
            let mut visit = visit;
            visit(base);
            visit(index);
        }
        HirPlace::Named { .. } => {}
    }
}

pub(crate) fn value_type(expression: &HirExpression) -> HirType {
    match expression {
        HirExpression::Value(value) => value.ty(),
        HirExpression::Unary { ty, .. }
        | HirExpression::Binary { ty, .. }
        | HirExpression::Select { ty, .. }
        | HirExpression::Concat { ty, .. }
        | HirExpression::Extract { ty, .. }
        | HirExpression::Load { ty, .. }
        | HirExpression::Compare { ty, .. }
        | HirExpression::FloatCompare { ty, .. }
        | HirExpression::Cast { ty, .. }
        | HirExpression::Deref { ty, .. }
        | HirExpression::Index { ty, .. }
        | HirExpression::AddressOf { ty, .. } => ty.clone(),
        HirExpression::Call { return_types, .. }
        | HirExpression::Intrinsic { return_types, .. } => {
            return_types.first().cloned().unwrap_or_else(HirType::void)
        }
    }
}

pub(crate) fn zero_expression_for_type(ty: &HirType) -> HirExpression {
    match ty {
        HirType::Integer(bits) => HirExpression::Value(crate::ir::hir::HirValue::Integer {
            value: 0,
            bits: *bits,
        }),
        _ => HirExpression::Value(crate::ir::hir::HirValue::Integer { value: 0, bits: 64 }),
    }
}
