use crate::ir::hir::optimizers::algebraic::simplify_algebraic_expression;
use crate::ir::hir::optimizers::common::{
    recurse_expression, simplify_place_expressions, value_type, zero_expression_for_type,
};
use crate::ir::hir::{
    HirBinaryOperation, HirCompareOperation, HirExpression, HirFunction, HirModule, HirPlace,
    HirStatement, HirTarget, HirType,
};

pub fn optimize_condition_idioms(function: &mut HirFunction) {
    for block in &mut function.blocks {
        for statement in &mut block.statements {
            simplify_condition_idiom_statement(statement);
        }
    }
}

pub fn optimize_condition_idioms_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_condition_idioms(function);
    }
}

fn simplify_condition_idiom_statement(statement: &mut HirStatement) {
    match statement {
        HirStatement::Assign { target, value } => {
            simplify_condition_idiom_place(target);
            simplify_condition_idiom_expression(value);
        }
        HirStatement::Expr(value) => simplify_condition_idiom_expression(value),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            simplify_condition_idiom_expression(condition);
            for statement in &mut then_body.statements {
                simplify_condition_idiom_statement(statement);
            }
            if let Some(else_body) = else_body {
                for statement in &mut else_body.statements {
                    simplify_condition_idiom_statement(statement);
                }
            }
        }
        HirStatement::While { condition, body } => {
            simplify_condition_idiom_expression(condition);
            for statement in &mut body.statements {
                simplify_condition_idiom_statement(statement);
            }
        }
        HirStatement::Loop { body } => {
            for statement in &mut body.statements {
                simplify_condition_idiom_statement(statement);
            }
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            simplify_condition_idiom_expression(value);
            for case in cases {
                for statement in &mut case.body.statements {
                    simplify_condition_idiom_statement(statement);
                }
            }
            if let Some(default) = default {
                for statement in &mut default.statements {
                    simplify_condition_idiom_statement(statement);
                }
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                simplify_condition_idiom_expression(value);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => {
            simplify_condition_idiom_expression(value)
        }
        HirStatement::Goto(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Label(_)
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn simplify_condition_idiom_expression(expression: &mut HirExpression) {
    recurse_expression(expression, simplify_condition_idiom_expression);
    simplify_algebraic_expression(expression);
    let current = expression.clone();
    *expression = simplify_condition_idiom_expression_once(current);
}

fn simplify_condition_idiom_expression_once(expression: HirExpression) -> HirExpression {
    if let Some(result) = simplify_strict_compare_conjunction_idiom(&expression) {
        return result;
    }
    if let Some(result) = simplify_nonstrict_compare_disjunction_idiom(&expression) {
        return result;
    }
    if let Some(result) = simplify_signbit_extract_idiom(&expression) {
        return result;
    }
    if let Some(result) = simplify_signed_nonpositive_idiom(&expression) {
        return result;
    }
    if let Some(result) = simplify_signed_sub_less_than_idiom(&expression) {
        return result;
    }
    expression
}

fn simplify_condition_idiom_place(place: &mut HirPlace) {
    simplify_place_expressions(place, simplify_condition_idiom_expression);
}

fn simplify_strict_compare_conjunction_idiom(expression: &HirExpression) -> Option<HirExpression> {
    let HirExpression::Binary {
        op: HirBinaryOperation::And,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };

    simplify_compare_pair_to_strict(lhs, rhs).or_else(|| simplify_compare_pair_to_strict(rhs, lhs))
}

fn simplify_nonstrict_compare_disjunction_idiom(
    expression: &HirExpression,
) -> Option<HirExpression> {
    let HirExpression::Binary {
        op: HirBinaryOperation::Or,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };

    simplify_compare_pair_to_nonstrict(lhs, rhs)
        .or_else(|| simplify_compare_pair_to_nonstrict(rhs, lhs))
}

fn simplify_compare_pair_to_strict(
    range_compare: &HirExpression,
    inequality_compare: &HirExpression,
) -> Option<HirExpression> {
    let HirExpression::Compare {
        op: range_op,
        lhs: range_lhs,
        rhs: range_rhs,
        ..
    } = range_compare
    else {
        return None;
    };
    let HirExpression::Compare {
        op: inequality_op,
        lhs: neq_lhs,
        rhs: neq_rhs,
        ..
    } = inequality_compare
    else {
        return None;
    };
    if *inequality_op != HirCompareOperation::Ne {
        return None;
    }
    if **range_lhs != **neq_lhs || **range_rhs != **neq_rhs {
        return None;
    }

    let strict_op = match range_op {
        HirCompareOperation::Sge => HirCompareOperation::Sgt,
        HirCompareOperation::Uge => HirCompareOperation::Ugt,
        HirCompareOperation::Sle => HirCompareOperation::Slt,
        HirCompareOperation::Ule => HirCompareOperation::Ult,
        _ => return None,
    };

    Some(HirExpression::Compare {
        op: strict_op,
        lhs: Box::new((**range_lhs).clone()),
        rhs: Box::new((**range_rhs).clone()),
        ty: HirType::integer(1),
    })
}

fn simplify_compare_pair_to_nonstrict(
    range_compare: &HirExpression,
    equality_compare: &HirExpression,
) -> Option<HirExpression> {
    let HirExpression::Compare {
        op: range_op,
        lhs: range_lhs,
        rhs: range_rhs,
        ..
    } = range_compare
    else {
        return None;
    };
    let HirExpression::Compare {
        op: equality_op,
        lhs: eq_lhs,
        rhs: eq_rhs,
        ..
    } = equality_compare
    else {
        return None;
    };
    if *equality_op != HirCompareOperation::Eq {
        return None;
    }
    if **range_lhs != **eq_lhs || **range_rhs != **eq_rhs {
        return None;
    }

    let nonstrict_op = match range_op {
        HirCompareOperation::Slt => HirCompareOperation::Sle,
        HirCompareOperation::Ult => HirCompareOperation::Ule,
        HirCompareOperation::Sgt => HirCompareOperation::Sge,
        HirCompareOperation::Ugt => HirCompareOperation::Uge,
        _ => return None,
    };

    Some(HirExpression::Compare {
        op: nonstrict_op,
        lhs: Box::new((**range_lhs).clone()),
        rhs: Box::new((**range_rhs).clone()),
        ty: HirType::integer(1),
    })
}

fn simplify_signbit_extract_idiom(expression: &HirExpression) -> Option<HirExpression> {
    let HirExpression::Extract { value, lsb, ty, .. } = expression else {
        return None;
    };
    if *ty != HirType::integer(1) {
        return None;
    }
    let value_ty = value_type(value);
    let bits = integer_bits(&value_ty)?;
    if *lsb + 1 != bits {
        return None;
    }
    Some(HirExpression::Compare {
        op: HirCompareOperation::Slt,
        lhs: Box::new((**value).clone()),
        rhs: Box::new(zero_expression_for_type(&value_ty)),
        ty: HirType::integer(1),
    })
}

fn simplify_signed_nonpositive_idiom(expression: &HirExpression) -> Option<HirExpression> {
    let HirExpression::Binary {
        op: HirBinaryOperation::Or,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    let value = equality_zero_operand(lhs)?;
    if matches_signbit(rhs, &value) || matches_signbit(lhs, &equality_zero_operand(rhs)?) {
        let ty = value_type(&value);
        return Some(HirExpression::Compare {
            op: HirCompareOperation::Sle,
            lhs: Box::new(value),
            rhs: Box::new(zero_expression_for_type(&ty)),
            ty: HirType::integer(1),
        });
    }
    None
}

fn equality_zero_operand(expression: &HirExpression) -> Option<HirExpression> {
    if let HirExpression::Compare {
        op: HirCompareOperation::Eq,
        lhs,
        rhs,
        ..
    } = expression
    {
        if is_zero_expression(rhs) {
            return Some((**lhs).clone());
        }
        if is_zero_expression(lhs) {
            return Some((**rhs).clone());
        }
    }
    None
}

fn matches_signbit(expression: &HirExpression, value: &HirExpression) -> bool {
    matches!(
        expression,
        HirExpression::Extract { value: inner, lsb, .. }
            if **inner == *value && *lsb + 1 == integer_bits(&value_type(value)).unwrap_or(0)
    ) || matches!(
        expression,
        HirExpression::Compare {
            op: HirCompareOperation::Slt,
            lhs,
            rhs,
            ..
        } if **lhs == *value && is_zero_expression(rhs)
    )
}

fn simplify_signed_sub_less_than_idiom(expression: &HirExpression) -> Option<HirExpression> {
    let HirExpression::Binary {
        op: HirBinaryOperation::Xor,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    let negative_sub = signed_negative_operand(lhs)?;
    let HirExpression::Binary {
        op: HirBinaryOperation::Sub,
        lhs: sub_lhs,
        rhs: sub_rhs,
        ..
    } = negative_sub
    else {
        return None;
    };
    let overflow_value = signed_negative_operand(rhs)?;
    let HirExpression::Binary {
        op: HirBinaryOperation::And,
        lhs: overflow_lhs,
        rhs: overflow_rhs,
        ..
    } = overflow_value
    else {
        return None;
    };
    let HirExpression::Binary {
        op: HirBinaryOperation::Xor,
        lhs: xor_lhs_l,
        rhs: xor_lhs_r,
        ..
    } = &**overflow_lhs
    else {
        return None;
    };
    let HirExpression::Binary {
        op: HirBinaryOperation::Xor,
        lhs: xor_rhs_l,
        rhs: xor_rhs_r,
        ..
    } = &**overflow_rhs
    else {
        return None;
    };

    let expected_sub = HirExpression::Binary {
        op: HirBinaryOperation::Sub,
        lhs: Box::new(sub_lhs.as_ref().clone()),
        rhs: Box::new(sub_rhs.as_ref().clone()),
        ty: value_type(negative_sub),
    };

    if xor_lhs_l.as_ref() == sub_lhs.as_ref()
        && xor_lhs_r.as_ref() == sub_rhs.as_ref()
        && xor_rhs_l.as_ref() == sub_lhs.as_ref()
        && xor_rhs_r.as_ref() == &expected_sub
    {
        return Some(HirExpression::Compare {
            op: HirCompareOperation::Slt,
            lhs: Box::new(sub_lhs.as_ref().clone()),
            rhs: Box::new(sub_rhs.as_ref().clone()),
            ty: HirType::integer(1),
        });
    }
    None
}

fn signed_negative_operand(expression: &HirExpression) -> Option<&HirExpression> {
    match expression {
        HirExpression::Extract { value, lsb, .. } => {
            if *lsb + 1 == integer_bits(&value_type(value)).unwrap_or(0) {
                Some(value)
            } else {
                None
            }
        }
        HirExpression::Compare {
            op: HirCompareOperation::Slt,
            lhs,
            rhs,
            ..
        } if is_zero_expression(rhs) => Some(lhs),
        _ => None,
    }
}

fn integer_bits(ty: &HirType) -> Option<u16> {
    if let HirType::Integer(bits) = ty {
        Some(*bits)
    } else {
        None
    }
}

fn is_zero_expression(expression: &HirExpression) -> bool {
    matches!(
        expression,
        HirExpression::Value(crate::ir::hir::HirValue::Integer { value: 0, .. })
    ) || matches!(
        expression,
        HirExpression::Value(crate::ir::hir::HirValue::Boolean(false))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::hir::HirValue;

    fn named(name: &str) -> HirExpression {
        HirExpression::Value(HirValue::Named {
            name: name.to_string(),
            ty: HirType::integer(32),
        })
    }

    fn zero32() -> HirExpression {
        HirExpression::Value(HirValue::Integer { value: 0, bits: 32 })
    }

    fn binary(op: HirBinaryOperation, lhs: HirExpression, rhs: HirExpression) -> HirExpression {
        HirExpression::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            ty: HirType::integer(32),
        }
    }

    fn slt_zero(value: HirExpression) -> HirExpression {
        HirExpression::Compare {
            op: HirCompareOperation::Slt,
            lhs: Box::new(value),
            rhs: Box::new(zero32()),
            ty: HirType::integer(1),
        }
    }

    #[test]
    fn simplifies_compare_based_signed_less_than_overflow_idiom() {
        let lhs = named("lhs");
        let rhs = named("rhs");
        let sub = binary(HirBinaryOperation::Sub, lhs.clone(), rhs.clone());
        let overflow = binary(
            HirBinaryOperation::And,
            binary(HirBinaryOperation::Xor, lhs.clone(), rhs.clone()),
            binary(HirBinaryOperation::Xor, lhs.clone(), sub.clone()),
        );
        let expression = HirExpression::Binary {
            op: HirBinaryOperation::Xor,
            lhs: Box::new(slt_zero(sub)),
            rhs: Box::new(slt_zero(overflow)),
            ty: HirType::integer(1),
        };

        let simplified = simplify_condition_idiom_expression_once(expression);
        assert_eq!(
            simplified,
            HirExpression::Compare {
                op: HirCompareOperation::Slt,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
                ty: HirType::integer(1),
            }
        );
    }
}
