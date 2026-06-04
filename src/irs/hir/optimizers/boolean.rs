use crate::irs::hir::optimizers::common::{recurse_expression, simplify_place_expressions};
use crate::irs::hir::{
    HirBinaryOperation, HirCompareOperation, HirExpression, HirFunction, HirModule, HirPlace,
    HirStatement, HirTarget, HirType, HirUnaryOperation,
};

pub fn optimize_boolean(function: &mut HirFunction) {
    for block in &mut function.blocks {
        for statement in &mut block.statements {
            simplify_boolean_statement(statement);
        }
    }
}

pub fn optimize_boolean_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_boolean(function);
    }
}

pub(crate) fn simplify_logical_not(value: HirExpression, ty: HirType) -> HirExpression {
    match value {
        HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            value,
            ..
        } => *value,
        HirExpression::Compare { op, lhs, rhs, .. } => HirExpression::Compare {
            op: invert_compare_operation(op),
            lhs,
            rhs,
            ty,
        },
        HirExpression::Binary {
            op: HirBinaryOperation::Or,
            lhs,
            rhs,
            ..
        } if expression_is_boolean(&lhs) && expression_is_boolean(&rhs) => HirExpression::Binary {
            op: HirBinaryOperation::And,
            lhs: Box::new(simplify_logical_not(*lhs, HirType::integer(1))),
            rhs: Box::new(simplify_logical_not(*rhs, HirType::integer(1))),
            ty,
        },
        HirExpression::Binary {
            op: HirBinaryOperation::And,
            lhs,
            rhs,
            ..
        } if expression_is_boolean(&lhs) && expression_is_boolean(&rhs) => HirExpression::Binary {
            op: HirBinaryOperation::Or,
            lhs: Box::new(simplify_logical_not(*lhs, HirType::integer(1))),
            rhs: Box::new(simplify_logical_not(*rhs, HirType::integer(1))),
            ty,
        },
        other => HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            value: Box::new(other),
            ty,
        },
    }
}

fn simplify_boolean_statement(statement: &mut HirStatement) {
    match statement {
        HirStatement::Assign { target, value } => {
            simplify_boolean_place(target);
            simplify_boolean_expression(value);
        }
        HirStatement::Expr(value) => simplify_boolean_expression(value),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            simplify_boolean_expression(condition);
            simplify_statement_condition(condition);
            for statement in &mut then_body.statements {
                simplify_boolean_statement(statement);
            }
            if let Some(else_body) = else_body {
                for statement in &mut else_body.statements {
                    simplify_boolean_statement(statement);
                }
            }
        }
        HirStatement::While { condition, body } => {
            simplify_boolean_expression(condition);
            simplify_statement_condition(condition);
            for statement in &mut body.statements {
                simplify_boolean_statement(statement);
            }
        }
        HirStatement::Loop { body } => {
            for statement in &mut body.statements {
                simplify_boolean_statement(statement);
            }
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            simplify_boolean_expression(value);
            for case in cases {
                for statement in &mut case.body.statements {
                    simplify_boolean_statement(statement);
                }
            }
            if let Some(default) = default {
                for statement in &mut default.statements {
                    simplify_boolean_statement(statement);
                }
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                simplify_boolean_expression(value);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => simplify_boolean_expression(value),
        HirStatement::Goto(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Label(_)
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn simplify_statement_condition(condition: &mut HirExpression) {
    if let HirExpression::Unary {
        op: HirUnaryOperation::LogicalNot,
        value,
        ty,
    } = condition
    {
        let simplified = simplify_logical_not((**value).clone(), ty.clone());
        *condition = simplified;
    }
}

fn simplify_boolean_expression(expression: &mut HirExpression) {
    recurse_expression(expression, simplify_boolean_expression);
    let mut current = expression.clone();
    for _ in 0..8 {
        let next = simplify_boolean_expression_once(current.clone());
        if next == current {
            *expression = current;
            return;
        }
        current = next;
    }
    *expression = current;
}

fn simplify_boolean_expression_once(expression: HirExpression) -> HirExpression {
    match expression {
        HirExpression::Unary {
            op: HirUnaryOperation::LogicalNot,
            value,
            ty,
        } => simplify_logical_not(*value, ty),
        HirExpression::Compare { op, lhs, rhs, ty } => {
            if let Some(boolean_value) = boolean_constant_value(&rhs) {
                return simplify_boolean_compare(op, *lhs, boolean_value, ty);
            }
            if let Some(boolean_value) = boolean_constant_value(&lhs) {
                return simplify_boolean_compare(op, *rhs, boolean_value, ty);
            }
            HirExpression::Compare { op, lhs, rhs, ty }
        }
        _ => expression,
    }
}

fn simplify_boolean_compare(
    op: HirCompareOperation,
    value: HirExpression,
    boolean_value: bool,
    ty: HirType,
) -> HirExpression {
    match (op, boolean_value) {
        (HirCompareOperation::Eq, true) | (HirCompareOperation::Ne, false) => value,
        (HirCompareOperation::Eq, false) | (HirCompareOperation::Ne, true) => {
            simplify_logical_not(value, ty)
        }
        _ => HirExpression::Compare {
            op,
            lhs: Box::new(value),
            rhs: Box::new(HirExpression::Value(crate::irs::hir::HirValue::Boolean(
                boolean_value,
            ))),
            ty,
        },
    }
}

fn simplify_boolean_place(place: &mut HirPlace) {
    simplify_place_expressions(place, simplify_boolean_expression);
}

fn expression_is_boolean(expression: &HirExpression) -> bool {
    match expression {
        HirExpression::Value(crate::irs::hir::HirValue::Boolean(_)) => true,
        HirExpression::Value(crate::irs::hir::HirValue::Named { ty, .. }) => {
            *ty == HirType::integer(1)
        }
        HirExpression::Compare { ty, .. }
        | HirExpression::FloatCompare { ty, .. }
        | HirExpression::Unary { ty, .. }
        | HirExpression::Binary { ty, .. } => *ty == HirType::integer(1),
        _ => false,
    }
}

fn boolean_constant_value(expression: &HirExpression) -> Option<bool> {
    match expression {
        HirExpression::Value(crate::irs::hir::HirValue::Boolean(value)) => Some(*value),
        HirExpression::Value(crate::irs::hir::HirValue::Integer { value, bits: 1 }) => {
            Some(*value != 0)
        }
        _ => None,
    }
}

fn invert_compare_operation(op: HirCompareOperation) -> HirCompareOperation {
    match op {
        HirCompareOperation::Eq => HirCompareOperation::Ne,
        HirCompareOperation::Ne => HirCompareOperation::Eq,
        HirCompareOperation::Ult => HirCompareOperation::Uge,
        HirCompareOperation::Ule => HirCompareOperation::Ugt,
        HirCompareOperation::Ugt => HirCompareOperation::Ule,
        HirCompareOperation::Uge => HirCompareOperation::Ult,
        HirCompareOperation::Slt => HirCompareOperation::Sge,
        HirCompareOperation::Sle => HirCompareOperation::Sgt,
        HirCompareOperation::Sgt => HirCompareOperation::Sle,
        HirCompareOperation::Sge => HirCompareOperation::Slt,
    }
}
