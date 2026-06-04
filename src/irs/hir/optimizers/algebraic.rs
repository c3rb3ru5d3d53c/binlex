use crate::irs::hir::optimizers::common::{
    recurse_expression, simplify_place_expressions, value_type, zero_expression_for_type,
};
use crate::irs::hir::{
    HirBinaryOperation, HirCompareOperation, HirExpression, HirFunction, HirModule, HirPlace,
    HirStatement, HirTarget, HirType, HirValue,
};

pub fn optimize_algebraic(function: &mut HirFunction) {
    for block in &mut function.blocks {
        for statement in &mut block.statements {
            simplify_algebraic_statement(statement);
        }
    }
}

pub fn optimize_algebraic_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_algebraic(function);
    }
}

pub(crate) fn simplify_algebraic_statement(statement: &mut HirStatement) {
    match statement {
        HirStatement::Assign { target, value } => {
            simplify_algebraic_place(target);
            simplify_algebraic_expression(value);
        }
        HirStatement::Expr(value) => simplify_algebraic_expression(value),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            simplify_algebraic_expression(condition);
            for statement in &mut then_body.statements {
                simplify_algebraic_statement(statement);
            }
            if let Some(else_body) = else_body {
                for statement in &mut else_body.statements {
                    simplify_algebraic_statement(statement);
                }
            }
        }
        HirStatement::While { condition, body } => {
            simplify_algebraic_expression(condition);
            for statement in &mut body.statements {
                simplify_algebraic_statement(statement);
            }
        }
        HirStatement::Loop { body } => {
            for statement in &mut body.statements {
                simplify_algebraic_statement(statement);
            }
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            simplify_algebraic_expression(value);
            for case in cases {
                for statement in &mut case.body.statements {
                    simplify_algebraic_statement(statement);
                }
            }
            if let Some(default) = default {
                for statement in &mut default.statements {
                    simplify_algebraic_statement(statement);
                }
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                simplify_algebraic_expression(value);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => simplify_algebraic_expression(value),
        HirStatement::Goto(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Label(_)
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

pub(crate) fn simplify_algebraic_expression(expression: &mut HirExpression) {
    recurse_expression(expression, simplify_algebraic_expression);
    let current = expression.clone();
    *expression = simplify_algebraic_expression_once(current);
}

fn simplify_algebraic_expression_once(expression: HirExpression) -> HirExpression {
    match expression {
        HirExpression::Binary { op, lhs, rhs, ty } => {
            if is_zero_expression(&lhs) {
                match op {
                    HirBinaryOperation::Add | HirBinaryOperation::Or | HirBinaryOperation::Xor => {
                        return *rhs;
                    }
                    HirBinaryOperation::Mul | HirBinaryOperation::And => {
                        return zero_expression_for_type(&ty);
                    }
                    _ => {}
                }
            }
            if is_zero_expression(&rhs) {
                match op {
                    HirBinaryOperation::Add
                    | HirBinaryOperation::Sub
                    | HirBinaryOperation::Or
                    | HirBinaryOperation::Xor => return *lhs,
                    HirBinaryOperation::Mul | HirBinaryOperation::And => {
                        return zero_expression_for_type(&ty);
                    }
                    _ => {}
                }
            }
            if is_one_expression(&rhs) && matches!(op, HirBinaryOperation::Mul) {
                return *lhs;
            }
            if is_one_expression(&lhs) && matches!(op, HirBinaryOperation::Mul) {
                return *rhs;
            }
            if lhs == rhs {
                match op {
                    HirBinaryOperation::Xor => return zero_expression_for_type(&ty),
                    HirBinaryOperation::And | HirBinaryOperation::Or => return *lhs,
                    _ => {}
                }
            }
            HirExpression::Binary { op, lhs, rhs, ty }
        }
        HirExpression::Compare { op, lhs, rhs, ty } => {
            if lhs == rhs {
                match op {
                    HirCompareOperation::Eq
                    | HirCompareOperation::Ule
                    | HirCompareOperation::Uge
                    | HirCompareOperation::Sle
                    | HirCompareOperation::Sge => {
                        return HirExpression::Value(HirValue::Boolean(true));
                    }
                    HirCompareOperation::Ne
                    | HirCompareOperation::Ult
                    | HirCompareOperation::Ugt
                    | HirCompareOperation::Slt
                    | HirCompareOperation::Sgt => {
                        return HirExpression::Value(HirValue::Boolean(false));
                    }
                }
            }
            HirExpression::Compare { op, lhs, rhs, ty }
        }
        HirExpression::Extract { value, lsb, ty } => {
            if let HirType::Integer(bits) = value_type(&value) {
                if lsb + 1 == bits {
                    return HirExpression::Compare {
                        op: HirCompareOperation::Slt,
                        lhs: value,
                        rhs: Box::new(zero_expression_for_type(&HirType::integer(bits))),
                        ty: HirType::integer(1),
                    };
                }
            }
            HirExpression::Extract { value, lsb, ty }
        }
        _ => expression,
    }
}

pub(crate) fn simplify_algebraic_place(place: &mut HirPlace) {
    simplify_place_expressions(place, simplify_algebraic_expression);
}

fn is_zero_expression(expression: &HirExpression) -> bool {
    matches!(
        expression,
        HirExpression::Value(HirValue::Integer { value: 0, .. })
    ) || matches!(expression, HirExpression::Value(HirValue::Boolean(false)))
}

fn is_one_expression(expression: &HirExpression) -> bool {
    matches!(
        expression,
        HirExpression::Value(HirValue::Integer { value: 1, .. })
    ) || matches!(expression, HirExpression::Value(HirValue::Boolean(true)))
}
