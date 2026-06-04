use crate::irs::hir::optimizers::common::{
    recurse_expression, simplify_place_expressions, simplify_target_expressions,
};
use crate::irs::hir::{
    HirBlock, HirExpression, HirFunction, HirModule, HirStatement, HirType, HirValue,
};

pub fn optimize_undefs(function: &mut HirFunction) {
    for block in &mut function.blocks {
        fold_undefs_in_block(block);
    }
}

pub fn optimize_undefs_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_undefs(function);
    }
}

fn fold_undefs_in_block(block: &mut HirBlock) {
    for statement in &mut block.statements {
        fold_undefs_in_statement(statement);
    }
}

fn fold_undefs_in_statement(statement: &mut HirStatement) {
    match statement {
        HirStatement::Assign { target, value } => {
            simplify_place_expressions(target, fold_undefs_in_expression);
            fold_undefs_in_expression(value);
        }
        HirStatement::Expr(value) => fold_undefs_in_expression(value),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            fold_undefs_in_expression(condition);
            fold_undefs_in_block(then_body);
            if let Some(else_body) = else_body {
                fold_undefs_in_block(else_body);
            }
        }
        HirStatement::While { condition, body } => {
            fold_undefs_in_expression(condition);
            fold_undefs_in_block(body);
        }
        HirStatement::Loop { body } => fold_undefs_in_block(body),
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            fold_undefs_in_expression(value);
            for case in cases {
                fold_undefs_in_block(&mut case.body);
            }
            if let Some(default) = default {
                fold_undefs_in_block(default);
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                fold_undefs_in_expression(value);
            }
        }
        HirStatement::Goto(target) => {
            simplify_target_expressions(target, fold_undefs_in_expression);
        }
        HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Label(_)
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn fold_undefs_in_expression(expression: &mut HirExpression) {
    recurse_expression(expression, fold_undefs_in_expression);
    if let Some(folded) = fold_undef_expression(expression) {
        *expression = folded;
    }
}

fn fold_undef_expression(expression: &HirExpression) -> Option<HirExpression> {
    match expression {
        HirExpression::Unary { value, ty, .. }
        | HirExpression::Extract { value, ty, .. }
        | HirExpression::Cast { value, ty, .. }
        | HirExpression::Dereference { pointer: value, ty } => {
            is_undef_expression(value).then(|| undef_expression(ty.clone()))
        }
        HirExpression::Binary { lhs, rhs, ty, .. }
        | HirExpression::Compare { lhs, rhs, ty, .. }
        | HirExpression::FloatCompare { lhs, rhs, ty, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ty,
        } => (is_undef_expression(lhs) || is_undef_expression(rhs))
            .then(|| undef_expression(ty.clone())),
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ty,
        } => {
            if is_undef_expression(condition) {
                return Some(undef_expression(ty.clone()));
            }
            if when_true == when_false {
                return Some((**when_true).clone());
            }
            (is_undef_expression(when_true) || is_undef_expression(when_false))
                .then(|| undef_expression(ty.clone()))
        }
        HirExpression::Concat { parts, ty } => parts
            .iter()
            .any(is_undef_expression)
            .then(|| undef_expression(ty.clone())),
        HirExpression::Load { address, ty, .. } => {
            is_undef_expression(address).then(|| undef_expression(ty.clone()))
        }
        HirExpression::Value(_)
        | HirExpression::Call { .. }
        | HirExpression::Intrinsic { .. }
        | HirExpression::AddressOf { .. } => None,
    }
}

fn is_undef_expression(expression: &HirExpression) -> bool {
    matches!(expression, HirExpression::Value(HirValue::Undef { .. }))
}

fn undef_expression(ty: HirType) -> HirExpression {
    HirExpression::Value(HirValue::Undef { ty })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::irs::hir::HirType;

    #[test]
    fn preserves_never_assigned_local_reads() {
        let mut function = HirFunction {
            blocks: vec![HirBlock {
                statements: vec![HirStatement::Return {
                    values: vec![HirExpression::Value(HirValue::Named {
                        name: "ret0".to_string(),
                        ty: HirType::integer(64),
                    })],
                }],
            }],
            ..HirFunction::new(Some("test".to_string()))
        };

        optimize_undefs(&mut function);
        assert_eq!(
            function.blocks[0].statements,
            vec![HirStatement::Return {
                values: vec![HirExpression::Value(HirValue::Named {
                    name: "ret0".to_string(),
                    ty: HirType::integer(64),
                })],
            }]
        );
    }

    #[test]
    fn folds_pure_expressions_with_explicit_undef_operands() {
        let mut function = HirFunction {
            blocks: vec![HirBlock {
                statements: vec![HirStatement::Return {
                    values: vec![HirExpression::Binary {
                        op: crate::irs::hir::HirBinaryOperation::Add,
                        lhs: Box::new(HirExpression::Value(HirValue::Undef {
                            ty: HirType::integer(32),
                        })),
                        rhs: Box::new(HirExpression::Value(HirValue::Integer {
                            value: 1,
                            bits: 32,
                        })),
                        ty: HirType::integer(32),
                    }],
                }],
            }],
            ..HirFunction::new(Some("test".to_string()))
        };

        optimize_undefs(&mut function);
        assert_eq!(
            function.blocks[0].statements,
            vec![HirStatement::Return {
                values: vec![HirExpression::Value(HirValue::Undef {
                    ty: HirType::integer(32),
                })],
            }]
        );
    }

    #[test]
    fn preserves_calls_with_undef_arguments() {
        let mut function = HirFunction {
            blocks: vec![HirBlock {
                statements: vec![HirStatement::Expr(HirExpression::Call {
                    target: crate::irs::hir::HirTarget::Direct("side_effect".to_string()),
                    abi: None,
                    arguments: vec![HirExpression::Value(HirValue::Undef {
                        ty: HirType::integer(64),
                    })],
                    return_types: vec![HirType::integer(64)],
                })],
            }],
            ..HirFunction::new(Some("test".to_string()))
        };

        optimize_undefs(&mut function);
        assert_eq!(
            function.blocks[0].statements,
            vec![HirStatement::Expr(HirExpression::Call {
                target: crate::irs::hir::HirTarget::Direct("side_effect".to_string()),
                abi: None,
                arguments: vec![HirExpression::Value(HirValue::Undef {
                    ty: HirType::integer(64),
                })],
                return_types: vec![HirType::integer(64)],
            })]
        );
    }
}
