use crate::irs::hir::optimizers::common::{
    next_generated_local_index, recurse_expression, simplify_place_expressions, value_type,
};
use crate::irs::hir::{
    HirExpression, HirFunction, HirModule, HirPlace, HirStatement, HirTarget, HirType, HirValue,
};
use std::collections::HashMap;

pub fn optimize_load_hoisting(function: &mut HirFunction) {
    let mut next_index = next_generated_local_index(function, "load");
    for block in &mut function.blocks {
        hoist_repeated_loads_in_block(block, &mut function.locals, &mut next_index);
    }
}

pub fn optimize_load_hoisting_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_load_hoisting(function);
    }
}

fn hoist_repeated_loads_in_block(
    block: &mut crate::irs::hir::HirBlock,
    locals: &mut Vec<crate::irs::hir::statement::HirLocal>,
    next_index: &mut usize,
) {
    let mut counts = HashMap::new();
    for statement in &block.statements {
        collect_loads_in_statement(statement, &mut counts);
    }
    let repeated: Vec<HirExpression> = counts
        .into_iter()
        .filter_map(|(expression, count)| (count > 1).then_some(expression))
        .collect();
    if repeated.is_empty() {
        return;
    }

    let mut replacements = HashMap::new();
    for expression in repeated {
        let name = format!("load{}", *next_index);
        *next_index += 1;
        let ty = load_expression_type(&expression).unwrap_or_else(|| value_type(&expression));
        locals.push(crate::irs::hir::statement::HirLocal {
            name: name.clone(),
            ty: ty.clone(),
            init: None,
            storage: None,
        });
        replacements.insert(expression, name);
    }

    let mut new_statements = Vec::new();
    for mut statement in std::mem::take(&mut block.statements) {
        let mut prepended = Vec::new();
        for (expression, name) in &replacements {
            if statement_contains_expression(&statement, expression) {
                let ty = load_expression_type(expression).unwrap_or_else(|| value_type(expression));
                prepended.push(HirStatement::Assign {
                    target: HirPlace::Named {
                        name: name.clone(),
                        ty: ty.clone(),
                    },
                    value: expression.clone(),
                });
            }
        }
        replace_loads_in_statement(&mut statement, &replacements);
        new_statements.extend(prepended);
        new_statements.push(statement);
    }
    block.statements = new_statements;
}

fn collect_loads_in_statement(
    statement: &HirStatement,
    counts: &mut HashMap<HirExpression, usize>,
) {
    match statement {
        HirStatement::Assign { target, value } => {
            collect_loads_in_place(target, counts);
            collect_loads_in_expression(value, counts);
        }
        HirStatement::Expr(value) => collect_loads_in_expression(value, counts),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_loads_in_expression(condition, counts);
            for statement in &then_body.statements {
                collect_loads_in_statement(statement, counts);
            }
            if let Some(else_body) = else_body {
                for statement in &else_body.statements {
                    collect_loads_in_statement(statement, counts);
                }
            }
        }
        HirStatement::While { condition, body } => {
            collect_loads_in_expression(condition, counts);
            for statement in &body.statements {
                collect_loads_in_statement(statement, counts);
            }
        }
        HirStatement::Loop { body } => {
            for statement in &body.statements {
                collect_loads_in_statement(statement, counts);
            }
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            collect_loads_in_expression(value, counts);
            for case in cases {
                for statement in &case.body.statements {
                    collect_loads_in_statement(statement, counts);
                }
            }
            if let Some(default) = default {
                for statement in &default.statements {
                    collect_loads_in_statement(statement, counts);
                }
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                collect_loads_in_expression(value, counts);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => {
            collect_loads_in_expression(value, counts)
        }
        _ => {}
    }
}

fn collect_loads_in_expression(
    expression: &HirExpression,
    counts: &mut HashMap<HirExpression, usize>,
) {
    match expression {
        HirExpression::Load { .. } => {
            *counts.entry(expression.clone()).or_insert(0) += 1;
        }
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Dereference { pointer: value, .. } => {
            collect_loads_in_expression(value, counts);
        }
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => {
            collect_loads_in_expression(lhs, counts);
            collect_loads_in_expression(rhs, counts);
        }
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_loads_in_expression(condition, counts);
            collect_loads_in_expression(when_true, counts);
            collect_loads_in_expression(when_false, counts);
        }
        HirExpression::Concat { parts, .. } => {
            for part in parts {
                collect_loads_in_expression(part, counts);
            }
        }
        HirExpression::Call {
            target, arguments, ..
        } => {
            if let HirTarget::Indirect(target) = target {
                collect_loads_in_expression(target, counts);
            }
            for argument in arguments {
                collect_loads_in_expression(argument, counts);
            }
        }
        HirExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                collect_loads_in_expression(argument, counts);
            }
        }
        HirExpression::AddressOf { place, .. } => collect_loads_in_place(place, counts),
        HirExpression::Value(_) => {}
    }
}

fn collect_loads_in_place(place: &HirPlace, counts: &mut HashMap<HirExpression, usize>) {
    match place {
        HirPlace::Dereference { pointer, .. }
        | HirPlace::Memory {
            address: pointer, ..
        } => collect_loads_in_expression(pointer, counts),
        HirPlace::Index { base, index, .. } => {
            collect_loads_in_expression(base, counts);
            collect_loads_in_expression(index, counts);
        }
        HirPlace::Named { .. } => {}
    }
}

fn load_expression_type(expression: &HirExpression) -> Option<HirType> {
    if let HirExpression::Load { ty, .. } = expression {
        Some(ty.clone())
    } else {
        None
    }
}

fn statement_contains_expression(statement: &HirStatement, needle: &HirExpression) -> bool {
    let mut counts = HashMap::new();
    collect_loads_in_statement(statement, &mut counts);
    counts.contains_key(needle)
}

fn replace_loads_in_statement(
    statement: &mut HirStatement,
    replacements: &HashMap<HirExpression, String>,
) {
    match statement {
        HirStatement::Assign { target, value } => {
            replace_loads_in_place(target, replacements);
            replace_loads_in_expression(value, replacements);
        }
        HirStatement::Expr(value) => replace_loads_in_expression(value, replacements),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            replace_loads_in_expression(condition, replacements);
            for statement in &mut then_body.statements {
                replace_loads_in_statement(statement, replacements);
            }
            if let Some(else_body) = else_body {
                for statement in &mut else_body.statements {
                    replace_loads_in_statement(statement, replacements);
                }
            }
        }
        HirStatement::While { condition, body } => {
            replace_loads_in_expression(condition, replacements);
            for statement in &mut body.statements {
                replace_loads_in_statement(statement, replacements);
            }
        }
        HirStatement::Loop { body } => {
            for statement in &mut body.statements {
                replace_loads_in_statement(statement, replacements);
            }
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            replace_loads_in_expression(value, replacements);
            for case in cases {
                for statement in &mut case.body.statements {
                    replace_loads_in_statement(statement, replacements);
                }
            }
            if let Some(default) = default {
                for statement in &mut default.statements {
                    replace_loads_in_statement(statement, replacements);
                }
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                replace_loads_in_expression(value, replacements);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => {
            replace_loads_in_expression(value, replacements)
        }
        _ => {}
    }
}

fn replace_loads_in_expression(
    expression: &mut HirExpression,
    replacements: &HashMap<HirExpression, String>,
) {
    if let Some(name) = replacements.get(expression) {
        let ty = load_expression_type(expression).unwrap_or_else(|| value_type(expression));
        *expression = HirExpression::Value(HirValue::Named {
            name: name.clone(),
            ty,
        });
        return;
    }
    recurse_expression(expression, |value| {
        replace_loads_in_expression(value, replacements)
    });
}

fn replace_loads_in_place(place: &mut HirPlace, replacements: &HashMap<HirExpression, String>) {
    simplify_place_expressions(place, |value| {
        replace_loads_in_expression(value, replacements)
    });
}
