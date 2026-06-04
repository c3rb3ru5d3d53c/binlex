use crate::irs::hir::optimizers::common::{next_generated_local_index, value_type};
use crate::irs::hir::{HirExpression, HirFunction, HirModule, HirPlace, HirStatement, HirTarget};

pub fn optimize_call_arguments(function: &mut HirFunction) {
    let mut next_index = next_generated_local_index(function, "load");
    for block in &mut function.blocks {
        extract_complex_call_arguments_in_block(block, &mut function.locals, &mut next_index);
    }
}

pub fn optimize_call_arguments_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_call_arguments(function);
    }
}

fn extract_complex_call_arguments_in_block(
    block: &mut crate::irs::hir::HirBlock,
    locals: &mut Vec<crate::irs::hir::statement::HirLocal>,
    next_index: &mut usize,
) {
    let mut new_statements = Vec::new();
    for mut statement in std::mem::take(&mut block.statements) {
        let mut prepend = Vec::new();
        extract_complex_call_arguments_in_statement(
            &mut statement,
            locals,
            next_index,
            &mut prepend,
        );
        new_statements.extend(prepend);
        new_statements.push(statement);
    }
    block.statements = new_statements;
}

fn extract_complex_call_arguments_in_statement(
    statement: &mut HirStatement,
    locals: &mut Vec<crate::irs::hir::statement::HirLocal>,
    next_index: &mut usize,
    prepend: &mut Vec<HirStatement>,
) {
    match statement {
        HirStatement::Assign { value, .. } | HirStatement::Expr(value) => {
            extract_complex_call_arguments_from_expression(value, locals, next_index, prepend);
        }
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            extract_complex_call_arguments_from_expression(condition, locals, next_index, prepend);
            extract_complex_call_arguments_in_block(then_body, locals, next_index);
            if let Some(else_body) = else_body {
                extract_complex_call_arguments_in_block(else_body, locals, next_index);
            }
        }
        HirStatement::While { condition, body } => {
            extract_complex_call_arguments_from_expression(condition, locals, next_index, prepend);
            extract_complex_call_arguments_in_block(body, locals, next_index);
        }
        HirStatement::Loop { body } => {
            extract_complex_call_arguments_in_block(body, locals, next_index)
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            extract_complex_call_arguments_from_expression(value, locals, next_index, prepend);
            for case in cases {
                extract_complex_call_arguments_in_block(&mut case.body, locals, next_index);
            }
            if let Some(default) = default {
                extract_complex_call_arguments_in_block(default, locals, next_index);
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                extract_complex_call_arguments_from_expression(value, locals, next_index, prepend);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => {
            extract_complex_call_arguments_from_expression(value, locals, next_index, prepend);
        }
        _ => {}
    }
}

fn extract_complex_call_arguments_from_expression(
    expression: &mut HirExpression,
    locals: &mut Vec<crate::irs::hir::statement::HirLocal>,
    next_index: &mut usize,
    prepend: &mut Vec<HirStatement>,
) {
    match expression {
        HirExpression::Call { arguments, .. } | HirExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                if should_extract_complex_load_argument(argument) {
                    let name = format!("load{}", *next_index);
                    *next_index += 1;
                    let ty = value_type(argument);
                    locals.push(crate::irs::hir::statement::HirLocal {
                        name: name.clone(),
                        ty: ty.clone(),
                        init: None,
                        storage: None,
                    });
                    prepend.push(HirStatement::Assign {
                        target: HirPlace::Named {
                            name: name.clone(),
                            ty: ty.clone(),
                        },
                        value: argument.clone(),
                    });
                    *argument = HirExpression::Value(crate::irs::hir::HirValue::Named { name, ty });
                } else {
                    extract_complex_call_arguments_from_expression(
                        argument, locals, next_index, prepend,
                    );
                }
            }
        }
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Dereference { pointer: value, .. } => {
            extract_complex_call_arguments_from_expression(value, locals, next_index, prepend);
        }
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => {
            extract_complex_call_arguments_from_expression(lhs, locals, next_index, prepend);
            extract_complex_call_arguments_from_expression(rhs, locals, next_index, prepend);
        }
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            extract_complex_call_arguments_from_expression(condition, locals, next_index, prepend);
            extract_complex_call_arguments_from_expression(when_true, locals, next_index, prepend);
            extract_complex_call_arguments_from_expression(when_false, locals, next_index, prepend);
        }
        HirExpression::Concat { parts, .. } => {
            for part in parts {
                extract_complex_call_arguments_from_expression(part, locals, next_index, prepend);
            }
        }
        HirExpression::Load { address, .. } => {
            extract_complex_call_arguments_from_expression(address, locals, next_index, prepend);
        }
        HirExpression::AddressOf { place, .. } => {
            extract_complex_call_arguments_from_place(place, locals, next_index, prepend);
        }
        HirExpression::Value(_) => {}
    }
}

fn extract_complex_call_arguments_from_place(
    place: &mut HirPlace,
    locals: &mut Vec<crate::irs::hir::statement::HirLocal>,
    next_index: &mut usize,
    prepend: &mut Vec<HirStatement>,
) {
    match place {
        HirPlace::Dereference { pointer, .. }
        | HirPlace::Memory {
            address: pointer, ..
        } => {
            extract_complex_call_arguments_from_expression(pointer, locals, next_index, prepend);
        }
        HirPlace::Index { base, index, .. } => {
            extract_complex_call_arguments_from_expression(base, locals, next_index, prepend);
            extract_complex_call_arguments_from_expression(index, locals, next_index, prepend);
        }
        HirPlace::Named { .. } => {}
    }
}

fn should_extract_complex_load_argument(expression: &HirExpression) -> bool {
    match expression {
        HirExpression::Load { .. } => true,
        HirExpression::Dereference { .. } => true,
        HirExpression::Binary { lhs, rhs, .. } => {
            expression_contains_memory_read(lhs) || expression_contains_memory_read(rhs)
        }
        _ => false,
    }
}

fn expression_contains_memory_read(expression: &HirExpression) -> bool {
    match expression {
        HirExpression::Load { .. } | HirExpression::Dereference { .. } => true,
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. } => expression_contains_memory_read(value),
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => expression_contains_memory_read(lhs) || expression_contains_memory_read(rhs),
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            expression_contains_memory_read(condition)
                || expression_contains_memory_read(when_true)
                || expression_contains_memory_read(when_false)
        }
        HirExpression::Concat { parts, .. } => parts.iter().any(expression_contains_memory_read),
        HirExpression::Call { .. }
        | HirExpression::Intrinsic { .. }
        | HirExpression::AddressOf { .. }
        | HirExpression::Value(_) => false,
    }
}
