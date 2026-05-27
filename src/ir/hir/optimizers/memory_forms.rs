use crate::ir::hir::optimizers::common::{recurse_expression, simplify_place_expressions};
use crate::ir::hir::{
    HirAddressSpace, HirExpression, HirFunction, HirModule, HirPlace, HirStatement, HirTarget,
};

pub fn optimize_memory_forms(function: &mut HirFunction) {
    for block in &mut function.blocks {
        recover_memory_forms_in_block(block);
    }
}

pub fn optimize_memory_forms_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_memory_forms(function);
    }
}

fn recover_memory_forms_in_block(block: &mut crate::ir::hir::HirBlock) {
    for statement in &mut block.statements {
        recover_memory_forms_in_statement(statement);
    }
}

fn recover_memory_forms_in_statement(statement: &mut HirStatement) {
    match statement {
        HirStatement::Assign { target, value } => {
            recover_memory_forms_in_place(target);
            recover_memory_forms_in_expression(value);
        }
        HirStatement::Expr(value) => recover_memory_forms_in_expression(value),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            recover_memory_forms_in_expression(condition);
            recover_memory_forms_in_block(then_body);
            if let Some(else_body) = else_body {
                recover_memory_forms_in_block(else_body);
            }
        }
        HirStatement::While { condition, body } => {
            recover_memory_forms_in_expression(condition);
            recover_memory_forms_in_block(body);
        }
        HirStatement::Loop { body } => recover_memory_forms_in_block(body),
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            recover_memory_forms_in_expression(value);
            for case in cases {
                recover_memory_forms_in_block(&mut case.body);
            }
            if let Some(default) = default {
                recover_memory_forms_in_block(default);
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                recover_memory_forms_in_expression(value);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => recover_memory_forms_in_expression(value),
        _ => {}
    }
}

fn recover_memory_forms_in_expression(expression: &mut HirExpression) {
    recurse_expression(expression, recover_memory_forms_in_expression);
    let current = expression.clone();
    if let HirExpression::Load {
        address_space: HirAddressSpace::Default,
        address,
        ty,
    } = current
    {
        *expression = HirExpression::Deref {
            pointer: address,
            ty,
        };
    }
}

fn recover_memory_forms_in_place(place: &mut HirPlace) {
    simplify_place_expressions(place, recover_memory_forms_in_expression);
    let current = place.clone();
    if let HirPlace::Memory {
        address_space: HirAddressSpace::Default,
        address,
        ty,
    } = current
    {
        *place = HirPlace::Deref {
            pointer: address,
            ty,
        };
    }
}
