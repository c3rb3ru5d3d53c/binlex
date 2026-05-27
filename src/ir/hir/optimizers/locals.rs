use crate::ir::hir::{
    HirExpression, HirFunction, HirModule, HirPlace, HirStatement, HirTarget, HirValue,
};
use std::collections::BTreeSet;

pub fn optimize_locals(function: &mut HirFunction) {
    let mut referenced = BTreeSet::new();
    for block in &function.blocks {
        collect_referenced_names_in_block(block, &mut referenced);
        collect_assigned_names_in_block(block, &mut referenced);
    }
    function
        .locals
        .retain(|local| referenced.contains(&local.name));
}

pub fn optimize_locals_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_locals(function);
    }
}

fn collect_referenced_names_in_block(
    block: &crate::ir::hir::HirBlock,
    names: &mut BTreeSet<String>,
) {
    for statement in &block.statements {
        collect_referenced_names_in_statement(statement, names);
    }
}

fn collect_referenced_names_in_statement(statement: &HirStatement, names: &mut BTreeSet<String>) {
    match statement {
        HirStatement::Assign { value, .. } | HirStatement::Expr(value) => {
            collect_referenced_names_in_expression(value, names)
        }
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_referenced_names_in_expression(condition, names);
            collect_referenced_names_in_block(then_body, names);
            if let Some(else_body) = else_body {
                collect_referenced_names_in_block(else_body, names);
            }
        }
        HirStatement::While { condition, body } => {
            collect_referenced_names_in_expression(condition, names);
            collect_referenced_names_in_block(body, names)
        }
        HirStatement::Loop { body } => collect_referenced_names_in_block(body, names),
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            collect_referenced_names_in_expression(value, names);
            for case in cases {
                collect_referenced_names_in_block(&case.body, names);
            }
            if let Some(default) = default {
                collect_referenced_names_in_block(default, names);
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                collect_referenced_names_in_expression(value, names);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => {
            collect_referenced_names_in_expression(value, names)
        }
        _ => {}
    }
}

fn collect_referenced_names_in_expression(
    expression: &HirExpression,
    names: &mut BTreeSet<String>,
) {
    match expression {
        HirExpression::Value(HirValue::Named { name, .. }) => {
            names.insert(name.clone());
        }
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Deref { pointer: value, .. } => {
            collect_referenced_names_in_expression(value, names);
        }
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => {
            collect_referenced_names_in_expression(lhs, names);
            collect_referenced_names_in_expression(rhs, names);
        }
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            collect_referenced_names_in_expression(condition, names);
            collect_referenced_names_in_expression(when_true, names);
            collect_referenced_names_in_expression(when_false, names);
        }
        HirExpression::Concat { parts, .. } => {
            for part in parts {
                collect_referenced_names_in_expression(part, names);
            }
        }
        HirExpression::Load { address, .. } => {
            collect_referenced_names_in_expression(address, names)
        }
        HirExpression::Call {
            target, arguments, ..
        } => {
            if let HirTarget::Indirect(target) = target {
                collect_referenced_names_in_expression(target, names);
            }
            for argument in arguments {
                collect_referenced_names_in_expression(argument, names);
            }
        }
        HirExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                collect_referenced_names_in_expression(argument, names);
            }
        }
        HirExpression::AddressOf { place, .. } => collect_referenced_names_in_place(place, names),
        HirExpression::Value(_) => {}
    }
}

fn collect_referenced_names_in_place(place: &HirPlace, names: &mut BTreeSet<String>) {
    match place {
        HirPlace::Named { name, .. } => {
            names.insert(name.clone());
        }
        HirPlace::Deref { pointer, .. }
        | HirPlace::Memory {
            address: pointer, ..
        } => {
            collect_referenced_names_in_expression(pointer, names);
        }
        HirPlace::Index { base, index, .. } => {
            collect_referenced_names_in_expression(base, names);
            collect_referenced_names_in_expression(index, names);
        }
    }
}

fn collect_assigned_names_in_block(block: &crate::ir::hir::HirBlock, names: &mut BTreeSet<String>) {
    for statement in &block.statements {
        if let HirStatement::Assign {
            target: HirPlace::Named { name, .. },
            ..
        } = statement
        {
            names.insert(name.clone());
        }
    }
}
