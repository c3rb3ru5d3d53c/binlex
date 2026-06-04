use crate::irs::hir::{
    HirBlock, HirExpression, HirFunction, HirModule, HirPlace, HirStatement, HirTarget, HirType,
    HirValue,
};

pub fn optimize_inline_temps(function: &mut HirFunction) {
    for block in &mut function.blocks {
        optimize_inline_temps_in_block(block);
    }
}

pub fn optimize_inline_temps_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_inline_temps(function);
    }
}

fn inline_single_use_temps_once(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index + 1 < block.statements.len() {
        let (name, value, ty) = match assignment_candidate(&block.statements[index]) {
            Some(candidate) => candidate,
            None => {
                index += 1;
                continue;
            }
        };
        if !is_generated_temp_name(&name) || !expression_safe_to_duplicate(&value) {
            index += 1;
            continue;
        }
        let mut uses = 0usize;
        let mut assigns = 0usize;
        count_name_uses_in_statements(
            &block.statements[(index + 1)..],
            &name,
            &mut uses,
            &mut assigns,
        );
        if uses != 1 || assigns != 0 {
            index += 1;
            continue;
        }
        if !replace_name_in_statement(&mut block.statements[index + 1], &name, &value) {
            index += 1;
            continue;
        }
        let _ = ty;
        block.statements.remove(index);
        changed = true;
    }
    changed
}

fn optimize_inline_temps_in_block(block: &mut HirBlock) {
    loop {
        if !inline_single_use_temps_once(block) {
            break;
        }
    }
    for statement in &mut block.statements {
        optimize_inline_temps_in_statement(statement);
    }
}

fn optimize_inline_temps_in_statement(statement: &mut HirStatement) {
    match statement {
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            optimize_inline_temps_in_block(then_body);
            if let Some(else_body) = else_body {
                optimize_inline_temps_in_block(else_body);
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            optimize_inline_temps_in_block(body);
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                optimize_inline_temps_in_block(&mut case.body);
            }
            if let Some(default) = default {
                optimize_inline_temps_in_block(default);
            }
        }
        HirStatement::Assign { .. }
        | HirStatement::Expr(_)
        | HirStatement::Return { .. }
        | HirStatement::Goto(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Label(_)
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn assignment_candidate(statement: &HirStatement) -> Option<(String, HirExpression, HirType)> {
    match statement {
        HirStatement::Assign {
            target: HirPlace::Named { name, ty },
            value,
        } => Some((name.clone(), value.clone(), ty.clone())),
        _ => None,
    }
}

fn count_name_uses_in_statements(
    statements: &[HirStatement],
    name: &str,
    uses: &mut usize,
    assigns: &mut usize,
) {
    for statement in statements {
        count_name_uses_in_statement(statement, name, uses, assigns);
    }
}

fn count_name_uses_in_statement(
    statement: &HirStatement,
    name: &str,
    uses: &mut usize,
    assigns: &mut usize,
) {
    match statement {
        HirStatement::Assign { target, value } => {
            if let HirPlace::Named {
                name: target_name, ..
            } = target
            {
                if target_name == name {
                    *assigns += 1;
                }
            }
            count_name_uses_in_expression(value, name, uses);
        }
        HirStatement::Expr(value) => count_name_uses_in_expression(value, name, uses),
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            count_name_uses_in_expression(condition, name, uses);
            count_name_uses_in_statements(&then_body.statements, name, uses, assigns);
            if let Some(else_body) = else_body {
                count_name_uses_in_statements(&else_body.statements, name, uses, assigns);
            }
        }
        HirStatement::While { condition, body } => {
            count_name_uses_in_expression(condition, name, uses);
            count_name_uses_in_statements(&body.statements, name, uses, assigns);
        }
        HirStatement::Loop { body } => {
            count_name_uses_in_statements(&body.statements, name, uses, assigns);
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            count_name_uses_in_expression(value, name, uses);
            for case in cases {
                count_name_uses_in_statements(&case.body.statements, name, uses, assigns);
            }
            if let Some(default) = default {
                count_name_uses_in_statements(&default.statements, name, uses, assigns);
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                count_name_uses_in_expression(value, name, uses);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => {
            count_name_uses_in_expression(value, name, uses)
        }
        HirStatement::Goto(_)
        | HirStatement::Break
        | HirStatement::Continue
        | HirStatement::Label(_)
        | HirStatement::Trap
        | HirStatement::Unreachable => {}
    }
}

fn count_name_uses_in_expression(expression: &HirExpression, name: &str, uses: &mut usize) {
    match expression {
        HirExpression::Value(HirValue::Named {
            name: value_name, ..
        }) if value_name == name => *uses += 1,
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Dereference { pointer: value, .. } => {
            count_name_uses_in_expression(value, name, uses)
        }
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => {
            count_name_uses_in_expression(lhs, name, uses);
            count_name_uses_in_expression(rhs, name, uses);
        }
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            count_name_uses_in_expression(condition, name, uses);
            count_name_uses_in_expression(when_true, name, uses);
            count_name_uses_in_expression(when_false, name, uses);
        }
        HirExpression::Concat { parts, .. } => {
            for part in parts {
                count_name_uses_in_expression(part, name, uses);
            }
        }
        HirExpression::Load { address, .. } => count_name_uses_in_expression(address, name, uses),
        HirExpression::Call {
            target, arguments, ..
        } => {
            if let HirTarget::Indirect(target) = target {
                count_name_uses_in_expression(target, name, uses);
            }
            for argument in arguments {
                count_name_uses_in_expression(argument, name, uses);
            }
        }
        HirExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                count_name_uses_in_expression(argument, name, uses);
            }
        }
        HirExpression::AddressOf { place, .. } => count_name_uses_in_place(place, name, uses),
        HirExpression::Value(_) => {}
    }
}

fn count_name_uses_in_place(place: &HirPlace, name: &str, uses: &mut usize) {
    match place {
        HirPlace::Named {
            name: place_name, ..
        } if place_name == name => *uses += 1,
        HirPlace::Dereference { pointer, .. }
        | HirPlace::Memory {
            address: pointer, ..
        } => count_name_uses_in_expression(pointer, name, uses),
        HirPlace::Index { base, index, .. } => {
            count_name_uses_in_expression(base, name, uses);
            count_name_uses_in_expression(index, name, uses);
        }
        HirPlace::Named { .. } => {}
    }
}

fn replace_name_in_statement(
    statement: &mut HirStatement,
    name: &str,
    replacement: &HirExpression,
) -> bool {
    let mut changed = false;
    match statement {
        HirStatement::Assign { value, .. } => {
            changed |= replace_name_in_expression(value, name, replacement)
        }
        HirStatement::Expr(value) => {
            changed |= replace_name_in_expression(value, name, replacement)
        }
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            changed |= replace_name_in_expression(condition, name, replacement);
            for statement in &mut then_body.statements {
                changed |= replace_name_in_statement(statement, name, replacement);
            }
            if let Some(else_body) = else_body {
                for statement in &mut else_body.statements {
                    changed |= replace_name_in_statement(statement, name, replacement);
                }
            }
        }
        HirStatement::While { condition, body } => {
            changed |= replace_name_in_expression(condition, name, replacement);
            for statement in &mut body.statements {
                changed |= replace_name_in_statement(statement, name, replacement);
            }
        }
        HirStatement::Loop { body } => {
            for statement in &mut body.statements {
                changed |= replace_name_in_statement(statement, name, replacement);
            }
        }
        HirStatement::Switch {
            value,
            cases,
            default,
        } => {
            changed |= replace_name_in_expression(value, name, replacement);
            for case in cases {
                for statement in &mut case.body.statements {
                    changed |= replace_name_in_statement(statement, name, replacement);
                }
            }
            if let Some(default) = default {
                for statement in &mut default.statements {
                    changed |= replace_name_in_statement(statement, name, replacement);
                }
            }
        }
        HirStatement::Return { values } => {
            for value in values {
                changed |= replace_name_in_expression(value, name, replacement);
            }
        }
        HirStatement::Goto(HirTarget::Indirect(value)) => {
            changed |= replace_name_in_expression(value, name, replacement)
        }
        _ => {}
    }
    changed
}

fn replace_name_in_expression(
    expression: &mut HirExpression,
    name: &str,
    replacement: &HirExpression,
) -> bool {
    match expression {
        HirExpression::Value(HirValue::Named {
            name: value_name, ..
        }) if value_name == name => {
            *expression = replacement.clone();
            true
        }
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Dereference { pointer: value, .. } => {
            replace_name_in_expression(value, name, replacement)
        }
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => {
            replace_name_in_expression(lhs, name, replacement)
                | replace_name_in_expression(rhs, name, replacement)
        }
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            replace_name_in_expression(condition, name, replacement)
                | replace_name_in_expression(when_true, name, replacement)
                | replace_name_in_expression(when_false, name, replacement)
        }
        HirExpression::Concat { parts, .. } => parts
            .iter_mut()
            .any(|part| replace_name_in_expression(part, name, replacement)),
        HirExpression::Load { address, .. } => {
            replace_name_in_expression(address, name, replacement)
        }
        HirExpression::Call {
            target, arguments, ..
        } => {
            let mut changed = false;
            if let HirTarget::Indirect(target) = target {
                changed |= replace_name_in_expression(target, name, replacement);
            }
            for argument in arguments {
                changed |= replace_name_in_expression(argument, name, replacement);
            }
            changed
        }
        HirExpression::Intrinsic { arguments, .. } => arguments
            .iter_mut()
            .any(|argument| replace_name_in_expression(argument, name, replacement)),
        HirExpression::AddressOf { place, .. } => replace_name_in_place(place, name, replacement),
        HirExpression::Value(_) => false,
    }
}

fn replace_name_in_place(place: &mut HirPlace, name: &str, replacement: &HirExpression) -> bool {
    match place {
        HirPlace::Dereference { pointer, .. }
        | HirPlace::Memory {
            address: pointer, ..
        } => replace_name_in_expression(pointer, name, replacement),
        HirPlace::Index { base, index, .. } => {
            replace_name_in_expression(base, name, replacement)
                | replace_name_in_expression(index, name, replacement)
        }
        HirPlace::Named { .. } => false,
    }
}

fn expression_safe_to_duplicate(expression: &HirExpression) -> bool {
    match expression {
        HirExpression::Value(_) => true,
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Dereference { pointer: value, .. } => expression_safe_to_duplicate(value),
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => expression_safe_to_duplicate(lhs) && expression_safe_to_duplicate(rhs),
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            expression_safe_to_duplicate(condition)
                && expression_safe_to_duplicate(when_true)
                && expression_safe_to_duplicate(when_false)
        }
        HirExpression::Concat { parts, .. } => parts.iter().all(expression_safe_to_duplicate),
        HirExpression::Load { address, .. } => expression_safe_to_duplicate(address),
        HirExpression::AddressOf { place, .. } => place_safe_to_duplicate(place),
        HirExpression::Call { .. } | HirExpression::Intrinsic { .. } => false,
    }
}

fn place_safe_to_duplicate(place: &HirPlace) -> bool {
    match place {
        HirPlace::Named { .. } => true,
        HirPlace::Dereference { pointer, .. }
        | HirPlace::Memory {
            address: pointer, ..
        } => expression_safe_to_duplicate(pointer),
        HirPlace::Index { base, index, .. } => {
            expression_safe_to_duplicate(base) && expression_safe_to_duplicate(index)
        }
    }
}

fn is_generated_temp_name(name: &str) -> bool {
    [
        "bin_", "cmp_", "load_", "extract_", "ptr_", "call_", "cast_", "select_",
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}
