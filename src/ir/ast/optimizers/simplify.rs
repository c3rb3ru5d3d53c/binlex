use crate::ir::ast::{
    AstBinaryOperation, AstBlock, AstCompareOperation, AstExpression, AstFunction, AstModule,
    AstPlace, AstStatement, AstTarget, AstType, AstUnaryOperation, AstValue,
};
use crate::ir::storage::IrStorage;
use std::collections::BTreeMap;

pub fn optimize_ast_function(function: &mut AstFunction) {
    for _ in 0..4 {
        inline_single_use_temps(function);
        eliminate_dead_assignments(function);
        prune_unused_locals(function);
    }
}

pub fn optimize_ast_module(module: &mut AstModule) {
    for function in &mut module.functions {
        optimize_ast_function(function);
    }
}

fn inline_single_use_temps(function: &mut AstFunction) {
    let mut assignments = BTreeMap::new();
    let mut uses = BTreeMap::new();
    count_block_assignments_and_uses(&function.blocks, &mut assignments, &mut uses);

    let local_storage = function
        .locals
        .iter()
        .map(|local| {
            (
                local.name.clone(),
                local
                    .storage
                    .as_ref()
                    .is_some_and(is_concrete_declaration_storage),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut replacements = BTreeMap::new();
    collect_replacements_from_blocks(
        &function.blocks,
        &assignments,
        &uses,
        &local_storage,
        &mut replacements,
    );
    if replacements.is_empty() {
        return;
    }

    for block in &mut function.blocks {
        replace_block_values(block, &replacements);
        remove_replaced_assignments(block, &replacements);
        simplify_block_expressions(block);
    }
}

fn eliminate_dead_assignments(function: &mut AstFunction) {
    let mut assignments = BTreeMap::new();
    let mut uses = BTreeMap::new();
    count_block_assignments_and_uses(&function.blocks, &mut assignments, &mut uses);
    for block in &mut function.blocks {
        eliminate_dead_assignments_in_block(block, &uses);
        simplify_block_expressions(block);
    }
}

fn prune_unused_locals(function: &mut AstFunction) {
    let mut used = BTreeMap::new();
    let mut assignments = BTreeMap::new();
    count_block_assignments_and_uses(&function.blocks, &mut assignments, &mut used);
    function
        .locals
        .retain(|local| used.contains_key(&local.name) || assignments.contains_key(&local.name));
}

fn count_block_assignments_and_uses(
    blocks: &[AstBlock],
    assignments: &mut BTreeMap<String, usize>,
    uses: &mut BTreeMap<String, usize>,
) {
    for block in blocks {
        count_assignments_and_uses_in_block(block, assignments, uses);
    }
}

fn count_assignments_and_uses_in_block(
    block: &AstBlock,
    assignments: &mut BTreeMap<String, usize>,
    uses: &mut BTreeMap<String, usize>,
) {
    for statement in &block.statements {
        match statement {
            AstStatement::Assign { target, value } => {
                if let AstPlace::Named { name, .. } = target {
                    *assignments.entry(name.clone()).or_default() += 1;
                } else {
                    count_place_uses(target, uses);
                }
                count_expression_uses(value, uses);
            }
            AstStatement::Expr(value) => count_expression_uses(value, uses),
            AstStatement::If {
                condition,
                then_body,
                else_body,
            } => {
                count_expression_uses(condition, uses);
                count_assignments_and_uses_in_block(then_body, assignments, uses);
                if let Some(else_body) = else_body {
                    count_assignments_and_uses_in_block(else_body, assignments, uses);
                }
            }
            AstStatement::While { condition, body } => {
                count_expression_uses(condition, uses);
                count_assignments_and_uses_in_block(body, assignments, uses);
            }
            AstStatement::Loop { body } => {
                count_assignments_and_uses_in_block(body, assignments, uses);
            }
            AstStatement::Switch {
                value,
                cases,
                default,
            } => {
                count_expression_uses(value, uses);
                for case in cases {
                    count_assignments_and_uses_in_block(&case.body, assignments, uses);
                }
                if let Some(default) = default {
                    count_assignments_and_uses_in_block(default, assignments, uses);
                }
            }
            AstStatement::Return { values } => {
                for value in values {
                    count_expression_uses(value, uses);
                }
            }
            AstStatement::Goto(target) => count_target_uses(target, uses),
            AstStatement::Break
            | AstStatement::Continue
            | AstStatement::Label(_)
            | AstStatement::Trap
            | AstStatement::Unreachable => {}
        }
    }
}

fn count_expression_uses(expression: &AstExpression, uses: &mut BTreeMap<String, usize>) {
    match expression {
        AstExpression::Value(AstValue::Named { name, .. }) => {
            *uses.entry(name.clone()).or_default() += 1;
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. } => count_expression_uses(value, uses),
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. } => {
            count_expression_uses(lhs, uses);
            count_expression_uses(rhs, uses);
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            count_expression_uses(condition, uses);
            count_expression_uses(when_true, uses);
            count_expression_uses(when_false, uses);
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                count_expression_uses(part, uses);
            }
        }
        AstExpression::Load { address, .. } => count_expression_uses(address, uses),
        AstExpression::Call {
            target, arguments, ..
        } => {
            count_target_uses(target, uses);
            for argument in arguments {
                count_expression_uses(argument, uses);
            }
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                count_expression_uses(argument, uses);
            }
        }
        AstExpression::AddressOf { place, .. } => count_place_uses(place, uses),
        AstExpression::Deref { pointer, .. } => count_expression_uses(pointer, uses),
        AstExpression::Index { base, index, .. } => {
            count_expression_uses(base, uses);
            count_expression_uses(index, uses);
        }
        AstExpression::Value(_) => {}
    }
}

fn count_place_uses(place: &AstPlace, uses: &mut BTreeMap<String, usize>) {
    match place {
        AstPlace::Named { name, .. } => {
            *uses.entry(name.clone()).or_default() += 1;
        }
        AstPlace::Deref { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => {
            count_expression_uses(pointer, uses);
        }
        AstPlace::Index { base, index, .. } => {
            count_expression_uses(base, uses);
            count_expression_uses(index, uses);
        }
    }
}

fn count_target_uses(target: &AstTarget, uses: &mut BTreeMap<String, usize>) {
    if let AstTarget::Indirect(expression) = target {
        count_expression_uses(expression, uses);
    }
}

fn collect_replacements_from_blocks(
    blocks: &[AstBlock],
    assignments: &BTreeMap<String, usize>,
    uses: &BTreeMap<String, usize>,
    local_storage: &BTreeMap<String, bool>,
    replacements: &mut BTreeMap<String, AstExpression>,
) {
    for block in blocks {
        collect_replacements_from_block(block, assignments, uses, local_storage, replacements);
    }
}

fn collect_replacements_from_block(
    block: &AstBlock,
    assignments: &BTreeMap<String, usize>,
    uses: &BTreeMap<String, usize>,
    local_storage: &BTreeMap<String, bool>,
    replacements: &mut BTreeMap<String, AstExpression>,
) {
    for statement in &block.statements {
        match statement {
            AstStatement::Assign {
                target: AstPlace::Named { name, .. },
                value,
            } if assignments.get(name).copied().unwrap_or_default() == 1
                && uses.get(name).copied().unwrap_or_default() <= inline_use_limit(value)
                && !local_storage.get(name).copied().unwrap_or_default()
                && is_inlineable_expression(value) =>
            {
                replacements.insert(name.clone(), simplified_expression(value.clone()));
            }
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                collect_replacements_from_block(
                    then_body,
                    assignments,
                    uses,
                    local_storage,
                    replacements,
                );
                if let Some(else_body) = else_body {
                    collect_replacements_from_block(
                        else_body,
                        assignments,
                        uses,
                        local_storage,
                        replacements,
                    );
                }
            }
            AstStatement::While { body, .. } | AstStatement::Loop { body } => {
                collect_replacements_from_block(
                    body,
                    assignments,
                    uses,
                    local_storage,
                    replacements,
                );
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    collect_replacements_from_block(
                        &case.body,
                        assignments,
                        uses,
                        local_storage,
                        replacements,
                    );
                }
                if let Some(default) = default {
                    collect_replacements_from_block(
                        default,
                        assignments,
                        uses,
                        local_storage,
                        replacements,
                    );
                }
            }
            _ => {}
        }
    }
}

fn is_inlineable_expression(expression: &AstExpression) -> bool {
    match expression {
        AstExpression::Value(
            AstValue::Integer { .. } | AstValue::Boolean(_) | AstValue::Null { .. },
        ) => true,
        AstExpression::Cast { value, .. } => is_inlineable_expression(value),
        AstExpression::Value(AstValue::Named { .. }) => true,
        AstExpression::Compare { lhs, rhs, .. } => {
            is_inlineable_expression(lhs) && is_inlineable_expression(rhs)
        }
        AstExpression::Unary { op, value, .. } if *op == AstUnaryOperation::LogicalNot => {
            is_inlineable_expression(value)
        }
        AstExpression::Binary { op, lhs, rhs, .. } => {
            matches!(
                op,
                AstBinaryOperation::Add
                    | AstBinaryOperation::Sub
                    | AstBinaryOperation::And
                    | AstBinaryOperation::Or
                    | AstBinaryOperation::Xor
            ) && is_inlineable_expression(lhs)
                && is_inlineable_expression(rhs)
        }
        _ => false,
    }
}

fn inline_use_limit(expression: &AstExpression) -> usize {
    match expression {
        AstExpression::Binary {
            op: AstBinaryOperation::Add | AstBinaryOperation::Sub,
            lhs,
            rhs,
            ..
        } if is_inlineable_expression(lhs) && is_inlineable_expression(rhs) => 2,
        _ => 1,
    }
}

fn is_concrete_declaration_storage(storage: &IrStorage) -> bool {
    matches!(
        storage,
        IrStorage::Register { .. } | IrStorage::Stack { .. }
    )
}

fn replace_block_values(block: &mut AstBlock, replacements: &BTreeMap<String, AstExpression>) {
    for statement in &mut block.statements {
        replace_statement_values(statement, replacements);
    }
}

fn replace_statement_values(
    statement: &mut AstStatement,
    replacements: &BTreeMap<String, AstExpression>,
) {
    match statement {
        AstStatement::Assign { target, value } => {
            replace_place_values(target, replacements);
            replace_expression_values(value, replacements);
        }
        AstStatement::Expr(value) => replace_expression_values(value, replacements),
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            replace_expression_values(condition, replacements);
            replace_block_values(then_body, replacements);
            if let Some(else_body) = else_body {
                replace_block_values(else_body, replacements);
            }
        }
        AstStatement::While { condition, body } => {
            replace_expression_values(condition, replacements);
            replace_block_values(body, replacements);
        }
        AstStatement::Loop { body } => replace_block_values(body, replacements),
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            replace_expression_values(value, replacements);
            for case in cases {
                replace_block_values(&mut case.body, replacements);
            }
            if let Some(default) = default {
                replace_block_values(default, replacements);
            }
        }
        AstStatement::Return { values } => {
            for value in values {
                replace_expression_values(value, replacements);
            }
        }
        AstStatement::Goto(target) => replace_target_values(target, replacements),
        AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Label(_)
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn replace_expression_values(
    expression: &mut AstExpression,
    replacements: &BTreeMap<String, AstExpression>,
) {
    match expression {
        AstExpression::Value(AstValue::Named { name, .. }) => {
            if let Some(replacement) = replacements.get(name) {
                *expression = replacement.clone();
            }
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. } => replace_expression_values(value, replacements),
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. } => {
            replace_expression_values(lhs, replacements);
            replace_expression_values(rhs, replacements);
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            replace_expression_values(condition, replacements);
            replace_expression_values(when_true, replacements);
            replace_expression_values(when_false, replacements);
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                replace_expression_values(part, replacements);
            }
        }
        AstExpression::Load { address, .. } => replace_expression_values(address, replacements),
        AstExpression::Call {
            target, arguments, ..
        } => {
            replace_target_values(target, replacements);
            for argument in arguments {
                replace_expression_values(argument, replacements);
            }
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                replace_expression_values(argument, replacements);
            }
        }
        AstExpression::AddressOf { place, .. } => replace_place_values(place, replacements),
        AstExpression::Deref { pointer, .. } => replace_expression_values(pointer, replacements),
        AstExpression::Index { base, index, .. } => {
            replace_expression_values(base, replacements);
            replace_expression_values(index, replacements);
        }
        AstExpression::Value(_) => {}
    }
    *expression = simplified_expression(expression.clone());
}

fn replace_place_values(place: &mut AstPlace, replacements: &BTreeMap<String, AstExpression>) {
    match place {
        AstPlace::Named { .. } => {}
        AstPlace::Deref { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => {
            replace_expression_values(pointer, replacements);
        }
        AstPlace::Index { base, index, .. } => {
            replace_expression_values(base, replacements);
            replace_expression_values(index, replacements);
        }
    }
}

fn replace_target_values(target: &mut AstTarget, replacements: &BTreeMap<String, AstExpression>) {
    if let AstTarget::Indirect(expression) = target {
        replace_expression_values(expression, replacements);
    }
}

fn remove_replaced_assignments(
    block: &mut AstBlock,
    replacements: &BTreeMap<String, AstExpression>,
) {
    block.statements.retain(|statement| {
        !matches!(
            statement,
            AstStatement::Assign {
                target: AstPlace::Named { name, .. },
                ..
            } if replacements.contains_key(name)
        )
    });
    for statement in &mut block.statements {
        match statement {
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                remove_replaced_assignments(then_body, replacements);
                if let Some(else_body) = else_body {
                    remove_replaced_assignments(else_body, replacements);
                }
            }
            AstStatement::While { body, .. } | AstStatement::Loop { body } => {
                remove_replaced_assignments(body, replacements);
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    remove_replaced_assignments(&mut case.body, replacements);
                }
                if let Some(default) = default {
                    remove_replaced_assignments(default, replacements);
                }
            }
            _ => {}
        }
    }
}

fn eliminate_dead_assignments_in_block(block: &mut AstBlock, uses: &BTreeMap<String, usize>) {
    let mut rewritten = Vec::with_capacity(block.statements.len());
    for mut statement in std::mem::take(&mut block.statements) {
        match &mut statement {
            AstStatement::Assign {
                target: AstPlace::Named { name, .. },
                value,
            } if uses.get(name).copied().unwrap_or_default() == 0 => {
                if expression_has_side_effects(value) {
                    rewritten.push(AstStatement::Expr(value.clone()));
                }
            }
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                eliminate_dead_assignments_in_block(then_body, uses);
                if let Some(else_body) = else_body {
                    eliminate_dead_assignments_in_block(else_body, uses);
                }
                rewritten.push(statement);
            }
            AstStatement::While { body, .. } | AstStatement::Loop { body } => {
                eliminate_dead_assignments_in_block(body, uses);
                rewritten.push(statement);
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    eliminate_dead_assignments_in_block(&mut case.body, uses);
                }
                if let Some(default) = default {
                    eliminate_dead_assignments_in_block(default, uses);
                }
                rewritten.push(statement);
            }
            _ => rewritten.push(statement),
        }
    }
    block.statements = rewritten;
}

fn expression_has_side_effects(expression: &AstExpression) -> bool {
    match expression {
        AstExpression::Call { .. } | AstExpression::Intrinsic { .. } => true,
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. } => expression_has_side_effects(value),
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. }
        | AstExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => expression_has_side_effects(lhs) || expression_has_side_effects(rhs),
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            expression_has_side_effects(condition)
                || expression_has_side_effects(when_true)
                || expression_has_side_effects(when_false)
        }
        AstExpression::Concat { parts, .. } => parts.iter().any(expression_has_side_effects),
        AstExpression::Load { address, .. }
        | AstExpression::Deref {
            pointer: address, ..
        } => expression_has_side_effects(address),
        AstExpression::AddressOf { place, .. } => place_has_side_effects(place),
        AstExpression::Value(_) => false,
    }
}

fn place_has_side_effects(place: &AstPlace) -> bool {
    match place {
        AstPlace::Named { .. } => false,
        AstPlace::Deref { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => expression_has_side_effects(pointer),
        AstPlace::Index { base, index, .. } => {
            expression_has_side_effects(base) || expression_has_side_effects(index)
        }
    }
}

fn simplify_block_expressions(block: &mut AstBlock) {
    for statement in &mut block.statements {
        simplify_statement_expressions(statement);
    }
}

fn simplify_statement_expressions(statement: &mut AstStatement) {
    match statement {
        AstStatement::Assign { target, value } => {
            simplify_place_expressions(target);
            *value = simplified_expression(value.clone());
        }
        AstStatement::Expr(value) => *value = simplified_expression(value.clone()),
        AstStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            *condition = simplified_expression(condition.clone());
            simplify_block_expressions(then_body);
            if let Some(else_body) = else_body {
                simplify_block_expressions(else_body);
            }
        }
        AstStatement::While { condition, body } => {
            *condition = simplified_expression(condition.clone());
            simplify_block_expressions(body);
        }
        AstStatement::Loop { body } => simplify_block_expressions(body),
        AstStatement::Switch {
            value,
            cases,
            default,
        } => {
            *value = simplified_expression(value.clone());
            for case in cases {
                simplify_block_expressions(&mut case.body);
            }
            if let Some(default) = default {
                simplify_block_expressions(default);
            }
        }
        AstStatement::Return { values } => {
            for value in values {
                *value = simplified_expression(value.clone());
            }
        }
        AstStatement::Goto(target) => simplify_target_expressions(target),
        AstStatement::Break
        | AstStatement::Continue
        | AstStatement::Label(_)
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn simplify_place_expressions(place: &mut AstPlace) {
    match place {
        AstPlace::Named { .. } => {}
        AstPlace::Deref { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => {
            *pointer = Box::new(simplified_expression((**pointer).clone()));
        }
        AstPlace::Index { base, index, .. } => {
            *base = Box::new(simplified_expression((**base).clone()));
            *index = Box::new(simplified_expression((**index).clone()));
        }
    }
}

fn simplify_target_expressions(target: &mut AstTarget) {
    if let AstTarget::Indirect(expression) = target {
        *expression = Box::new(simplified_expression((**expression).clone()));
    }
}

fn simplified_expression(expression: AstExpression) -> AstExpression {
    let expression = match expression {
        AstExpression::Cast { op, value, ty } => match simplified_expression(*value) {
            AstExpression::Value(AstValue::Integer { value, .. }) => {
                AstExpression::Value(AstValue::Integer {
                    value,
                    bits: integer_type_bits(&ty).unwrap_or(64),
                })
            }
            AstExpression::Value(AstValue::Boolean(value)) if integer_type_bits(&ty).is_some() => {
                AstExpression::Value(AstValue::Integer {
                    value: i128::from(value),
                    bits: integer_type_bits(&ty).unwrap_or(1),
                })
            }
            value => AstExpression::Cast {
                op,
                value: Box::new(value),
                ty,
            },
        },
        AstExpression::Unary { op, value, ty } => AstExpression::Unary {
            op,
            value: Box::new(simplified_expression(*value)),
            ty,
        },
        AstExpression::Binary { op, lhs, rhs, ty } => AstExpression::Binary {
            op,
            lhs: Box::new(simplified_expression(*lhs)),
            rhs: Box::new(simplified_expression(*rhs)),
            ty,
        },
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ty,
        } => AstExpression::Select {
            condition: Box::new(simplified_expression(*condition)),
            when_true: Box::new(simplified_expression(*when_true)),
            when_false: Box::new(simplified_expression(*when_false)),
            ty,
        },
        AstExpression::Concat { parts, ty } => AstExpression::Concat {
            parts: parts.into_iter().map(simplified_expression).collect(),
            ty,
        },
        AstExpression::Extract { value, lsb, ty } => AstExpression::Extract {
            value: Box::new(simplified_expression(*value)),
            lsb,
            ty,
        },
        AstExpression::Load {
            address_space,
            address,
            ty,
        } => AstExpression::Load {
            address_space,
            address: Box::new(simplified_expression(*address)),
            ty,
        },
        AstExpression::Compare { op, lhs, rhs, ty } => AstExpression::Compare {
            op,
            lhs: Box::new(simplified_expression(*lhs)),
            rhs: Box::new(simplified_expression(*rhs)),
            ty,
        },
        AstExpression::FloatCompare { op, lhs, rhs, ty } => AstExpression::FloatCompare {
            op,
            lhs: Box::new(simplified_expression(*lhs)),
            rhs: Box::new(simplified_expression(*rhs)),
            ty,
        },
        AstExpression::Call {
            target,
            arguments,
            return_types,
        } => AstExpression::Call {
            target,
            arguments: arguments.into_iter().map(simplified_expression).collect(),
            return_types,
        },
        AstExpression::Intrinsic {
            name,
            arguments,
            return_types,
        } => AstExpression::Intrinsic {
            name,
            arguments: arguments.into_iter().map(simplified_expression).collect(),
            return_types,
        },
        AstExpression::AddressOf { place, ty } => AstExpression::AddressOf { place, ty },
        AstExpression::Deref { pointer, ty } => AstExpression::Deref {
            pointer: Box::new(simplified_expression(*pointer)),
            ty,
        },
        AstExpression::Index { base, index, ty } => AstExpression::Index {
            base: Box::new(simplified_expression(*base)),
            index: Box::new(simplified_expression(*index)),
            ty,
        },
        AstExpression::Value(value) => AstExpression::Value(value),
    };
    simplify_condition_idiom_expression(expression)
}

fn simplify_condition_idiom_expression(expression: AstExpression) -> AstExpression {
    if let Some(result) = simplify_logical_not_compare(&expression) {
        return result;
    }
    if let Some(result) = simplify_strict_compare_conjunction_idiom(&expression) {
        return result;
    }
    if let Some(result) = simplify_nonstrict_compare_disjunction_idiom(&expression) {
        return result;
    }
    if let Some(result) = simplify_negated_nonstrict_compare_disjunction_idiom(&expression) {
        return result;
    }
    if let Some(result) = simplify_signed_sub_less_than_idiom(&expression) {
        return result;
    }
    expression
}

fn simplify_logical_not_compare(expression: &AstExpression) -> Option<AstExpression> {
    let AstExpression::Unary {
        op: AstUnaryOperation::LogicalNot,
        value,
        ..
    } = expression
    else {
        return None;
    };
    let AstExpression::Compare { op, lhs, rhs, .. } = &**value else {
        return None;
    };
    Some(AstExpression::Compare {
        op: invert_compare_operation(*op),
        lhs: Box::new((**lhs).clone()),
        rhs: Box::new((**rhs).clone()),
        ty: AstType::integer(1),
    })
}

fn simplify_strict_compare_conjunction_idiom(expression: &AstExpression) -> Option<AstExpression> {
    let AstExpression::Binary {
        op: AstBinaryOperation::And,
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
    expression: &AstExpression,
) -> Option<AstExpression> {
    let AstExpression::Binary {
        op: AstBinaryOperation::Or,
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

fn simplify_negated_nonstrict_compare_disjunction_idiom(
    expression: &AstExpression,
) -> Option<AstExpression> {
    let AstExpression::Binary {
        op: AstBinaryOperation::And,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    let lhs = logical_not_operand(lhs)?;
    let rhs = logical_not_operand(rhs)?;
    let nonstrict = simplify_compare_pair_to_nonstrict(lhs, rhs)
        .or_else(|| simplify_compare_pair_to_nonstrict(rhs, lhs))?;
    let AstExpression::Compare { op, lhs, rhs, .. } = nonstrict else {
        return None;
    };
    Some(AstExpression::Compare {
        op: invert_compare_operation(op),
        lhs,
        rhs,
        ty: AstType::integer(1),
    })
}

fn logical_not_operand(expression: &AstExpression) -> Option<&AstExpression> {
    match expression {
        AstExpression::Unary {
            op: AstUnaryOperation::LogicalNot,
            value,
            ..
        } => Some(value),
        _ => None,
    }
}

fn simplify_compare_pair_to_strict(
    range_compare: &AstExpression,
    inequality_compare: &AstExpression,
) -> Option<AstExpression> {
    let AstExpression::Compare {
        op: range_op,
        lhs: range_lhs,
        rhs: range_rhs,
        ..
    } = range_compare
    else {
        return None;
    };
    let AstExpression::Compare {
        op: inequality_op,
        lhs: neq_lhs,
        rhs: neq_rhs,
        ..
    } = inequality_compare
    else {
        return None;
    };
    if *inequality_op != AstCompareOperation::Ne {
        return None;
    }
    if **range_lhs != **neq_lhs || **range_rhs != **neq_rhs {
        return None;
    }

    let op = match range_op {
        AstCompareOperation::Sge => AstCompareOperation::Sgt,
        AstCompareOperation::Uge => AstCompareOperation::Ugt,
        AstCompareOperation::Sle => AstCompareOperation::Slt,
        AstCompareOperation::Ule => AstCompareOperation::Ult,
        _ => return None,
    };
    Some(AstExpression::Compare {
        op,
        lhs: Box::new((**range_lhs).clone()),
        rhs: Box::new((**range_rhs).clone()),
        ty: AstType::integer(1),
    })
}

fn simplify_compare_pair_to_nonstrict(
    range_compare: &AstExpression,
    equality_compare: &AstExpression,
) -> Option<AstExpression> {
    let range_compare =
        simplify_signed_sub_less_than_idiom(range_compare).unwrap_or_else(|| range_compare.clone());
    let AstExpression::Compare {
        op: range_op,
        lhs: range_lhs,
        rhs: range_rhs,
        ..
    } = &range_compare
    else {
        return None;
    };
    let AstExpression::Compare {
        op: equality_op,
        lhs: eq_lhs,
        rhs: eq_rhs,
        ..
    } = equality_compare
    else {
        return None;
    };
    if *equality_op != AstCompareOperation::Eq {
        return None;
    }
    if **range_lhs != **eq_lhs || **range_rhs != **eq_rhs {
        return None;
    }

    let op = match range_op {
        AstCompareOperation::Slt => AstCompareOperation::Sle,
        AstCompareOperation::Ult => AstCompareOperation::Ule,
        AstCompareOperation::Sgt => AstCompareOperation::Sge,
        AstCompareOperation::Ugt => AstCompareOperation::Uge,
        _ => return None,
    };
    Some(AstExpression::Compare {
        op,
        lhs: Box::new((**range_lhs).clone()),
        rhs: Box::new((**range_rhs).clone()),
        ty: AstType::integer(1),
    })
}

fn simplify_signed_sub_less_than_idiom(expression: &AstExpression) -> Option<AstExpression> {
    let AstExpression::Binary {
        op: AstBinaryOperation::Xor,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    let negative_sub = signed_negative_operand(lhs)?;
    let AstExpression::Binary {
        op: AstBinaryOperation::Sub,
        lhs: sub_lhs,
        rhs: sub_rhs,
        ..
    } = negative_sub
    else {
        return None;
    };
    let overflow_value = signed_negative_operand(rhs)?;
    let AstExpression::Binary {
        op: AstBinaryOperation::And,
        lhs: overflow_lhs,
        rhs: overflow_rhs,
        ..
    } = overflow_value
    else {
        return None;
    };
    let AstExpression::Binary {
        op: AstBinaryOperation::Xor,
        lhs: xor_lhs_l,
        rhs: xor_lhs_r,
        ..
    } = &**overflow_lhs
    else {
        return None;
    };
    let AstExpression::Binary {
        op: AstBinaryOperation::Xor,
        lhs: xor_rhs_l,
        rhs: xor_rhs_r,
        ..
    } = &**overflow_rhs
    else {
        return None;
    };

    let expected_sub = AstExpression::Binary {
        op: AstBinaryOperation::Sub,
        lhs: Box::new(sub_lhs.as_ref().clone()),
        rhs: Box::new(sub_rhs.as_ref().clone()),
        ty: expression_type(negative_sub),
    };

    if xor_lhs_l.as_ref() == sub_lhs.as_ref()
        && xor_lhs_r.as_ref() == sub_rhs.as_ref()
        && xor_rhs_l.as_ref() == sub_lhs.as_ref()
        && xor_rhs_r.as_ref() == &expected_sub
    {
        return Some(AstExpression::Compare {
            op: AstCompareOperation::Slt,
            lhs: Box::new(sub_lhs.as_ref().clone()),
            rhs: Box::new(sub_rhs.as_ref().clone()),
            ty: AstType::integer(1),
        });
    }
    None
}

fn signed_negative_operand(expression: &AstExpression) -> Option<&AstExpression> {
    match expression {
        AstExpression::Extract { value, lsb, .. } => {
            if *lsb + 1 == integer_type_bits(&expression_type(value)).unwrap_or(0) {
                Some(value)
            } else {
                None
            }
        }
        AstExpression::Compare {
            op: AstCompareOperation::Slt,
            lhs,
            rhs,
            ..
        } if is_zero_expression(rhs) => Some(lhs),
        _ => None,
    }
}

fn invert_compare_operation(op: AstCompareOperation) -> AstCompareOperation {
    match op {
        AstCompareOperation::Eq => AstCompareOperation::Ne,
        AstCompareOperation::Ne => AstCompareOperation::Eq,
        AstCompareOperation::Ult => AstCompareOperation::Uge,
        AstCompareOperation::Ule => AstCompareOperation::Ugt,
        AstCompareOperation::Ugt => AstCompareOperation::Ule,
        AstCompareOperation::Uge => AstCompareOperation::Ult,
        AstCompareOperation::Slt => AstCompareOperation::Sge,
        AstCompareOperation::Sle => AstCompareOperation::Sgt,
        AstCompareOperation::Sgt => AstCompareOperation::Sle,
        AstCompareOperation::Sge => AstCompareOperation::Slt,
    }
}

fn expression_type(expression: &AstExpression) -> AstType {
    match expression {
        AstExpression::Value(value) => value.ty(),
        AstExpression::Unary { ty, .. }
        | AstExpression::Binary { ty, .. }
        | AstExpression::Select { ty, .. }
        | AstExpression::Concat { ty, .. }
        | AstExpression::Extract { ty, .. }
        | AstExpression::Load { ty, .. }
        | AstExpression::Compare { ty, .. }
        | AstExpression::FloatCompare { ty, .. }
        | AstExpression::Cast { ty, .. }
        | AstExpression::AddressOf { ty, .. }
        | AstExpression::Deref { ty, .. }
        | AstExpression::Index { ty, .. } => ty.clone(),
        AstExpression::Call { return_types, .. }
        | AstExpression::Intrinsic { return_types, .. } => {
            return_types.first().cloned().unwrap_or_else(AstType::void)
        }
    }
}

fn is_zero_expression(expression: &AstExpression) -> bool {
    matches!(
        expression,
        AstExpression::Value(AstValue::Integer { value: 0, .. })
            | AstExpression::Value(AstValue::Boolean(false))
    )
}

fn integer_type_bits(ty: &AstType) -> Option<u16> {
    if let AstType::Integer(bits) = ty {
        Some(*bits)
    } else {
        None
    }
}
