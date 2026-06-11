use crate::irs::ast::{
    AstAddressSpace, AstBinaryOperation, AstBlock, AstCompareOperation, AstExpression, AstFunction,
    AstModule, AstPlace, AstStatement, AstTarget, AstType, AstUnaryOperation, AstValue,
};
use crate::irs::storage::IrStorage;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub fn optimize_ast_function(function: &mut AstFunction) {
    let mut run_guarded_shift_conditions = true;
    let mut run_stack_cookie_check_calls = true;
    for _ in 0..4 {
        inline_single_use_temps(function);
        if run_guarded_shift_conditions {
            run_guarded_shift_conditions = simplify_guarded_shift_conditions(function);
        }
        fold_guard_prefixes_to_fallthrough(function);
        structure_dispatch_regions(function);
        materialize_loop_induction_updates(function);
        cleanup_redundant_labels_and_gotos(function);
        if run_stack_cookie_check_calls {
            run_stack_cookie_check_calls = simplify_stack_cookie_check_calls(function);
        }
        eliminate_dead_assignments(function);
        prune_unused_locals(function);
    }
}

pub(crate) fn optimize_ast_function_with_timing<F>(function: &mut AstFunction, mut record: F)
where
    F: FnMut(&'static str, Duration),
{
    let mut run_guarded_shift_conditions = true;
    let mut run_stack_cookie_check_calls = true;
    for iteration in 0..4 {
        let suffix = match iteration {
            0 => "1",
            1 => "2",
            2 => "3",
            _ => "4",
        };
        macro_rules! pass {
            ($name:literal, $call:expr) => {{
                let started_at = Instant::now();
                let result = $call;
                let name = match $name {
                    "inline_single_use_temps" => match suffix {
                        "1" => "inline_single_use_temps_1",
                        "2" => "inline_single_use_temps_2",
                        "3" => "inline_single_use_temps_3",
                        _ => "inline_single_use_temps_4",
                    },
                    "simplify_guarded_shift_conditions" => match suffix {
                        "1" => "simplify_guarded_shift_conditions_1",
                        "2" => "simplify_guarded_shift_conditions_2",
                        "3" => "simplify_guarded_shift_conditions_3",
                        _ => "simplify_guarded_shift_conditions_4",
                    },
                    "fold_guard_prefixes_to_fallthrough" => match suffix {
                        "1" => "fold_guard_prefixes_to_fallthrough_1",
                        "2" => "fold_guard_prefixes_to_fallthrough_2",
                        "3" => "fold_guard_prefixes_to_fallthrough_3",
                        _ => "fold_guard_prefixes_to_fallthrough_4",
                    },
                    "structure_dispatch_regions" => match suffix {
                        "1" => "structure_dispatch_regions_1",
                        "2" => "structure_dispatch_regions_2",
                        "3" => "structure_dispatch_regions_3",
                        _ => "structure_dispatch_regions_4",
                    },
                    "materialize_loop_induction_updates" => match suffix {
                        "1" => "materialize_loop_induction_updates_1",
                        "2" => "materialize_loop_induction_updates_2",
                        "3" => "materialize_loop_induction_updates_3",
                        _ => "materialize_loop_induction_updates_4",
                    },
                    "cleanup_redundant_labels_and_gotos" => match suffix {
                        "1" => "cleanup_redundant_labels_and_gotos_1",
                        "2" => "cleanup_redundant_labels_and_gotos_2",
                        "3" => "cleanup_redundant_labels_and_gotos_3",
                        _ => "cleanup_redundant_labels_and_gotos_4",
                    },
                    "simplify_stack_cookie_check_calls" => match suffix {
                        "1" => "simplify_stack_cookie_check_calls_1",
                        "2" => "simplify_stack_cookie_check_calls_2",
                        "3" => "simplify_stack_cookie_check_calls_3",
                        _ => "simplify_stack_cookie_check_calls_4",
                    },
                    "eliminate_dead_assignments" => match suffix {
                        "1" => "eliminate_dead_assignments_1",
                        "2" => "eliminate_dead_assignments_2",
                        "3" => "eliminate_dead_assignments_3",
                        _ => "eliminate_dead_assignments_4",
                    },
                    _ => match suffix {
                        "1" => "prune_unused_locals_1",
                        "2" => "prune_unused_locals_2",
                        "3" => "prune_unused_locals_3",
                        _ => "prune_unused_locals_4",
                    },
                };
                record(name, started_at.elapsed());
                result
            }};
        }

        pass!("inline_single_use_temps", inline_single_use_temps(function));
        if run_guarded_shift_conditions {
            run_guarded_shift_conditions = pass!(
                "simplify_guarded_shift_conditions",
                simplify_guarded_shift_conditions(function)
            );
        }
        pass!(
            "fold_guard_prefixes_to_fallthrough",
            fold_guard_prefixes_to_fallthrough(function)
        );
        pass!(
            "structure_dispatch_regions",
            structure_dispatch_regions(function)
        );
        pass!(
            "materialize_loop_induction_updates",
            materialize_loop_induction_updates(function)
        );
        pass!(
            "cleanup_redundant_labels_and_gotos",
            cleanup_redundant_labels_and_gotos(function)
        );
        if run_stack_cookie_check_calls {
            run_stack_cookie_check_calls = pass!(
                "simplify_stack_cookie_check_calls",
                simplify_stack_cookie_check_calls(function)
            );
        }
        pass!(
            "eliminate_dead_assignments",
            eliminate_dead_assignments(function)
        );
        pass!("prune_unused_locals", prune_unused_locals(function));
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

fn cleanup_redundant_labels_and_gotos(function: &mut AstFunction) {
    let mut targets = BTreeSet::new();
    for block in &function.blocks {
        collect_direct_goto_targets(block, &mut targets);
    }
    for block in &mut function.blocks {
        cleanup_redundant_labels_and_gotos_in_block(block, &targets);
    }
}

fn cleanup_redundant_labels_and_gotos_in_block(block: &mut AstBlock, targets: &BTreeSet<String>) {
    for statement in &mut block.statements {
        match statement {
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                cleanup_redundant_labels_and_gotos_in_block(then_body, targets);
                if let Some(else_body) = else_body {
                    cleanup_redundant_labels_and_gotos_in_block(else_body, targets);
                }
            }
            AstStatement::While { body, .. } | AstStatement::Loop { body } => {
                cleanup_redundant_labels_and_gotos_in_block(body, targets);
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    cleanup_redundant_labels_and_gotos_in_block(&mut case.body, targets);
                }
                if let Some(default) = default {
                    cleanup_redundant_labels_and_gotos_in_block(default, targets);
                }
            }
            _ => {}
        }
    }

    collapse_binary_goto_fallthroughs(block);

    let mut index = 0;
    while index + 1 < block.statements.len() {
        if let (AstStatement::Goto(AstTarget::Direct(target)), AstStatement::Label(label)) =
            (&block.statements[index], &block.statements[index + 1])
            && target == label
        {
            block.statements.remove(index);
            continue;
        }
        index += 1;
    }

    block.statements.retain(
        |statement| !matches!(statement, AstStatement::Label(label) if !targets.contains(label)),
    );
}

fn collapse_binary_goto_fallthroughs(block: &mut AstBlock) {
    let mut index = 0;
    while index + 1 < block.statements.len() {
        if let AstStatement::If {
            then_body,
            else_body: Some(else_body),
            ..
        } = &block.statements[index]
            && let (Some(then_target), Some(else_target)) = (
                single_direct_goto_target(then_body),
                single_direct_goto_target(else_body),
            )
            && then_target == else_target
        {
            block.statements[index] =
                AstStatement::Goto(AstTarget::Direct(then_target.to_string()));
            index += 1;
            continue;
        }

        let Some(next_label) = label_name(&block.statements[index + 1]).map(str::to_string) else {
            index += 1;
            continue;
        };
        let AstStatement::If {
            condition,
            then_body,
            else_body: Some(else_body),
        } = &block.statements[index]
        else {
            index += 1;
            continue;
        };
        let Some(then_target) = single_direct_goto_target(then_body) else {
            index += 1;
            continue;
        };
        let Some(else_target) = single_direct_goto_target(else_body) else {
            index += 1;
            continue;
        };

        let replacement = if then_target == next_label {
            Some(AstStatement::If {
                condition: negate_ast_condition(condition.clone()),
                then_body: AstBlock {
                    statements: vec![AstStatement::Goto(AstTarget::Direct(
                        else_target.to_string(),
                    ))],
                },
                else_body: None,
            })
        } else if else_target == next_label {
            Some(AstStatement::If {
                condition: condition.clone(),
                then_body: AstBlock {
                    statements: vec![AstStatement::Goto(AstTarget::Direct(
                        then_target.to_string(),
                    ))],
                },
                else_body: None,
            })
        } else {
            None
        };

        if let Some(replacement) = replacement {
            block.statements[index] = replacement;
        }
        index += 1;
    }
}

fn collect_direct_goto_targets(block: &AstBlock, targets: &mut BTreeSet<String>) {
    for statement in &block.statements {
        match statement {
            AstStatement::Goto(AstTarget::Direct(target)) => {
                targets.insert(target.clone());
            }
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                collect_direct_goto_targets(then_body, targets);
                if let Some(else_body) = else_body {
                    collect_direct_goto_targets(else_body, targets);
                }
            }
            AstStatement::While { body, .. } | AstStatement::Loop { body } => {
                collect_direct_goto_targets(body, targets);
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    collect_direct_goto_targets(&case.body, targets);
                }
                if let Some(default) = default {
                    collect_direct_goto_targets(default, targets);
                }
            }
            _ => {}
        }
    }
}

fn simplify_stack_cookie_check_calls(function: &mut AstFunction) -> bool {
    let stack_pointer_locals = function
        .locals
        .iter()
        .filter_map(|local| {
            let Some(IrStorage::Register { name, .. }) = &local.storage else {
                return None;
            };
            is_stack_pointer_name(name).then(|| local.name.clone())
        })
        .collect::<BTreeSet<_>>();
    if stack_pointer_locals.is_empty() {
        return false;
    }
    let mut changed = false;
    for block in &mut function.blocks {
        changed |= simplify_stack_cookie_check_calls_in_block(
            block,
            &stack_pointer_locals,
            &mut BTreeMap::new(),
        );
    }
    changed
}

fn simplify_stack_cookie_check_calls_in_block(
    block: &mut AstBlock,
    stack_pointer_locals: &BTreeSet<String>,
    definitions: &mut BTreeMap<String, AstExpression>,
) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            AstStatement::Assign {
                target: AstPlace::Named { name, .. },
                value,
            } => {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    value,
                    stack_pointer_locals,
                    definitions,
                );
                definitions.insert(name.clone(), value.clone());
            }
            AstStatement::Assign { target, value } => {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    value,
                    stack_pointer_locals,
                    definitions,
                );
                changed |= simplify_stack_cookie_check_call_in_place(
                    target,
                    stack_pointer_locals,
                    definitions,
                );
            }
            AstStatement::Expr(value) => {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    value,
                    stack_pointer_locals,
                    definitions,
                );
            }
            AstStatement::If {
                condition,
                then_body,
                else_body,
            } => {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    condition,
                    stack_pointer_locals,
                    definitions,
                );
                changed |= simplify_stack_cookie_check_calls_in_block(
                    then_body,
                    stack_pointer_locals,
                    &mut definitions.clone(),
                );
                if let Some(else_body) = else_body {
                    changed |= simplify_stack_cookie_check_calls_in_block(
                        else_body,
                        stack_pointer_locals,
                        &mut definitions.clone(),
                    );
                }
            }
            AstStatement::While { condition, body } => {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    condition,
                    stack_pointer_locals,
                    definitions,
                );
                changed |= simplify_stack_cookie_check_calls_in_block(
                    body,
                    stack_pointer_locals,
                    &mut definitions.clone(),
                );
            }
            AstStatement::Loop { body } => {
                changed |= simplify_stack_cookie_check_calls_in_block(
                    body,
                    stack_pointer_locals,
                    &mut definitions.clone(),
                );
            }
            AstStatement::Switch {
                value,
                cases,
                default,
            } => {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    value,
                    stack_pointer_locals,
                    definitions,
                );
                for case in cases {
                    changed |= simplify_stack_cookie_check_calls_in_block(
                        &mut case.body,
                        stack_pointer_locals,
                        &mut definitions.clone(),
                    );
                }
                if let Some(default) = default {
                    changed |= simplify_stack_cookie_check_calls_in_block(
                        default,
                        stack_pointer_locals,
                        &mut definitions.clone(),
                    );
                }
            }
            AstStatement::Return { values } => {
                for value in values {
                    changed |= simplify_stack_cookie_check_call_in_expression(
                        value,
                        stack_pointer_locals,
                        definitions,
                    );
                }
            }
            AstStatement::Goto(AstTarget::Indirect(value)) => {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    value,
                    stack_pointer_locals,
                    definitions,
                );
            }
            AstStatement::Goto(AstTarget::Direct(_))
            | AstStatement::Break
            | AstStatement::Continue
            | AstStatement::Comment(_)
            | AstStatement::Label(_)
            | AstStatement::Trap
            | AstStatement::Unreachable => {}
        }
    }
    changed
}

fn simplify_stack_cookie_check_call_in_place(
    place: &mut AstPlace,
    stack_pointer_locals: &BTreeSet<String>,
    definitions: &BTreeMap<String, AstExpression>,
) -> bool {
    match place {
        AstPlace::Dereference { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => simplify_stack_cookie_check_call_in_expression(
            pointer,
            stack_pointer_locals,
            definitions,
        ),
        AstPlace::Index { base, index, .. } => {
            let mut changed = simplify_stack_cookie_check_call_in_expression(
                base,
                stack_pointer_locals,
                definitions,
            );
            changed |= simplify_stack_cookie_check_call_in_expression(
                index,
                stack_pointer_locals,
                definitions,
            );
            changed
        }
        AstPlace::Named { .. } => false,
    }
}

fn simplify_stack_cookie_check_call_in_expression(
    expression: &mut AstExpression,
    stack_pointer_locals: &BTreeSet<String>,
    definitions: &BTreeMap<String, AstExpression>,
) -> bool {
    let mut changed = false;
    match expression {
        AstExpression::Call {
            target, arguments, ..
        } => {
            for argument in arguments.iter_mut() {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    argument,
                    stack_pointer_locals,
                    definitions,
                );
            }
            if arguments.len() > 1
                && matches!(target, AstTarget::Direct(target) if target.starts_with("function_"))
                && let Some(cookie_argument) = arguments
                    .iter()
                    .find(|argument| {
                        is_stack_cookie_expression(argument, definitions, stack_pointer_locals)
                    })
                    .cloned()
            {
                *arguments = vec![cookie_argument];
                changed = true;
            }
        }
        AstExpression::Unary { value, .. }
        | AstExpression::Extract { value, .. }
        | AstExpression::Cast { value, .. }
        | AstExpression::Dereference { pointer: value, .. } => {
            changed |= simplify_stack_cookie_check_call_in_expression(
                value,
                stack_pointer_locals,
                definitions,
            );
        }
        AstExpression::Binary { lhs, rhs, .. }
        | AstExpression::Compare { lhs, rhs, .. }
        | AstExpression::FloatCompare { lhs, rhs, .. }
        | AstExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => {
            changed |= simplify_stack_cookie_check_call_in_expression(
                lhs,
                stack_pointer_locals,
                definitions,
            );
            changed |= simplify_stack_cookie_check_call_in_expression(
                rhs,
                stack_pointer_locals,
                definitions,
            );
        }
        AstExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            changed |= simplify_stack_cookie_check_call_in_expression(
                condition,
                stack_pointer_locals,
                definitions,
            );
            changed |= simplify_stack_cookie_check_call_in_expression(
                when_true,
                stack_pointer_locals,
                definitions,
            );
            changed |= simplify_stack_cookie_check_call_in_expression(
                when_false,
                stack_pointer_locals,
                definitions,
            );
        }
        AstExpression::Concat { parts, .. } => {
            for part in parts {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    part,
                    stack_pointer_locals,
                    definitions,
                );
            }
        }
        AstExpression::Load { address, .. } => {
            changed |= simplify_stack_cookie_check_call_in_expression(
                address,
                stack_pointer_locals,
                definitions,
            );
        }
        AstExpression::Intrinsic { arguments, .. } => {
            for argument in arguments {
                changed |= simplify_stack_cookie_check_call_in_expression(
                    argument,
                    stack_pointer_locals,
                    definitions,
                );
            }
        }
        AstExpression::AddressOf { place, .. } => {
            changed |=
                simplify_stack_cookie_check_call_in_place(place, stack_pointer_locals, definitions);
        }
        AstExpression::Member { base, .. } => {
            changed |= simplify_stack_cookie_check_call_in_expression(
                base,
                stack_pointer_locals,
                definitions,
            );
        }
        AstExpression::Value(_) => {}
    }
    changed
}

fn is_stack_cookie_expression(
    expression: &AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
    stack_pointer_locals: &BTreeSet<String>,
) -> bool {
    let expression = resolve_named_expression(expression, definitions);
    let AstExpression::Binary {
        op: AstBinaryOperation::Xor,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return false;
    };
    (is_stack_cookie_load(lhs, definitions, stack_pointer_locals)
        && is_stack_pointer_expression(rhs, definitions, stack_pointer_locals))
        || (is_stack_cookie_load(rhs, definitions, stack_pointer_locals)
            && is_stack_pointer_expression(lhs, definitions, stack_pointer_locals))
}

fn is_stack_cookie_load(
    expression: &AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
    stack_pointer_locals: &BTreeSet<String>,
) -> bool {
    match resolve_named_expression(expression, definitions) {
        AstExpression::Load {
            address_space:
                AstAddressSpace::Stack
                | AstAddressSpace::Local { .. }
                | AstAddressSpace::Argument { .. }
                | AstAddressSpace::Spill { .. }
                | AstAddressSpace::Incoming { .. },
            ..
        } => true,
        AstExpression::Load { address, .. } => {
            is_stack_slot_address(address, definitions, stack_pointer_locals)
        }
        _ => false,
    }
}

fn is_stack_slot_address(
    expression: &AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
    stack_pointer_locals: &BTreeSet<String>,
) -> bool {
    match resolve_named_expression(expression, definitions) {
        AstExpression::Binary {
            op: AstBinaryOperation::Add | AstBinaryOperation::Sub,
            lhs,
            rhs,
            ..
        } => {
            (is_stack_pointer_expression(lhs, definitions, stack_pointer_locals)
                && is_integer_expression(rhs))
                || (is_stack_pointer_expression(rhs, definitions, stack_pointer_locals)
                    && is_integer_expression(lhs))
        }
        expression => is_stack_pointer_expression(expression, definitions, stack_pointer_locals),
    }
}

fn is_stack_pointer_expression(
    expression: &AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
    stack_pointer_locals: &BTreeSet<String>,
) -> bool {
    match resolve_named_expression(expression, definitions) {
        AstExpression::Value(AstValue::Named { name, .. }) => {
            stack_pointer_locals.contains(name) || is_stack_pointer_name(name)
        }
        _ => false,
    }
}

fn is_stack_pointer_name(name: &str) -> bool {
    matches!(name, "sp" | "rsp" | "esp")
        || name.starts_with("sp.")
        || name.starts_with("rsp.")
        || name.starts_with("esp.")
}

fn is_integer_expression(expression: &AstExpression) -> bool {
    matches!(
        expression,
        AstExpression::Value(AstValue::Integer { .. })
            | AstExpression::Value(AstValue::Null { .. })
    )
}

fn simplify_guarded_shift_conditions(function: &mut AstFunction) -> bool {
    let mut changed = false;
    for block in &mut function.blocks {
        changed |= simplify_guarded_shift_conditions_in_block(block, &BTreeMap::new());
    }
    changed
}

fn materialize_loop_induction_updates(function: &mut AstFunction) {
    for block in &mut function.blocks {
        materialize_loop_induction_updates_in_block(block);
    }
}

fn materialize_loop_induction_updates_in_block(block: &mut AstBlock) {
    for statement in &mut block.statements {
        match statement {
            AstStatement::While { condition, body } => {
                materialize_loop_induction_updates_in_block(body);
                if let Some((name, update)) = loop_induction_update(condition)
                    && !block_assigns_name(body, &name)
                {
                    body.statements.push(AstStatement::Assign {
                        target: AstPlace::Named {
                            name,
                            ty: expression_type(&update),
                        },
                        value: update,
                    });
                }
            }
            AstStatement::Loop { body } => materialize_loop_induction_updates_in_block(body),
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                materialize_loop_induction_updates_in_block(then_body);
                if let Some(else_body) = else_body {
                    materialize_loop_induction_updates_in_block(else_body);
                }
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    materialize_loop_induction_updates_in_block(&mut case.body);
                }
                if let Some(default) = default {
                    materialize_loop_induction_updates_in_block(default);
                }
            }
            _ => {}
        }
    }
}

fn loop_induction_update(condition: &AstExpression) -> Option<(String, AstExpression)> {
    let AstExpression::Compare { lhs, rhs, .. } = condition else {
        return None;
    };
    induction_update_from_expression(lhs).or_else(|| induction_update_from_expression(rhs))
}

fn induction_update_from_expression(expression: &AstExpression) -> Option<(String, AstExpression)> {
    let AstExpression::Binary { op, lhs, rhs, ty } = expression else {
        return None;
    };
    if !matches!(op, AstBinaryOperation::Add | AstBinaryOperation::Sub) {
        return None;
    }

    let (name, value) = match (named_expression(lhs), integer_value(rhs)) {
        (Some(name), Some(offset)) if offset != 0 => (name, expression.clone()),
        (None, Some(_)) => return None,
        _ => match (integer_value(lhs), named_expression(rhs)) {
            (Some(offset), Some(name)) if *op == AstBinaryOperation::Add && offset != 0 => {
                (name, expression.clone())
            }
            _ => return None,
        },
    };

    if expression_type(&value) != *ty {
        return None;
    }

    Some((name.to_string(), value))
}

fn named_expression(expression: &AstExpression) -> Option<&str> {
    match expression {
        AstExpression::Value(AstValue::Named { name, .. }) => Some(name.as_str()),
        _ => None,
    }
}

fn block_assigns_name(block: &AstBlock, name: &str) -> bool {
    block
        .statements
        .iter()
        .any(|statement| statement_assigns_name(statement, name))
}

fn statement_assigns_name(statement: &AstStatement, name: &str) -> bool {
    match statement {
        AstStatement::Assign {
            target: AstPlace::Named { name: target, .. },
            ..
        } => target == name,
        AstStatement::If {
            then_body,
            else_body,
            ..
        } => {
            block_assigns_name(then_body, name)
                || else_body
                    .as_ref()
                    .is_some_and(|else_body| block_assigns_name(else_body, name))
        }
        AstStatement::While { body, .. } | AstStatement::Loop { body } => {
            block_assigns_name(body, name)
        }
        AstStatement::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|case| block_assigns_name(&case.body, name))
                || default
                    .as_ref()
                    .is_some_and(|default| block_assigns_name(default, name))
        }
        _ => false,
    }
}

fn structure_dispatch_regions(function: &mut AstFunction) {
    for block in &mut function.blocks {
        structure_dispatch_regions_in_block(block);
    }
}

fn fold_guard_prefixes_to_fallthrough(function: &mut AstFunction) {
    for block in &mut function.blocks {
        fold_guard_prefixes_to_fallthrough_in_block(block);
    }
}

fn fold_guard_prefixes_to_fallthrough_in_block(block: &mut AstBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_guard_prefixes_to_fallthrough_in_block(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_guard_prefixes_to_fallthrough_in_block(else_body);
                }
            }
            AstStatement::While { body, .. } | AstStatement::Loop { body } => {
                changed |= fold_guard_prefixes_to_fallthrough_in_block(body)
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_guard_prefixes_to_fallthrough_in_block(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_guard_prefixes_to_fallthrough_in_block(default);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < block.statements.len() {
        let Some((replacement, consumed)) =
            fold_guard_prefix_to_fallthrough_at(&block.statements, index)
        else {
            index += 1;
            continue;
        };
        block
            .statements
            .splice(index..(index + consumed), replacement);
        changed = true;
        index += 1;
    }
    changed
}

fn fold_guard_prefix_to_fallthrough_at(
    statements: &[AstStatement],
    start: usize,
) -> Option<(Vec<AstStatement>, usize)> {
    let label_index = statements
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, statement)| label_name(statement).map(|_| index))?;
    if label_index <= start {
        return None;
    }
    if statements[start..label_index]
        .iter()
        .any(|statement| !matches!(statement, AstStatement::If { .. }))
    {
        return None;
    }

    let label = label_name(&statements[label_index])?;
    let mut accepted = Vec::<AstExpression>::new();
    let mut reject = None::<(AstExpression, AstBlock)>;
    collect_fallthrough_guard_prefix(
        &statements[start..label_index],
        label,
        &mut accepted,
        &mut reject,
    );
    let (reject_condition, reject_body) = reject?;
    if accepted.is_empty() {
        return None;
    }
    let mut guard = reject_condition;
    for condition in accepted {
        guard = AstExpression::Binary {
            op: AstBinaryOperation::And,
            lhs: Box::new(guard),
            rhs: Box::new(negate_ast_condition(condition)),
            ty: AstType::integer(1),
        };
    }

    Some((
        vec![AstStatement::If {
            condition: simplified_expression(guard),
            then_body: reject_body,
            else_body: None,
        }],
        label_index - start + 1,
    ))
}

fn collect_fallthrough_guard_prefix(
    statements: &[AstStatement],
    label: &str,
    accepted: &mut Vec<AstExpression>,
    reject: &mut Option<(AstExpression, AstBlock)>,
) -> bool {
    let accepted_before = accepted.len();
    let had_reject = reject.is_some();
    for statement in statements {
        collect_fallthrough_guard_statement(statement, label, accepted, reject);
    }
    accepted.len() != accepted_before || reject.is_some() != had_reject
}

fn collect_fallthrough_guard_statement(
    statement: &AstStatement,
    label: &str,
    accepted: &mut Vec<AstExpression>,
    reject: &mut Option<(AstExpression, AstBlock)>,
) -> bool {
    let accepted_before = accepted.len();
    let had_reject = reject.is_some();
    let AstStatement::If {
        condition,
        then_body,
        else_body,
    } = statement
    else {
        return false;
    };
    if else_body.is_some() {
        return false;
    }
    if single_direct_goto_target(then_body) == Some(label) {
        if !accepted.iter().any(|existing| existing == condition) {
            accepted.push(condition.clone());
        }
        return true;
    }
    if body_is_terminal(then_body) && reject.is_none() {
        *reject = Some((condition.clone(), then_body.clone()));
        return true;
    }
    if collect_fallthrough_guard_prefix(&then_body.statements, label, accepted, reject) {
        let fallthrough_condition = negate_ast_condition(condition.clone());
        if !accepted
            .iter()
            .any(|existing| existing == &fallthrough_condition)
        {
            accepted.push(fallthrough_condition);
        }
    }
    accepted.len() != accepted_before || reject.is_some() != had_reject
}

fn negate_ast_condition(condition: AstExpression) -> AstExpression {
    simplified_expression(AstExpression::Unary {
        op: AstUnaryOperation::LogicalNot,
        value: Box::new(condition),
        ty: AstType::integer(1),
    })
}

fn structure_dispatch_regions_in_block(block: &mut AstBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            AstStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= structure_dispatch_regions_in_block(then_body);
                if let Some(else_body) = else_body {
                    changed |= structure_dispatch_regions_in_block(else_body);
                }
            }
            AstStatement::While { body, .. } | AstStatement::Loop { body } => {
                changed |= structure_dispatch_regions_in_block(body)
            }
            AstStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= structure_dispatch_regions_in_block(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= structure_dispatch_regions_in_block(default);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < block.statements.len() {
        let Some((replacement, consumed)) = structure_dispatch_region_at(&block.statements, index)
        else {
            index += 1;
            continue;
        };
        block
            .statements
            .splice(index..(index + consumed), replacement);
        changed = true;
        index += 1;
    }
    changed
}

#[derive(Clone)]
struct DispatchCase {
    label: String,
    conditions: Vec<AstExpression>,
    body: Vec<AstStatement>,
}

fn structure_dispatch_region_at(
    statements: &[AstStatement],
    start: usize,
) -> Option<(Vec<AstStatement>, usize)> {
    let first_label = statements
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, statement)| label_name(statement).map(|_| index))?;
    if first_label <= start {
        return None;
    }

    let default_goto_index = first_label.checked_sub(1)?;
    let join_label = direct_goto_target(statements.get(default_goto_index)?)?.to_string();
    let default_start = (start..default_goto_index)
        .find(|index| !matches!(statements[*index], AstStatement::If { .. }))
        .unwrap_or(default_goto_index);
    if default_start == default_goto_index {
        return None;
    }

    let mut case_bodies = BTreeMap::<String, Vec<AstStatement>>::new();
    let mut cursor = first_label;
    let mut join_index = None;
    while cursor < statements.len() {
        let Some(label) = statements.get(cursor).and_then(label_name) else {
            return None;
        };
        if label == join_label {
            join_index = Some(cursor);
            break;
        }

        let body_start = cursor + 1;
        let body_end = ((body_start)..statements.len())
            .find(|index| matches!(statements[*index], AstStatement::Label(_)))
            .unwrap_or(statements.len());
        let mut body = statements[body_start..body_end].to_vec();
        match body.last() {
            Some(AstStatement::Goto(AstTarget::Direct(target))) if target == &join_label => {
                body.pop();
            }
            _ if body_end < statements.len()
                && matches!(
                    statements.get(body_end),
                    Some(AstStatement::Label(label)) if label == &join_label
                ) => {}
            _ => return None,
        }
        case_bodies.insert(label.to_string(), body);
        cursor = body_end;
    }
    let join_index = join_index?;

    let mut cases = Vec::<DispatchCase>::new();
    let mut reject_guards = Vec::<AstStatement>::new();
    collect_dispatch_conditions(
        &statements[start..default_start],
        &case_bodies,
        &mut cases,
        &mut reject_guards,
    );
    if cases.is_empty() {
        return None;
    }
    for case in &mut cases {
        case.body = case_bodies.get(&case.label)?.clone();
    }

    let mut default_body = reject_guards;
    default_body.extend_from_slice(&statements[default_start..default_goto_index]);
    let dispatch = build_dispatch_if_chain(cases, default_body)?;
    let mut replacement = vec![dispatch];
    replacement.extend_from_slice(&statements[(join_index + 1)..]);

    Some((replacement, statements.len() - start))
}

fn collect_dispatch_conditions(
    statements: &[AstStatement],
    case_bodies: &BTreeMap<String, Vec<AstStatement>>,
    cases: &mut Vec<DispatchCase>,
    reject_guards: &mut Vec<AstStatement>,
) {
    for statement in statements {
        collect_dispatch_conditions_in_statement(statement, case_bodies, cases, reject_guards);
    }
}

fn collect_dispatch_conditions_in_statement(
    statement: &AstStatement,
    case_bodies: &BTreeMap<String, Vec<AstStatement>>,
    cases: &mut Vec<DispatchCase>,
    reject_guards: &mut Vec<AstStatement>,
) {
    let AstStatement::If {
        condition,
        then_body,
        else_body,
    } = statement
    else {
        return;
    };
    if else_body.is_some() {
        return;
    }
    if let Some(target) = single_direct_goto_target(then_body)
        && case_bodies.contains_key(target)
    {
        push_dispatch_condition(cases, target, condition.clone());
        return;
    }
    if body_is_terminal(then_body) {
        reject_guards.push(statement.clone());
        return;
    }
    collect_dispatch_conditions(&then_body.statements, case_bodies, cases, reject_guards);
}

fn push_dispatch_condition(cases: &mut Vec<DispatchCase>, label: &str, condition: AstExpression) {
    if cases.iter().any(|case| {
        case.conditions
            .iter()
            .any(|existing| existing == &condition)
    }) {
        return;
    }
    if let Some(case) = cases.iter_mut().find(|case| case.label == label) {
        case.conditions.push(condition);
        return;
    }
    cases.push(DispatchCase {
        label: label.to_string(),
        conditions: vec![condition],
        body: Vec::new(),
    });
}

fn build_dispatch_if_chain(
    cases: Vec<DispatchCase>,
    default_body: Vec<AstStatement>,
) -> Option<AstStatement> {
    let mut else_body = (!default_body.is_empty()).then_some(AstBlock {
        statements: default_body,
    });
    for case in cases.into_iter().rev() {
        let condition = disjoin_conditions(case.conditions)?;
        let statement = AstStatement::If {
            condition,
            then_body: AstBlock {
                statements: case.body,
            },
            else_body,
        };
        else_body = Some(AstBlock {
            statements: vec![statement],
        });
    }
    else_body?.statements.into_iter().next()
}

fn disjoin_conditions(mut conditions: Vec<AstExpression>) -> Option<AstExpression> {
    let mut condition = conditions.pop()?;
    while let Some(next) = conditions.pop() {
        condition = AstExpression::Binary {
            op: AstBinaryOperation::Or,
            lhs: Box::new(next),
            rhs: Box::new(condition),
            ty: AstType::integer(1),
        };
    }
    Some(condition)
}

fn label_name(statement: &AstStatement) -> Option<&str> {
    match statement {
        AstStatement::Label(label) => Some(label.as_str()),
        _ => None,
    }
}

fn direct_goto_target(statement: &AstStatement) -> Option<&str> {
    match statement {
        AstStatement::Goto(AstTarget::Direct(target)) => Some(target.as_str()),
        _ => None,
    }
}

fn single_direct_goto_target(block: &AstBlock) -> Option<&str> {
    match block.statements.as_slice() {
        [AstStatement::Goto(AstTarget::Direct(target))] => Some(target.as_str()),
        _ => None,
    }
}

fn body_is_terminal(block: &AstBlock) -> bool {
    block.statements.last().is_some_and(statement_is_terminal)
}

fn statement_is_terminal(statement: &AstStatement) -> bool {
    matches!(
        statement,
        AstStatement::Return { .. } | AstStatement::Trap | AstStatement::Unreachable
    )
}

fn simplify_guarded_shift_conditions_in_block(
    block: &mut AstBlock,
    incoming_definitions: &BTreeMap<String, AstExpression>,
) -> bool {
    let mut definitions = incoming_definitions.clone();
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            AstStatement::Assign {
                target: AstPlace::Named { name, .. },
                value,
            } => {
                changed |= simplify_expression_in_place(value, &definitions);
                definitions.insert(name.clone(), value.clone());
            }
            AstStatement::Assign { target, value } => {
                changed |= simplify_guarded_shift_conditions_in_place(target, &definitions);
                changed |= simplify_expression_in_place(value, &definitions);
            }
            AstStatement::Expr(value) => {
                changed |= simplify_expression_in_place(value, &definitions);
            }
            AstStatement::If {
                condition,
                then_body,
                else_body,
            } => {
                changed |= simplify_expression_in_place(condition, &definitions);
                changed |= simplify_guarded_shift_conditions_in_block(then_body, &definitions);
                if let Some(else_body) = else_body {
                    changed |= simplify_guarded_shift_conditions_in_block(else_body, &definitions);
                }
            }
            AstStatement::While { condition, body } => {
                changed |= simplify_expression_in_place(condition, &definitions);
                changed |= simplify_guarded_shift_conditions_in_block(body, &definitions);
            }
            AstStatement::Loop { body } => {
                changed |= simplify_guarded_shift_conditions_in_block(body, &definitions)
            }
            AstStatement::Switch {
                value,
                cases,
                default,
            } => {
                changed |= simplify_expression_in_place(value, &definitions);
                for case in cases {
                    changed |=
                        simplify_guarded_shift_conditions_in_block(&mut case.body, &definitions);
                }
                if let Some(default) = default {
                    changed |= simplify_guarded_shift_conditions_in_block(default, &definitions);
                }
            }
            AstStatement::Return { values } => {
                for value in values {
                    changed |= simplify_expression_in_place(value, &definitions);
                }
            }
            AstStatement::Goto(target) => {
                changed |= simplify_guarded_shift_conditions_in_target(target, &definitions)
            }
            AstStatement::Break
            | AstStatement::Continue
            | AstStatement::Comment(_)
            | AstStatement::Label(_)
            | AstStatement::Trap
            | AstStatement::Unreachable => {}
        }
    }
    changed
}

fn simplify_expression_in_place(
    expression: &mut AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
) -> bool {
    let simplified = simplify_expression_with_definitions(expression.clone(), definitions);
    if &simplified == expression {
        return false;
    }
    *expression = simplified;
    true
}

fn simplify_expression_with_definitions(
    expression: AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
) -> AstExpression {
    let expression = simplify_guarded_shift_compare(&expression, definitions).unwrap_or(expression);
    simplified_expression(expression)
}

fn simplify_guarded_shift_conditions_in_place(
    place: &mut AstPlace,
    definitions: &BTreeMap<String, AstExpression>,
) -> bool {
    match place {
        AstPlace::Dereference { pointer, .. }
        | AstPlace::Memory {
            address: pointer, ..
        } => simplify_expression_in_place(pointer, definitions),
        AstPlace::Index { base, index, .. } => {
            let mut changed = simplify_expression_in_place(base, definitions);
            changed |= simplify_expression_in_place(index, definitions);
            changed
        }
        AstPlace::Named { .. } => false,
    }
}

fn simplify_guarded_shift_conditions_in_target(
    target: &mut AstTarget,
    definitions: &BTreeMap<String, AstExpression>,
) -> bool {
    if let AstTarget::Indirect(expression) = target {
        return simplify_expression_in_place(expression, definitions);
    }
    false
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
            | AstStatement::Comment(_)
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
        AstExpression::Dereference { pointer, .. } => count_expression_uses(pointer, uses),
        AstExpression::Member { base, .. } => count_expression_uses(base, uses),
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
        AstPlace::Dereference { pointer, .. }
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
        | AstStatement::Comment(_)
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
        AstExpression::Dereference { pointer, .. } => {
            replace_expression_values(pointer, replacements)
        }
        AstExpression::Member { base, .. } => replace_expression_values(base, replacements),
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
        AstPlace::Dereference { pointer, .. }
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
            AstStatement::Assign { target, value } if is_self_assignment(target, value) => {}
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

fn is_self_assignment(target: &AstPlace, value: &AstExpression) -> bool {
    matches!(
        (target, value),
        (
            AstPlace::Named { name: target, .. },
            AstExpression::Value(AstValue::Named { name: value, .. })
        ) if target == value
    )
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
        | AstExpression::Dereference {
            pointer: address, ..
        } => expression_has_side_effects(address),
        AstExpression::Member { base, .. } => expression_has_side_effects(base),
        AstExpression::AddressOf { place, .. } => place_has_side_effects(place),
        AstExpression::Value(_) => false,
    }
}

fn place_has_side_effects(place: &AstPlace) -> bool {
    match place {
        AstPlace::Named { .. } => false,
        AstPlace::Dereference { pointer, .. }
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
        | AstStatement::Comment(_)
        | AstStatement::Label(_)
        | AstStatement::Trap
        | AstStatement::Unreachable => {}
    }
}

fn simplify_place_expressions(place: &mut AstPlace) {
    match place {
        AstPlace::Named { .. } => {}
        AstPlace::Dereference { pointer, .. }
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
            value if expression_type(&value) == ty => value,
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
            abi,
            arguments,
            return_types,
        } => AstExpression::Call {
            target,
            abi,
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
        AstExpression::Dereference { pointer, ty } => AstExpression::Dereference {
            pointer: Box::new(simplified_expression(*pointer)),
            ty,
        },
        AstExpression::Index { base, index, ty } => AstExpression::Index {
            base: Box::new(simplified_expression(*base)),
            index: Box::new(simplified_expression(*index)),
            ty,
        },
        AstExpression::Member { base, name, ty } => AstExpression::Member {
            base: Box::new(simplified_expression(*base)),
            name,
            ty,
        },
        AstExpression::Value(value) => AstExpression::Value(value),
    };
    let expression = simplify_algebraic_expression(expression);
    simplify_condition_idiom_expression(expression)
}

fn simplify_algebraic_expression(expression: AstExpression) -> AstExpression {
    if let Some(result) = simplify_zero_compare_with_linear_expression(&expression) {
        return result;
    }
    match expression {
        AstExpression::Unary {
            op: AstUnaryOperation::LogicalNot,
            value,
            ty,
        } => match *value {
            AstExpression::Value(AstValue::Boolean(value)) => {
                AstExpression::Value(AstValue::Boolean(!value))
            }
            AstExpression::Value(AstValue::Integer { value, bits }) => {
                AstExpression::Value(AstValue::Integer {
                    value: i128::from(value == 0),
                    bits,
                })
            }
            value => AstExpression::Unary {
                op: AstUnaryOperation::LogicalNot,
                value: Box::new(value),
                ty,
            },
        },
        AstExpression::Binary { op, lhs, rhs, ty } => {
            simplify_binary_expression(op, *lhs, *rhs, ty)
        }
        AstExpression::Compare { op, lhs, rhs, ty } => {
            if let (Some(lhs), Some(rhs)) = (integer_value(&lhs), integer_value(&rhs)) {
                return AstExpression::Value(AstValue::Boolean(evaluate_integer_compare(
                    op, lhs, rhs,
                )));
            }
            AstExpression::Compare { op, lhs, rhs, ty }
        }
        expression => expression,
    }
}

fn simplify_binary_expression(
    op: AstBinaryOperation,
    lhs: AstExpression,
    rhs: AstExpression,
    ty: AstType,
) -> AstExpression {
    if let (Some(lhs_value), Some(rhs_value)) = (integer_value(&lhs), integer_value(&rhs))
        && let Some(value) = evaluate_integer_binary(op, lhs_value, rhs_value)
    {
        return AstExpression::Value(AstValue::Integer {
            value,
            bits: integer_type_bits(&ty).unwrap_or(64),
        });
    }
    match op {
        AstBinaryOperation::Add if is_zero_expression(&lhs) => rhs,
        AstBinaryOperation::Add if is_zero_expression(&rhs) => lhs,
        AstBinaryOperation::Sub if is_zero_expression(&rhs) => lhs,
        AstBinaryOperation::Sub if lhs == rhs => zero_expression(&ty),
        AstBinaryOperation::Shl | AstBinaryOperation::LShr | AstBinaryOperation::AShr
            if is_zero_expression(&rhs) =>
        {
            lhs
        }
        AstBinaryOperation::Or | AstBinaryOperation::Xor if is_zero_expression(&lhs) => rhs,
        AstBinaryOperation::Or | AstBinaryOperation::Xor if is_zero_expression(&rhs) => lhs,
        AstBinaryOperation::Or if is_all_ones_expression(&lhs, &ty) => lhs,
        AstBinaryOperation::Or if is_all_ones_expression(&rhs, &ty) => rhs,
        AstBinaryOperation::And if is_zero_expression(&lhs) || is_zero_expression(&rhs) => {
            zero_expression(&ty)
        }
        AstBinaryOperation::And if is_all_ones_expression(&lhs, &ty) => rhs,
        AstBinaryOperation::And if is_all_ones_expression(&rhs, &ty) => lhs,
        AstBinaryOperation::Mul if is_zero_expression(&lhs) || is_zero_expression(&rhs) => {
            zero_expression(&ty)
        }
        AstBinaryOperation::Mul if is_one_expression(&lhs) => rhs,
        AstBinaryOperation::Mul if is_one_expression(&rhs) => lhs,
        _ => AstExpression::Binary {
            op,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
            ty,
        },
    }
}

#[derive(Clone)]
struct GuardedShift {
    op: AstBinaryOperation,
    value: AstExpression,
    count: AstExpression,
    ty: AstType,
}

fn simplify_guarded_shift_compare(
    expression: &AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
) -> Option<AstExpression> {
    let AstExpression::Compare { op, lhs, rhs, ty } = expression else {
        return None;
    };
    if !matches!(
        op,
        AstCompareOperation::Eq
            | AstCompareOperation::Ne
            | AstCompareOperation::Ult
            | AstCompareOperation::Ule
            | AstCompareOperation::Ugt
            | AstCompareOperation::Uge
            | AstCompareOperation::Slt
            | AstCompareOperation::Sle
            | AstCompareOperation::Sgt
            | AstCompareOperation::Sge
    ) {
        return None;
    }
    let lhs_shift = guarded_shift(lhs, definitions)?;
    let rhs_shift = guarded_shift(rhs, definitions)?;
    if lhs_shift.op != rhs_shift.op
        || lhs_shift.count != rhs_shift.count
        || lhs_shift.ty != rhs_shift.ty
    {
        return None;
    }
    Some(AstExpression::Compare {
        op: *op,
        lhs: Box::new(AstExpression::Binary {
            op: lhs_shift.op,
            lhs: Box::new(lhs_shift.value),
            rhs: Box::new(lhs_shift.count.clone()),
            ty: lhs_shift.ty.clone(),
        }),
        rhs: Box::new(AstExpression::Binary {
            op: rhs_shift.op,
            lhs: Box::new(rhs_shift.value),
            rhs: Box::new(rhs_shift.count),
            ty: rhs_shift.ty,
        }),
        ty: ty.clone(),
    })
}

fn guarded_shift(
    expression: &AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
) -> Option<GuardedShift> {
    let expression = strip_lossless_casts_and_zero_shifts(expression, definitions);
    if let Some(shift) = raw_guarded_shift(expression, definitions) {
        return Some(shift);
    }
    let AstExpression::Select {
        when_true,
        when_false,
        ..
    } = expression
    else {
        return None;
    };
    let false_shift = raw_guarded_shift(when_false, definitions)?;
    (resolve_named_expression(when_true, definitions) == &false_shift.value).then_some(false_shift)
}

fn raw_guarded_shift(
    expression: &AstExpression,
    definitions: &BTreeMap<String, AstExpression>,
) -> Option<GuardedShift> {
    let expression = strip_lossless_casts_and_zero_shifts(expression, definitions);
    if let AstExpression::Select {
        when_true,
        when_false,
        ..
    } = expression
        && is_zero_expression(resolve_named_expression(when_true, definitions))
    {
        return raw_guarded_shift(when_false, definitions);
    }
    let AstExpression::Binary { op, lhs, rhs, ty } = expression else {
        return None;
    };
    if !matches!(
        op,
        AstBinaryOperation::Shl | AstBinaryOperation::LShr | AstBinaryOperation::AShr
    ) {
        return None;
    }
    let bits = integer_type_bits(ty)?;
    let count = masked_shift_count(rhs, bits, definitions)?;
    Some(GuardedShift {
        op: *op,
        value: resolve_named_expression(lhs, definitions).clone(),
        count,
        ty: ty.clone(),
    })
}

fn masked_shift_count(
    expression: &AstExpression,
    bits: u16,
    definitions: &BTreeMap<String, AstExpression>,
) -> Option<AstExpression> {
    let expression = resolve_named_expression(expression, definitions);
    if let AstExpression::Cast { value, .. } = expression {
        return masked_shift_count(value, bits, definitions);
    }
    if let Some(value) = integer_value(expression)
        && (0..i128::from(bits)).contains(&value)
    {
        return Some(AstExpression::Value(AstValue::Integer {
            value,
            bits: u16::max(8, bits),
        }));
    }
    if let AstExpression::Select {
        when_false,
        when_true,
        ..
    } = expression
        && is_zero_expression(resolve_named_expression(when_true, definitions))
    {
        return masked_shift_count(when_false, bits, definitions);
    }
    let normalized = strip_lossless_casts_and_zero_shifts(expression, definitions);
    if let AstExpression::Extract { lsb: 0, ty, .. } = normalized
        && integer_type_bits(ty).and_then(|count_bits| 1u128.checked_shl(u32::from(count_bits)))
            == Some(u128::from(bits))
    {
        return Some(normalized.clone());
    }
    let AstExpression::Binary {
        op: AstBinaryOperation::And,
        lhs,
        rhs,
        ..
    } = normalized
    else {
        return None;
    };
    let mask = i128::from(bits - 1);
    if integer_value(rhs) == Some(mask) {
        return Some(normalized.clone());
    }
    if integer_value(lhs) == Some(mask) {
        return Some(normalized.clone());
    }
    None
}

fn strip_lossless_casts_and_zero_shifts<'a>(
    expression: &'a AstExpression,
    definitions: &'a BTreeMap<String, AstExpression>,
) -> &'a AstExpression {
    let expression = resolve_named_expression(expression, definitions);
    match expression {
        AstExpression::Cast { value, .. } => {
            strip_lossless_casts_and_zero_shifts(value, definitions)
        }
        AstExpression::Binary {
            op: AstBinaryOperation::LShr | AstBinaryOperation::AShr | AstBinaryOperation::Shl,
            lhs,
            rhs,
            ..
        } if is_zero_expression(resolve_named_expression(rhs, definitions)) => {
            strip_lossless_casts_and_zero_shifts(lhs, definitions)
        }
        _ => expression,
    }
}

fn resolve_named_expression<'a>(
    expression: &'a AstExpression,
    definitions: &'a BTreeMap<String, AstExpression>,
) -> &'a AstExpression {
    let mut expression = expression;
    for _ in 0..16 {
        let AstExpression::Value(AstValue::Named { name, .. }) = expression else {
            return expression;
        };
        let Some(next) = definitions.get(name) else {
            return expression;
        };
        expression = next;
    }
    expression
}

fn simplify_zero_compare_with_linear_expression(
    expression: &AstExpression,
) -> Option<AstExpression> {
    let AstExpression::Compare { op, lhs, rhs, .. } = expression else {
        return None;
    };
    if !matches!(
        op,
        AstCompareOperation::Eq
            | AstCompareOperation::Ne
            | AstCompareOperation::Ult
            | AstCompareOperation::Ule
            | AstCompareOperation::Ugt
            | AstCompareOperation::Uge
            | AstCompareOperation::Slt
            | AstCompareOperation::Sle
            | AstCompareOperation::Sgt
            | AstCompareOperation::Sge
    ) {
        return None;
    }
    let (linear, zero_on_rhs) = if is_zero_expression(rhs) {
        (lhs.as_ref(), true)
    } else if is_zero_expression(lhs) {
        (rhs.as_ref(), false)
    } else {
        return None;
    };
    let (base, delta) = linear_expression(linear)?;
    if delta == 0 {
        return None;
    }
    let rhs = AstExpression::Value(AstValue::Integer {
        value: -delta,
        bits: integer_type_bits(&expression_type(&base)).unwrap_or(64),
    });
    let (lhs, rhs) = if zero_on_rhs {
        (base, rhs)
    } else {
        (rhs, base)
    };
    Some(AstExpression::Compare {
        op: *op,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        ty: AstType::integer(1),
    })
}

fn linear_expression(expression: &AstExpression) -> Option<(AstExpression, i128)> {
    match expression {
        AstExpression::Cast { value, .. } => linear_expression(value),
        AstExpression::Binary {
            op: AstBinaryOperation::Add,
            lhs,
            rhs,
            ..
        } => {
            if let Some(value) = integer_value(rhs) {
                let (base, delta) = linear_expression(lhs)?;
                return Some((base, delta + value));
            }
            if let Some(value) = integer_value(lhs) {
                let (base, delta) = linear_expression(rhs)?;
                return Some((base, delta + value));
            }
            None
        }
        AstExpression::Binary {
            op: AstBinaryOperation::Sub,
            lhs,
            rhs,
            ..
        } => {
            if let Some(value) = integer_value(rhs) {
                let (base, delta) = linear_expression(lhs)?;
                return Some((base, delta - value));
            }
            None
        }
        AstExpression::Value(AstValue::Integer { .. }) => None,
        expression => Some((expression.clone(), 0)),
    }
}

fn integer_value(expression: &AstExpression) -> Option<i128> {
    match expression {
        AstExpression::Value(AstValue::Integer { value, .. }) => Some(*value),
        AstExpression::Value(AstValue::Boolean(value)) => Some(i128::from(*value)),
        AstExpression::Cast { value, .. } => integer_value(value),
        _ => None,
    }
}

fn zero_expression(ty: &AstType) -> AstExpression {
    AstExpression::Value(AstValue::Integer {
        value: 0,
        bits: integer_type_bits(ty).unwrap_or(64),
    })
}

fn is_one_expression(expression: &AstExpression) -> bool {
    matches!(
        expression,
        AstExpression::Value(AstValue::Integer { value: 1, .. })
            | AstExpression::Value(AstValue::Boolean(true))
    )
}

fn is_all_ones_expression(expression: &AstExpression, ty: &AstType) -> bool {
    let Some(bits) = integer_type_bits(ty) else {
        return false;
    };
    let Some(value) = integer_value(expression) else {
        return false;
    };
    if value == -1 {
        return true;
    }
    bits < 128 && value == ((1i128 << bits) - 1)
}

fn evaluate_integer_binary(op: AstBinaryOperation, lhs: i128, rhs: i128) -> Option<i128> {
    match op {
        AstBinaryOperation::Add => lhs.checked_add(rhs),
        AstBinaryOperation::Sub => lhs.checked_sub(rhs),
        AstBinaryOperation::Mul => lhs.checked_mul(rhs),
        AstBinaryOperation::And => Some(lhs & rhs),
        AstBinaryOperation::Or => Some(lhs | rhs),
        AstBinaryOperation::Xor => Some(lhs ^ rhs),
        AstBinaryOperation::Shl => u32::try_from(rhs).ok().and_then(|rhs| lhs.checked_shl(rhs)),
        AstBinaryOperation::LShr | AstBinaryOperation::AShr => {
            u32::try_from(rhs).ok().and_then(|rhs| lhs.checked_shr(rhs))
        }
        AstBinaryOperation::UDiv | AstBinaryOperation::SDiv if rhs != 0 => lhs.checked_div(rhs),
        AstBinaryOperation::URem | AstBinaryOperation::SRem if rhs != 0 => lhs.checked_rem(rhs),
        AstBinaryOperation::FAdd
        | AstBinaryOperation::FSub
        | AstBinaryOperation::FMul
        | AstBinaryOperation::FDiv
        | AstBinaryOperation::RotateLeft
        | AstBinaryOperation::RotateRight
        | AstBinaryOperation::UDiv
        | AstBinaryOperation::SDiv
        | AstBinaryOperation::URem
        | AstBinaryOperation::SRem => None,
    }
}

fn evaluate_integer_compare(op: AstCompareOperation, lhs: i128, rhs: i128) -> bool {
    match op {
        AstCompareOperation::Eq => lhs == rhs,
        AstCompareOperation::Ne => lhs != rhs,
        AstCompareOperation::Ult | AstCompareOperation::Slt => lhs < rhs,
        AstCompareOperation::Ule | AstCompareOperation::Sle => lhs <= rhs,
        AstCompareOperation::Ugt | AstCompareOperation::Sgt => lhs > rhs,
        AstCompareOperation::Uge | AstCompareOperation::Sge => lhs >= rhs,
    }
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
    if let Some(result) = simplify_signed_compare_overflow_idiom(&expression) {
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

fn simplify_signed_compare_overflow_idiom(expression: &AstExpression) -> Option<AstExpression> {
    let AstExpression::Binary {
        op: AstBinaryOperation::Xor,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    simplify_signed_compare_overflow_pair(lhs, rhs)
        .or_else(|| simplify_signed_compare_overflow_pair(rhs, lhs))
}

fn simplify_signed_compare_overflow_pair(
    compare: &AstExpression,
    overflow: &AstExpression,
) -> Option<AstExpression> {
    let AstExpression::Compare {
        op: AstCompareOperation::Slt,
        lhs,
        rhs,
        ..
    } = compare
    else {
        return None;
    };
    let overflow_value = signed_negative_operand(overflow)?;
    if !is_signed_sub_overflow_expression(overflow_value, lhs, rhs) {
        return None;
    }
    Some(AstExpression::Compare {
        op: AstCompareOperation::Slt,
        lhs: Box::new(lhs.as_ref().clone()),
        rhs: Box::new(rhs.as_ref().clone()),
        ty: AstType::integer(1),
    })
}

fn is_signed_sub_overflow_expression(
    expression: &AstExpression,
    lhs: &AstExpression,
    rhs: &AstExpression,
) -> bool {
    let AstExpression::Binary {
        op: AstBinaryOperation::And,
        lhs: overflow_lhs,
        rhs: overflow_rhs,
        ..
    } = peel_ast_casts(expression)
    else {
        return false;
    };
    let Some((xor_lhs_l, xor_lhs_r)) = xor_operands(peel_ast_casts(overflow_lhs)) else {
        return false;
    };
    let Some((xor_rhs_l, xor_rhs_r)) = xor_operands(peel_ast_casts(overflow_rhs)) else {
        return false;
    };
    let expected_sub = AstExpression::Binary {
        op: AstBinaryOperation::Sub,
        lhs: Box::new(peel_ast_casts(lhs).clone()),
        rhs: Box::new(peel_ast_casts(rhs).clone()),
        ty: expression_type(lhs),
    };

    equivalent_idiom_expression(xor_lhs_l, lhs)
        && equivalent_idiom_expression(xor_lhs_r, rhs)
        && equivalent_idiom_expression(xor_rhs_l, lhs)
        && equivalent_idiom_expression(xor_rhs_r, &expected_sub)
}

fn xor_operands(expression: &AstExpression) -> Option<(&AstExpression, &AstExpression)> {
    let AstExpression::Binary {
        op: AstBinaryOperation::Xor,
        lhs,
        rhs,
        ..
    } = expression
    else {
        return None;
    };
    Some((lhs, rhs))
}

fn equivalent_idiom_expression(lhs: &AstExpression, rhs: &AstExpression) -> bool {
    let lhs = peel_ast_casts(lhs);
    let rhs = peel_ast_casts(rhs);
    match (lhs, rhs) {
        (
            AstExpression::Value(AstValue::Integer { value: lhs, .. }),
            AstExpression::Value(AstValue::Integer { value: rhs, .. }),
        ) => lhs == rhs,
        (
            AstExpression::Value(AstValue::Named { name: lhs, .. }),
            AstExpression::Value(AstValue::Named { name: rhs, .. }),
        ) => lhs == rhs,
        (
            AstExpression::Binary {
                op: lhs_op,
                lhs: lhs_lhs,
                rhs: lhs_rhs,
                ..
            },
            AstExpression::Binary {
                op: rhs_op,
                lhs: rhs_lhs,
                rhs: rhs_rhs,
                ..
            },
        ) => {
            lhs_op == rhs_op
                && equivalent_idiom_expression(lhs_lhs, rhs_lhs)
                && equivalent_idiom_expression(lhs_rhs, rhs_rhs)
        }
        _ => lhs == rhs,
    }
}

fn peel_ast_casts(mut expression: &AstExpression) -> &AstExpression {
    while let AstExpression::Cast { value, .. } = expression {
        expression = value;
    }
    expression
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
        | AstExpression::Dereference { ty, .. }
        | AstExpression::Index { ty, .. }
        | AstExpression::Member { ty, .. } => ty.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn named(name: &str) -> AstExpression {
        AstExpression::Value(AstValue::Named {
            name: name.to_string(),
            ty: AstType::integer(64),
        })
    }

    fn int(value: i128) -> AstExpression {
        AstExpression::Value(AstValue::Integer { value, bits: 64 })
    }

    fn named_place(name: &str) -> AstPlace {
        AstPlace::Named {
            name: name.to_string(),
            ty: AstType::integer(64),
        }
    }

    #[test]
    fn simplifies_masked_guarded_shift_compare() {
        let ty = AstType::integer(64);
        let mut definitions = BTreeMap::new();
        definitions.insert("count".to_string(), int(0x30));
        definitions.insert(
            "is_zero".to_string(),
            AstExpression::Compare {
                op: AstCompareOperation::Eq,
                lhs: Box::new(named("count")),
                rhs: Box::new(int(0)),
                ty: AstType::integer(1),
            },
        );
        definitions.insert(
            "too_large".to_string(),
            AstExpression::Compare {
                op: AstCompareOperation::Uge,
                lhs: Box::new(named("count")),
                rhs: Box::new(int(0x40)),
                ty: AstType::integer(1),
            },
        );
        definitions.insert(
            "safe_count".to_string(),
            AstExpression::Select {
                condition: Box::new(named("too_large")),
                when_true: Box::new(int(0)),
                when_false: Box::new(named("count")),
                ty: ty.clone(),
            },
        );
        let guarded = |value: AstExpression| AstExpression::Select {
            condition: Box::new(named("is_zero")),
            when_true: Box::new(value.clone()),
            when_false: Box::new(AstExpression::Select {
                condition: Box::new(named("too_large")),
                when_true: Box::new(int(0)),
                when_false: Box::new(AstExpression::Binary {
                    op: AstBinaryOperation::LShr,
                    lhs: Box::new(value),
                    rhs: Box::new(named("safe_count")),
                    ty: ty.clone(),
                }),
                ty: ty.clone(),
            }),
            ty: ty.clone(),
        };
        let expression = AstExpression::Compare {
            op: AstCompareOperation::Ne,
            lhs: Box::new(guarded(named("lhs"))),
            rhs: Box::new(guarded(named("rhs"))),
            ty: AstType::integer(1),
        };
        let simplified = simplify_guarded_shift_compare(&expression, &definitions).unwrap();
        assert!(matches!(
            simplified,
            AstExpression::Compare {
                lhs,
                rhs,
                ..
            } if matches!(*lhs, AstExpression::Binary { op: AstBinaryOperation::LShr, .. })
                && matches!(*rhs, AstExpression::Binary { op: AstBinaryOperation::LShr, .. })
        ));
    }

    #[test]
    fn simplifies_zero_shift_and_linear_less_than_zero() {
        let shifted = simplified_expression(AstExpression::Binary {
            op: AstBinaryOperation::LShr,
            lhs: Box::new(named("x")),
            rhs: Box::new(int(0)),
            ty: AstType::integer(64),
        });
        assert_eq!(shifted, named("x"));

        let expression = AstExpression::Compare {
            op: AstCompareOperation::Slt,
            lhs: Box::new(AstExpression::Binary {
                op: AstBinaryOperation::Sub,
                lhs: Box::new(AstExpression::Binary {
                    op: AstBinaryOperation::Sub,
                    lhs: Box::new(named("x")),
                    rhs: Box::new(int(0x10)),
                    ty: AstType::integer(64),
                }),
                rhs: Box::new(int(0x10)),
                ty: AstType::integer(64),
            }),
            rhs: Box::new(int(0)),
            ty: AstType::integer(1),
        };
        let simplified = simplified_expression(expression);
        assert!(matches!(
            simplified,
            AstExpression::Compare {
                op: AstCompareOperation::Slt,
                lhs,
                rhs,
                ..
            } if *lhs == named("x") && integer_value(&rhs) == Some(0x20)
        ));
    }

    #[test]
    fn simplifies_signed_compare_overflow_idiom_after_linear_compare() {
        let expression = AstExpression::Binary {
            op: AstBinaryOperation::Xor,
            lhs: Box::new(AstExpression::Compare {
                op: AstCompareOperation::Slt,
                lhs: Box::new(AstExpression::Cast {
                    op: crate::irs::ast::AstCastOperation::Truncate,
                    value: Box::new(named("x")),
                    ty: AstType::integer(32),
                }),
                rhs: Box::new(AstExpression::Value(AstValue::Integer {
                    value: 0x13,
                    bits: 32,
                })),
                ty: AstType::integer(1),
            }),
            rhs: Box::new(AstExpression::Compare {
                op: AstCompareOperation::Slt,
                lhs: Box::new(AstExpression::Cast {
                    op: crate::irs::ast::AstCastOperation::Truncate,
                    value: Box::new(AstExpression::Binary {
                        op: AstBinaryOperation::And,
                        lhs: Box::new(AstExpression::Binary {
                            op: AstBinaryOperation::Xor,
                            lhs: Box::new(named("x")),
                            rhs: Box::new(int(0x13)),
                            ty: AstType::integer(64),
                        }),
                        rhs: Box::new(AstExpression::Binary {
                            op: AstBinaryOperation::Xor,
                            lhs: Box::new(named("x")),
                            rhs: Box::new(AstExpression::Binary {
                                op: AstBinaryOperation::Sub,
                                lhs: Box::new(named("x")),
                                rhs: Box::new(int(0x13)),
                                ty: AstType::integer(64),
                            }),
                            ty: AstType::integer(64),
                        }),
                        ty: AstType::integer(64),
                    }),
                    ty: AstType::integer(32),
                }),
                rhs: Box::new(AstExpression::Value(AstValue::Integer {
                    value: 0,
                    bits: 32,
                })),
                ty: AstType::integer(1),
            }),
            ty: AstType::integer(1),
        };

        let simplified = simplified_expression(expression);

        assert!(matches!(
            simplified,
            AstExpression::Compare {
                op: AstCompareOperation::Slt,
                lhs,
                rhs,
                ..
            } if matches!(*lhs, AstExpression::Cast { .. }) && integer_value(&rhs) == Some(0x13)
        ));
    }

    #[test]
    fn removes_self_assignments() {
        let mut function = AstFunction {
            locals: vec![crate::irs::ast::AstLocal {
                name: "x".to_string(),
                display_name: None,
                ty: AstType::integer(64),
                init: None,
                storage: None,
                comment: None,
            }],
            blocks: vec![AstBlock {
                statements: vec![
                    AstStatement::Assign {
                        target: named_place("x"),
                        value: named("x"),
                    },
                    AstStatement::Return {
                        values: vec![named("x")],
                    },
                ],
            }],
            ..AstFunction::default()
        };

        optimize_ast_function(&mut function);

        assert_eq!(
            function.blocks[0].statements,
            vec![AstStatement::Return {
                values: vec![named("x")]
            }]
        );
    }
}
