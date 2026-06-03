use crate::ir::hir::optimizers::boolean::{optimize_boolean, simplify_logical_not};
use crate::ir::hir::{
    HirBinaryOperation, HirBlock, HirExpression, HirFunction, HirModule, HirStatement, HirTarget,
    HirType,
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_CFG_OPTIMIZE_ITERATIONS: usize = 64;

pub fn optimize_cfg(function: &mut HirFunction) {
    for block in &mut function.blocks {
        for _ in 0..MAX_CFG_OPTIMIZE_ITERATIONS {
            let mut changed = false;
            changed |= inline_single_entry_regions(block);
            changed |= structure_top_level_regions(block);
            changed |= collapse_guard_jump_chains(block);
            changed |= fold_forward_guard_regions(block);
            changed |= recover_if_no_exit_regions(block);
            changed |= fold_known_conditions(block, &[]);
            changed |= replace_return_gotos(block);
            changed |= fold_two_entry_continuation_regions(block);
            changed |= fold_guarded_return_continuation_regions(block);
            changed |= fold_two_path_return_continuations(block);
            changed |= inline_terminal_label_gotos(block);
            changed |= fold_return_guarded_continuations(block);
            changed |= fold_shared_terminal_if_tails(block);
            changed |= eliminate_redundant_terminal_if_suffixes(block);
            changed |= fold_if_fallthrough_labels(block);
            changed |= simplify_if_goto_chains(block);
            changed |= remove_fallthrough_gotos(block);
            changed |= recover_while_loops(block);
            changed |= fold_loop_breaks_to_while(block);
            changed |= prune_unreferenced_labels(block);
            changed |= remove_unreachable_after_terminal(block);
            if !changed {
                break;
            }
        }
    }
    optimize_boolean(function);
}

pub fn optimize_cfg_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_cfg(function);
    }
}

#[derive(Clone)]
struct InlineRegion {
    start: usize,
    end: usize,
    label: String,
    statements: Vec<HirStatement>,
}

#[derive(Clone)]
struct StructuredRegion {
    label: Option<String>,
    statements: Vec<HirStatement>,
}

#[derive(Clone)]
struct BranchExit {
    join_label: String,
    body: Vec<HirStatement>,
}

fn inline_single_entry_regions(block: &mut HirBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= inline_single_entry_regions(then_body);
                if let Some(else_body) = else_body {
                    changed |= inline_single_entry_regions(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= inline_single_entry_regions(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= inline_single_entry_regions(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= inline_single_entry_regions(default);
                }
            }
            _ => {}
        }
    }

    loop {
        let Some(region) = find_inlineable_region(block) else {
            break;
        };
        if !inline_region_at_single_jump(block, &region) {
            break;
        }
        block.statements.drain(region.start..region.end);
        changed = true;
    }

    changed
}

fn structure_top_level_regions(block: &mut HirBlock) -> bool {
    let mut changed = false;
    loop {
        let Some(regions) = collect_top_level_regions(block) else {
            break;
        };
        let Some(new_regions) = collapse_region_if_else_joins(&regions)
            .or_else(|| collapse_small_single_ref_continuations(&regions))
        else {
            break;
        };
        block.statements = emit_top_level_regions(&new_regions);
        changed = true;
    }
    changed
}

fn collect_top_level_regions(block: &HirBlock) -> Option<Vec<StructuredRegion>> {
    if block.statements.is_empty() {
        return None;
    }
    let mut regions = Vec::new();
    let mut start = 0;
    let mut current_label = None;

    if let Some(HirStatement::Label(label)) = block.statements.first() {
        current_label = Some(label.clone());
        start = 1;
    }

    for index in start..block.statements.len() {
        if let HirStatement::Label(label) = &block.statements[index] {
            regions.push(StructuredRegion {
                label: current_label.take(),
                statements: block.statements[start..index].to_vec(),
            });
            current_label = Some(label.clone());
            start = index + 1;
        }
    }

    regions.push(StructuredRegion {
        label: current_label,
        statements: block.statements[start..].to_vec(),
    });

    Some(regions)
}

fn emit_top_level_regions(regions: &[StructuredRegion]) -> Vec<HirStatement> {
    let mut statements = Vec::new();
    for region in regions {
        if let Some(label) = &region.label {
            statements.push(HirStatement::Label(label.clone()));
        }
        statements.extend(region.statements.clone());
    }
    statements
}

fn collapse_region_if_else_joins(regions: &[StructuredRegion]) -> Option<Vec<StructuredRegion>> {
    let label_to_index = regions
        .iter()
        .enumerate()
        .filter_map(|(index, region)| region.label.as_ref().map(|label| (label.clone(), index)))
        .collect::<BTreeMap<_, _>>();
    let label_ref_counts = collect_region_label_reference_counts(regions);

    for index in 0..regions.len() {
        let (condition, then_target, else_target, prefix) =
            region_terminal_if_else(&regions[index])?;
        let then_index = *label_to_index.get(&then_target)?;
        let else_index = *label_to_index.get(&else_target)?;
        if then_index == else_index || then_index <= index || else_index <= index {
            continue;
        }
        let first_index = then_index.min(else_index);
        let second_index = then_index.max(else_index);
        if second_index != first_index + 1 {
            continue;
        }

        let join_then = branch_region_exit(
            &regions[then_index],
            regions
                .get(then_index + 1)
                .and_then(|region| region.label.as_deref()),
            &label_ref_counts,
        )?;
        let join_else = branch_region_exit(
            &regions[else_index],
            regions
                .get(else_index + 1)
                .and_then(|region| region.label.as_deref()),
            &label_ref_counts,
        )?;
        if join_then.join_label != join_else.join_label {
            continue;
        }
        if label_ref_counts
            .get(&join_then.join_label)
            .copied()
            .unwrap_or(0)
            != 2
        {
            continue;
        }

        let (then_body, else_body) = if then_index < else_index {
            (join_then.body, join_else.body)
        } else {
            (join_else.body, join_then.body)
        };

        let mut new_regions = Vec::with_capacity(regions.len() - 2);
        for region in &regions[..index] {
            new_regions.push(region.clone());
        }

        let mut merged_statements = prefix;
        merged_statements.push(HirStatement::If {
            condition,
            then_body: HirBlock {
                statements: then_body,
            },
            else_body: Some(HirBlock {
                statements: else_body,
            }),
        });
        new_regions.push(StructuredRegion {
            label: regions[index].label.clone(),
            statements: merged_statements,
        });

        for (candidate, region) in regions.iter().enumerate().skip(index + 1) {
            if candidate == then_index || candidate == else_index {
                continue;
            }
            new_regions.push(region.clone());
        }
        return Some(new_regions);
    }

    None
}

fn collapse_small_single_ref_continuations(
    regions: &[StructuredRegion],
) -> Option<Vec<StructuredRegion>> {
    let label_ref_counts = collect_region_label_reference_counts(regions);

    for target_index in 1..regions.len() {
        let Some(label) = regions[target_index].label.as_ref() else {
            continue;
        };
        if label_ref_counts.get(label).copied().unwrap_or(0) != 1 {
            continue;
        }
        if !region_can_fallthrough(&regions[target_index - 1]) {
            continue;
        }
        let body = &regions[target_index].statements;
        if body.is_empty()
            || body.len() > 16
            || region_contains_label_refs(body)
            || region_clone_cost(body) > 14
        {
            continue;
        }

        let continuation_label = regions
            .get(target_index + 1)
            .and_then(|region| region.label.as_ref())
            .cloned();

        let mut source_index = None;
        let mut rewritten_source = None;
        for (index, region) in regions.iter().enumerate() {
            let Some((rewritten, _replaced)) = rewrite_region_target_tail(
                &region.statements,
                label,
                body,
                continuation_label.as_deref(),
            ) else {
                continue;
            };
            source_index = Some(index);
            rewritten_source = Some(rewritten);
            break;
        }
        let (source_index, rewritten_source) = match (source_index, rewritten_source) {
            (Some(index), Some(statements)) => (index, statements),
            _ => continue,
        };

        let mut new_regions = Vec::with_capacity(regions.len() - 1);
        for region in &regions[..(target_index - 1)] {
            new_regions.push(region.clone());
        }

        let mut merged_predecessor = regions[target_index - 1].clone();
        merged_predecessor.statements.extend(body.clone());
        new_regions.push(merged_predecessor);

        for (index, region) in regions.iter().enumerate().skip(target_index + 1) {
            let mut region = region.clone();
            if index == source_index {
                region.statements = rewritten_source.clone();
            }
            new_regions.push(region);
        }

        if source_index < target_index - 1 {
            new_regions[source_index].statements = rewritten_source;
        } else if source_index == target_index - 1 {
            let current = new_regions[target_index - 1].statements.clone();
            new_regions[target_index - 1].statements =
                rewrite_region_target_tail(&current, label, body, continuation_label.as_deref())?.0;
        }

        return Some(new_regions);
    }

    None
}

fn region_can_fallthrough(region: &StructuredRegion) -> bool {
    region
        .statements
        .last()
        .is_none_or(|statement| !statement_prevents_fallthrough(statement))
}

fn region_clone_cost(statements: &[HirStatement]) -> usize {
    statements.iter().map(statement_clone_cost).sum()
}

fn statement_clone_cost(statement: &HirStatement) -> usize {
    match statement {
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            2 + region_clone_cost(&then_body.statements)
                + else_body
                    .as_ref()
                    .map(|else_body| region_clone_cost(&else_body.statements))
                    .unwrap_or(0)
        }
        HirStatement::While { .. } | HirStatement::Loop { .. } | HirStatement::Switch { .. } => 100,
        HirStatement::Label(_) | HirStatement::Goto(_) => 100,
        _ => 1,
    }
}

fn rewrite_region_target_tail(
    statements: &[HirStatement],
    target_label: &str,
    body: &[HirStatement],
    continuation_label: Option<&str>,
) -> Option<(Vec<HirStatement>, usize)> {
    let last = statements.last()?;
    let mut cloned_body = body.to_vec();
    if let Some(continuation_label) = continuation_label {
        if cloned_body
            .last()
            .is_none_or(|statement| !statement_prevents_fallthrough(statement))
        {
            cloned_body.push(HirStatement::Goto(HirTarget::Direct(
                continuation_label.to_string(),
            )));
        }
    }

    match last {
        HirStatement::Goto(HirTarget::Direct(target)) if target == target_label => {
            let mut new_statements = statements[..(statements.len() - 1)].to_vec();
            new_statements.extend(cloned_body);
            Some((new_statements, 1))
        }
        HirStatement::If {
            condition,
            then_body,
            else_body,
        } => {
            let then_replaced = if single_direct_goto_target(then_body) == Some(target_label) {
                Some(HirBlock {
                    statements: cloned_body.clone(),
                })
            } else {
                None
            };
            let else_replaced = else_body.as_ref().and_then(|else_body| {
                if single_direct_goto_target(else_body) == Some(target_label) {
                    Some(HirBlock {
                        statements: cloned_body.clone(),
                    })
                } else {
                    None
                }
            });
            if then_replaced.is_none() && else_replaced.is_none() {
                return None;
            }
            let mut replaced_count = 0;
            if then_replaced.is_some() {
                replaced_count += 1;
            }
            if else_replaced.is_some() {
                replaced_count += 1;
            }
            let mut new_statements = statements[..(statements.len() - 1)].to_vec();
            new_statements.push(HirStatement::If {
                condition: condition.clone(),
                then_body: then_replaced.unwrap_or_else(|| then_body.clone()),
                else_body: match (else_body, else_replaced) {
                    (Some(_), Some(block)) => Some(block),
                    (Some(existing), None) => Some(existing.clone()),
                    (None, _) => None,
                },
            });
            Some((new_statements, replaced_count))
        }
        _ => None,
    }
}

fn collect_region_label_reference_counts(regions: &[StructuredRegion]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for region in regions {
        let block = HirBlock {
            statements: region.statements.clone(),
        };
        for (label, count) in collect_label_reference_counts(&block) {
            *counts.entry(label).or_insert(0) += count;
        }
    }
    counts
}

fn region_terminal_if_else(
    region: &StructuredRegion,
) -> Option<(HirExpression, String, String, Vec<HirStatement>)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = region.statements.last()?
    else {
        return None;
    };
    let else_body = else_body.as_ref()?;
    let then_target = single_direct_goto_target(then_body)?.to_string();
    let else_target = single_direct_goto_target(else_body)?.to_string();
    if then_target == else_target {
        return None;
    }
    let prefix = region.statements[..(region.statements.len() - 1)].to_vec();
    if region_contains_label_refs(&prefix) {
        return None;
    }
    Some((condition.clone(), then_target, else_target, prefix))
}

fn branch_region_exit(
    region: &StructuredRegion,
    next_region_label: Option<&str>,
    label_ref_counts: &BTreeMap<String, usize>,
) -> Option<BranchExit> {
    let label = region.label.as_ref()?;
    if label_ref_counts.get(label).copied().unwrap_or(0) != 1 {
        return None;
    }
    if region.statements.is_empty() || region.statements.len() > 16 {
        return None;
    }

    let mut body = region.statements.clone();
    if let Some(HirStatement::Goto(HirTarget::Direct(target))) = body.last() {
        let join_label = target.clone();
        body.pop();
        if body.is_empty() || region_contains_label_refs(&body) {
            return None;
        }
        return Some(BranchExit { join_label, body });
    }

    let next_region_label = next_region_label?;
    if region_contains_label_refs(&body) {
        return None;
    }
    Some(BranchExit {
        join_label: next_region_label.to_string(),
        body,
    })
}

fn region_contains_label_refs(statements: &[HirStatement]) -> bool {
    let block = HirBlock {
        statements: statements.to_vec(),
    };
    !collect_label_reference_counts(&block).is_empty()
}

fn find_inlineable_region(block: &HirBlock) -> Option<InlineRegion> {
    let label_refs = collect_label_reference_counts(block);
    let mut index = 0;
    while index < block.statements.len() {
        let HirStatement::Label(label) = &block.statements[index] else {
            index += 1;
            continue;
        };
        if !label_has_no_fallthrough_entry(&block.statements, index) {
            index += 1;
            continue;
        }
        let total_refs = label_refs.get(label).copied().unwrap_or(0);
        if total_refs == 0 {
            index += 1;
            continue;
        }
        let end = next_top_level_label_index(&block.statements, index + 1);
        let region_statements = block.statements[index..end].to_vec();
        let local_refs = collect_label_reference_counts_in_statements(&region_statements);
        let local_labels = collect_local_labels(&region_statements);
        if region_statements.len() > 13 {
            index += 1;
            continue;
        }
        if local_labels.len() != 1 || !local_labels.contains(label) {
            index += 1;
            continue;
        }
        if !region_labels_are_self_contained(
            label,
            total_refs,
            &local_labels,
            &local_refs,
            &label_refs,
        ) {
            index += 1;
            continue;
        }
        let external_refs = total_refs.saturating_sub(local_refs.get(label).copied().unwrap_or(0));
        if external_refs != 1 {
            index += 1;
            continue;
        }

        let omit_entry_label = local_refs.get(label).copied().unwrap_or(0) == 0;
        let statements = if omit_entry_label {
            block.statements[(index + 1)..end].to_vec()
        } else {
            region_statements
        };
        return Some(InlineRegion {
            start: index,
            end,
            label: label.clone(),
            statements,
        });
    }
    None
}

fn region_labels_are_self_contained(
    entry_label: &str,
    entry_total_refs: usize,
    local_labels: &BTreeSet<String>,
    local_refs: &BTreeMap<String, usize>,
    all_refs: &BTreeMap<String, usize>,
) -> bool {
    for label in local_labels {
        let total = all_refs.get(label).copied().unwrap_or(0);
        let local = local_refs.get(label).copied().unwrap_or(0);
        if label == entry_label {
            if total.saturating_sub(local) != 1 {
                return false;
            }
        } else if total != local {
            return false;
        }
    }
    entry_total_refs > 0
}

fn next_top_level_label_index(statements: &[HirStatement], start: usize) -> usize {
    for index in start..statements.len() {
        if matches!(statements[index], HirStatement::Label(_)) {
            return index;
        }
    }
    statements.len()
}

fn label_has_no_fallthrough_entry(statements: &[HirStatement], index: usize) -> bool {
    if index == 0 {
        return true;
    }
    statement_prevents_fallthrough(&statements[index - 1])
}

fn statement_prevents_fallthrough(statement: &HirStatement) -> bool {
    matches!(
        statement,
        HirStatement::Goto(_)
            | HirStatement::Return { .. }
            | HirStatement::Trap
            | HirStatement::Unreachable
            | HirStatement::Break
            | HirStatement::Continue
    )
}

fn inline_region_at_single_jump(block: &mut HirBlock, region: &InlineRegion) -> bool {
    let mut replaced = false;
    inline_region_in_statements(&mut block.statements, region, &mut replaced);
    replaced
}

fn inline_region_in_statements(
    statements: &mut Vec<HirStatement>,
    region: &InlineRegion,
    replaced: &mut bool,
) {
    let mut index = 0;
    while index < statements.len() {
        if *replaced {
            return;
        }
        match &mut statements[index] {
            HirStatement::Goto(HirTarget::Direct(target)) if target == &region.label => {
                statements.splice(index..=index, region.statements.clone());
                *replaced = true;
                return;
            }
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                inline_region_in_statements(&mut then_body.statements, region, replaced);
                if *replaced {
                    return;
                }
                if let Some(else_body) = else_body {
                    inline_region_in_statements(&mut else_body.statements, region, replaced);
                    if *replaced {
                        return;
                    }
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                inline_region_in_statements(&mut body.statements, region, replaced);
                if *replaced {
                    return;
                }
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    inline_region_in_statements(&mut case.body.statements, region, replaced);
                    if *replaced {
                        return;
                    }
                }
                if let Some(default) = default {
                    inline_region_in_statements(&mut default.statements, region, replaced);
                    if *replaced {
                        return;
                    }
                }
            }
            _ => {}
        }
        index += 1;
    }
}

fn collapse_guard_jump_chains(block: &mut HirBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= collapse_guard_jump_chains(then_body);
                if let Some(else_body) = else_body {
                    changed |= collapse_guard_jump_chains(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= collapse_guard_jump_chains(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= collapse_guard_jump_chains(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= collapse_guard_jump_chains(default);
                }
            }
            _ => {}
        }
    }

    let mut index = 0;
    while index < block.statements.len() {
        let Some((target, mut condition)) = extract_guard_jump(&block.statements[index]) else {
            index += 1;
            continue;
        };

        let mut end = index + 1;
        while end < block.statements.len() {
            if matches!(block.statements[end], HirStatement::Label(_))
                || statement_is_terminal(&block.statements[end])
            {
                break;
            }
            let Some((next_target, next_condition)) = extract_guard_jump(&block.statements[end])
            else {
                break;
            };
            if next_target != target {
                break;
            }
            condition = logical_or(condition, next_condition);
            end += 1;
        }

        if end > index + 1 {
            block.statements[index] = HirStatement::If {
                condition,
                then_body: HirBlock {
                    statements: vec![HirStatement::Goto(HirTarget::Direct(target))],
                },
                else_body: None,
            };
            block.statements.drain((index + 1)..end);
            changed = true;
        }

        index += 1;
    }
    changed
}

fn extract_guard_jump(statement: &HirStatement) -> Option<(String, HirExpression)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = statement
    else {
        return None;
    };
    if else_body.is_none() {
        if let Some(target) = single_direct_goto_target(then_body) {
            return Some((target.to_string(), condition.clone()));
        }
        if then_body.statements.len() == 1 {
            if let Some((target, nested_condition)) = extract_guard_jump(&then_body.statements[0]) {
                return Some((target, logical_and(condition.clone(), nested_condition)));
            }
        }
    }
    if let Some(else_body) = else_body {
        if then_body.statements.is_empty() {
            let target = single_direct_goto_target(else_body)?;
            return Some((target.to_string(), negate_condition(condition.clone())));
        }
    }
    None
}

fn logical_or(lhs: HirExpression, rhs: HirExpression) -> HirExpression {
    HirExpression::Binary {
        op: HirBinaryOperation::Or,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        ty: HirType::integer(1),
    }
}

fn logical_and(lhs: HirExpression, rhs: HirExpression) -> HirExpression {
    HirExpression::Binary {
        op: HirBinaryOperation::And,
        lhs: Box::new(lhs),
        rhs: Box::new(rhs),
        ty: HirType::integer(1),
    }
}

fn fold_forward_guard_regions(block: &mut HirBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_forward_guard_regions(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_forward_guard_regions(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_forward_guard_regions(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_forward_guard_regions(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_forward_guard_regions(default);
                }
            }
            _ => {}
        }
    }

    let label_refs = collect_label_reference_counts(block);
    let mut index = 0;
    while index < block.statements.len() {
        let Some((target, negate)) = extract_guard_jump_target(&block.statements[index]) else {
            index += 1;
            continue;
        };
        let Some(label_index) = find_label_index(&block.statements, index + 1, &target) else {
            index += 1;
            continue;
        };
        let middle = &block.statements[(index + 1)..label_index];
        if !region_is_self_contained(middle, &target, &label_refs) {
            index += 1;
            continue;
        }

        let condition = match &block.statements[index] {
            HirStatement::If { condition, .. } => {
                if negate {
                    negate_condition(condition.clone())
                } else {
                    condition.clone()
                }
            }
            _ => unreachable!("forward guard regions must start from if"),
        };

        if middle.is_empty() {
            block.statements.remove(index);
            changed = true;
        } else {
            block.statements[index] = HirStatement::If {
                condition,
                then_body: HirBlock {
                    statements: middle.to_vec(),
                },
                else_body: None,
            };
            block.statements.drain((index + 1)..label_index);
            changed = true;
        }

        if label_refs.get(&target).copied().unwrap_or(0) == 1 {
            if let Some(HirStatement::Label(label)) = block.statements.get(index + 1) {
                if label == &target {
                    block.statements.remove(index + 1);
                }
            }
        }
        index += 1;
    }
    changed
}

fn region_is_self_contained(
    statements: &[HirStatement],
    join_label: &str,
    block_label_refs: &BTreeMap<String, usize>,
) -> bool {
    let local_labels = collect_local_labels(statements);
    let local_ref_counts = collect_label_reference_counts_in_statements(statements);

    for label in &local_labels {
        let total_refs = block_label_refs.get(label).copied().unwrap_or(0);
        let local_refs = local_ref_counts.get(label).copied().unwrap_or(0);
        if total_refs != local_refs {
            return false;
        }
    }

    statements
        .iter()
        .all(|statement| statement_targets_stay_within_region(statement, &local_labels, join_label))
}

fn collect_local_labels(statements: &[HirStatement]) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    for statement in statements {
        collect_local_labels_in_statement(statement, &mut labels);
    }
    labels
}

fn collect_local_labels_in_statement(statement: &HirStatement, labels: &mut BTreeSet<String>) {
    match statement {
        HirStatement::Label(label) => {
            labels.insert(label.clone());
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            for statement in &then_body.statements {
                collect_local_labels_in_statement(statement, labels);
            }
            if let Some(else_body) = else_body {
                for statement in &else_body.statements {
                    collect_local_labels_in_statement(statement, labels);
                }
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            for statement in &body.statements {
                collect_local_labels_in_statement(statement, labels);
            }
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                for statement in &case.body.statements {
                    collect_local_labels_in_statement(statement, labels);
                }
            }
            if let Some(default) = default {
                for statement in &default.statements {
                    collect_local_labels_in_statement(statement, labels);
                }
            }
        }
        _ => {}
    }
}

fn collect_label_reference_counts_in_statements(
    statements: &[HirStatement],
) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for statement in statements {
        collect_label_reference_counts_in_statement(statement, &mut counts);
    }
    counts
}

fn statement_targets_stay_within_region(
    statement: &HirStatement,
    local_labels: &BTreeSet<String>,
    join_label: &str,
) -> bool {
    match statement {
        HirStatement::Goto(HirTarget::Direct(target)) => {
            target == join_label || local_labels.contains(target)
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            then_body.statements.iter().all(|statement| {
                statement_targets_stay_within_region(statement, local_labels, join_label)
            }) && else_body.as_ref().is_none_or(|else_body| {
                else_body.statements.iter().all(|statement| {
                    statement_targets_stay_within_region(statement, local_labels, join_label)
                })
            })
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            body.statements.iter().all(|statement| {
                statement_targets_stay_within_region(statement, local_labels, join_label)
            })
        }
        HirStatement::Switch { cases, default, .. } => {
            cases.iter().all(|case| {
                case.body.statements.iter().all(|statement| {
                    statement_targets_stay_within_region(statement, local_labels, join_label)
                })
            }) && default.as_ref().is_none_or(|default| {
                default.statements.iter().all(|statement| {
                    statement_targets_stay_within_region(statement, local_labels, join_label)
                })
            })
        }
        _ => true,
    }
}

fn recover_if_no_exit_regions(block: &mut HirBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= recover_if_no_exit_regions(then_body);
                if let Some(else_body) = else_body {
                    changed |= recover_if_no_exit_regions(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= recover_if_no_exit_regions(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= recover_if_no_exit_regions(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= recover_if_no_exit_regions(default);
                }
            }
            _ => {}
        }
    }

    let label_refs = collect_label_reference_counts(block);
    let mut index = 0;
    while index < block.statements.len() {
        let Some((target, negate)) = extract_guard_jump_target(&block.statements[index]) else {
            index += 1;
            continue;
        };
        let Some(label_index) = find_label_index(&block.statements, index + 1, &target) else {
            index += 1;
            continue;
        };
        if label_index <= index + 1 {
            index += 1;
            continue;
        }
        let body = &block.statements[(index + 1)..label_index];
        if body.iter().any(|statement| {
            matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
                || statement_is_terminal(statement)
        }) {
            index += 1;
            continue;
        }

        let condition = match &block.statements[index] {
            HirStatement::If { condition, .. } => {
                if negate {
                    negate_condition(condition.clone())
                } else {
                    condition.clone()
                }
            }
            _ => unreachable!("guard jump target extraction must start from if"),
        };

        block.statements[index] = HirStatement::If {
            condition,
            then_body: HirBlock {
                statements: body.to_vec(),
            },
            else_body: None,
        };
        block.statements.drain((index + 1)..label_index);
        changed = true;

        if label_refs.get(&target).copied().unwrap_or(0) == 1 {
            if let Some(HirStatement::Label(label)) = block.statements.get(index + 1) {
                if label == &target {
                    block.statements.remove(index + 1);
                }
            }
        }
        index += 1;
    }

    changed
}

fn extract_guard_jump_target(statement: &HirStatement) -> Option<(String, bool)> {
    let HirStatement::If {
        then_body,
        else_body,
        ..
    } = statement
    else {
        return None;
    };
    if else_body.is_none() {
        let target = single_direct_goto_target(then_body)?;
        return Some((target.to_string(), true));
    }
    if let Some(else_body) = else_body {
        if then_body.statements.is_empty() {
            let target = single_direct_goto_target(else_body)?;
            return Some((target.to_string(), false));
        }
    }
    None
}

fn find_label_index(statements: &[HirStatement], start: usize, target: &str) -> Option<usize> {
    statements
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, statement)| match statement {
            HirStatement::Label(label) if label == target => Some(index),
            _ => None,
        })
}

fn replace_return_gotos(block: &mut HirBlock) -> bool {
    let return_labels = collect_label_returns(block);
    let mut changed = false;
    for statement in &mut block.statements {
        changed |= replace_return_gotos_in_statement(statement, &return_labels);
    }
    changed
}

fn fold_guarded_return_continuation_regions(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        match &mut block.statements[index] {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_guarded_return_continuation_regions(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_guarded_return_continuation_regions(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_guarded_return_continuation_regions(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_guarded_return_continuation_regions(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_guarded_return_continuation_regions(default);
                }
            }
            _ => {}
        }

        let Some((replacement, consumed)) =
            guarded_return_continuation_region_rewrite(&block.statements, index)
        else {
            index += 1;
            continue;
        };
        block
            .statements
            .splice(index..(index + consumed), replacement);
        changed = true;
        continue;
    }
    changed
}

fn guarded_return_continuation_region_rewrite(
    statements: &[HirStatement],
    index: usize,
) -> Option<(Vec<HirStatement>, usize)> {
    let HirStatement::If {
        condition: outer_condition,
        then_body: outer_then,
        else_body: None,
    } = statements.get(index)?
    else {
        return None;
    };
    if outer_then.statements.len() < 2 {
        return None;
    }

    let HirStatement::If {
        condition: inner_condition,
        then_body: inner_then,
        else_body: None,
    } = &outer_then.statements[0]
    else {
        return None;
    };
    let target = single_direct_goto_target(inner_then)?.to_string();
    let outer_suffix = &outer_then.statements[1..];
    if outer_suffix.iter().any(|statement| {
        matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
            || statement_is_terminal(statement)
    }) {
        return None;
    }

    let HirStatement::If {
        condition: guard_condition,
        then_body: guard_then,
        else_body: None,
    } = statements.get(index + 1)?
    else {
        return None;
    };
    if !body_is_terminal(guard_then)
        || negate_condition(inner_condition.clone()) != *guard_condition
    {
        return None;
    }

    let goto_index = index + 3;
    let middle_statement = statements.get(index + 2)?.clone();
    if matches!(
        middle_statement,
        HirStatement::Label(_)
            | HirStatement::Goto(_)
            | HirStatement::Return { .. }
            | HirStatement::Trap
            | HirStatement::Unreachable
    ) {
        return None;
    }
    let HirStatement::Goto(HirTarget::Direct(goto_target)) = statements.get(goto_index)? else {
        return None;
    };
    if goto_target != &target {
        return None;
    }
    let Some(label_after_goto) = statements.get(goto_index + 1).and_then(label_name) else {
        return None;
    };
    if label_after_goto != target {
        return None;
    }

    let mut replacement = Vec::new();
    let mut return_body = Vec::new();
    return_body.push(HirStatement::If {
        condition: outer_condition.clone(),
        then_body: HirBlock {
            statements: outer_suffix.to_vec(),
        },
        else_body: None,
    });
    return_body.extend(guard_then.statements.clone());
    replacement.push(HirStatement::If {
        condition: guard_condition.clone(),
        then_body: HirBlock {
            statements: return_body,
        },
        else_body: None,
    });
    replacement.push(HirStatement::If {
        condition: negate_condition(outer_condition.clone()),
        then_body: HirBlock {
            statements: vec![middle_statement],
        },
        else_body: None,
    });
    Some((replacement, 4))
}

fn fold_two_entry_continuation_regions(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        match &mut block.statements[index] {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_two_entry_continuation_regions(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_two_entry_continuation_regions(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_two_entry_continuation_regions(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_two_entry_continuation_regions(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_two_entry_continuation_regions(default);
                }
            }
            _ => {}
        }

        let Some((replacement, consumed)) =
            two_entry_continuation_region_rewrite(&block.statements, index)
        else {
            index += 1;
            continue;
        };
        block
            .statements
            .splice(index..(index + consumed), replacement);
        changed = true;
        continue;
    }
    changed
}

fn two_entry_continuation_region_rewrite(
    statements: &[HirStatement],
    index: usize,
) -> Option<(Vec<HirStatement>, usize)> {
    let HirStatement::If {
        condition: outer_condition,
        then_body: outer_then,
        else_body: None,
    } = statements.get(index)?
    else {
        return None;
    };
    if outer_then.statements.len() < 2 {
        return None;
    }

    let HirStatement::If {
        condition: join_skip_condition,
        then_body: join_skip_then,
        else_body: None,
    } = &outer_then.statements[0]
    else {
        return None;
    };
    let target = single_direct_goto_target(join_skip_then)?.to_string();
    let guarded_suffix = &outer_then.statements[1..];
    if guarded_suffix.iter().any(|statement| {
        matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
            || statement_is_terminal(statement)
    }) {
        return None;
    }

    let HirStatement::If {
        condition: return_condition,
        then_body: return_then,
        else_body: None,
    } = statements.get(index + 1)?
    else {
        return None;
    };
    if !body_is_terminal(return_then)
        || negate_condition(join_skip_condition.clone()) != *return_condition
    {
        return None;
    }

    let mut label_index = None;
    for candidate in (index + 3)..statements.len() {
        let Some(label_name) = statements.get(candidate).and_then(label_name) else {
            continue;
        };
        if label_name != target {
            continue;
        }
        if statements[(index + 2)..candidate]
            .iter()
            .any(|statement| matches!(statement, HirStatement::Label(_)))
        {
            continue;
        }
        label_index = Some(candidate);
        break;
    }
    let label_index = label_index?;
    let before_label = &statements[(index + 2)..label_index];
    let (goto_to_label, join_prefix) = before_label.split_last()?;
    let HirStatement::Goto(HirTarget::Direct(goto_target)) = goto_to_label else {
        return None;
    };
    if goto_target != &target {
        return None;
    }
    if join_prefix.is_empty()
        || join_prefix.iter().any(|statement| {
            matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
                || statement_is_terminal(statement)
        })
    {
        return None;
    }

    let mut replacement = Vec::new();
    let mut return_body = Vec::new();
    return_body.push(HirStatement::If {
        condition: outer_condition.clone(),
        then_body: HirBlock {
            statements: guarded_suffix.to_vec(),
        },
        else_body: None,
    });
    return_body.extend(return_then.statements.clone());
    replacement.push(HirStatement::If {
        condition: return_condition.clone(),
        then_body: HirBlock {
            statements: return_body,
        },
        else_body: None,
    });
    replacement.push(HirStatement::If {
        condition: negate_condition(outer_condition.clone()),
        then_body: HirBlock {
            statements: join_prefix.to_vec(),
        },
        else_body: None,
    });
    Some((replacement, label_index - index + 1))
}

fn fold_two_path_return_continuations(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        match &mut block.statements[index] {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_two_path_return_continuations(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_two_path_return_continuations(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_two_path_return_continuations(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_two_path_return_continuations(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_two_path_return_continuations(default);
                }
            }
            _ => {}
        }

        let Some((replacement, consumed)) =
            two_path_return_continuation_rewrite(&block.statements, index)
        else {
            index += 1;
            continue;
        };
        block
            .statements
            .splice(index..(index + consumed), replacement);
        changed = true;
        continue;
    }
    changed
}

fn two_path_return_continuation_rewrite(
    statements: &[HirStatement],
    index: usize,
) -> Option<(Vec<HirStatement>, usize)> {
    let HirStatement::If {
        condition: outer_condition,
        then_body: outer_then,
        else_body: None,
    } = statements.get(index)?
    else {
        return None;
    };
    if outer_then.statements.len() < 2 {
        return None;
    }
    let HirStatement::If {
        condition: skip_condition,
        then_body: skip_then,
        else_body: None,
    } = &outer_then.statements[0]
    else {
        return None;
    };
    let target = single_direct_goto_target(skip_then)?.to_string();
    let outer_suffix = &outer_then.statements[1..];
    if outer_suffix.iter().any(|statement| {
        matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
            || statement_is_terminal(statement)
    }) {
        return None;
    }

    let HirStatement::If {
        condition: return_condition,
        then_body: return_then,
        else_body: None,
    } = statements.get(index + 1)?
    else {
        return None;
    };
    if !body_is_terminal(return_then)
        || negate_condition(skip_condition.clone()) != *return_condition
    {
        return None;
    }

    let goto_index = index + 2;
    let HirStatement::Goto(HirTarget::Direct(goto_target)) = statements.get(goto_index)? else {
        return None;
    };
    if goto_target != &target {
        return None;
    }
    let Some(label_name_after) = statements.get(goto_index + 1).and_then(label_name) else {
        return None;
    };
    if label_name_after != target {
        return None;
    }

    let mut replacement = Vec::new();
    let mut return_body = Vec::new();
    return_body.push(HirStatement::If {
        condition: outer_condition.clone(),
        then_body: HirBlock {
            statements: outer_suffix.to_vec(),
        },
        else_body: None,
    });
    return_body.extend(return_then.statements.clone());
    replacement.push(HirStatement::If {
        condition: return_condition.clone(),
        then_body: HirBlock {
            statements: return_body,
        },
        else_body: None,
    });
    Some((replacement, 4))
}

fn fold_known_conditions(block: &mut HirBlock, assumptions: &[HirExpression]) -> bool {
    let mut changed = false;
    let mut current_assumptions = assumptions.to_vec();
    let mut index = 0;
    while index < block.statements.len() {
        let replacement = match &mut block.statements[index] {
            HirStatement::If {
                condition,
                then_body,
                else_body,
            } => {
                if let Some(known) =
                    condition_truth_under_assumptions(condition, &current_assumptions)
                {
                    let statements = if known {
                        then_body.statements.clone()
                    } else {
                        else_body
                            .as_ref()
                            .map(|body| body.statements.clone())
                            .unwrap_or_default()
                    };
                    Some(statements)
                } else {
                    let mut then_assumptions = current_assumptions.clone();
                    then_assumptions.push(condition.clone());
                    changed |= fold_known_conditions(then_body, &then_assumptions);

                    if let Some(else_body) = else_body {
                        let mut else_assumptions = current_assumptions.clone();
                        else_assumptions.push(negate_condition(condition.clone()));
                        changed |= fold_known_conditions(else_body, &else_assumptions);
                    }
                    None
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_known_conditions(body, &current_assumptions);
                None
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_known_conditions(&mut case.body, &current_assumptions);
                }
                if let Some(default) = default {
                    changed |= fold_known_conditions(default, &current_assumptions);
                }
                None
            }
            _ => None,
        };

        if let Some(replacement) = replacement {
            block.statements.splice(index..=index, replacement);
            changed = true;
            continue;
        }

        if let HirStatement::If {
            condition,
            then_body,
            else_body,
        } = &block.statements[index]
        {
            if else_body.is_none() && body_is_terminal(then_body) {
                current_assumptions.push(negate_condition(condition.clone()));
            } else if let Some(else_body) = else_body {
                if body_is_terminal(else_body) {
                    current_assumptions.push(condition.clone());
                }
            }
        } else if matches!(
            &block.statements[index],
            HirStatement::Label(_) | HirStatement::Goto(_)
        ) || statement_is_terminal(&block.statements[index])
        {
            current_assumptions.clear();
        }

        index += 1;
    }
    changed
}

fn condition_truth_under_assumptions(
    condition: &HirExpression,
    assumptions: &[HirExpression],
) -> Option<bool> {
    let negated = negate_condition(condition.clone());
    for assumption in assumptions {
        if assumption == condition {
            return Some(true);
        }
        if assumption == &negated {
            return Some(false);
        }
    }
    None
}

fn fold_return_guarded_continuations(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        match &mut block.statements[index] {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_return_guarded_continuations(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_return_guarded_continuations(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_return_guarded_continuations(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_return_guarded_continuations(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_return_guarded_continuations(default);
                }
            }
            _ => {}
        }

        let Some((replacement, consumed)) =
            return_guarded_continuation_rewrite(&block.statements, index)
        else {
            index += 1;
            continue;
        };
        block
            .statements
            .splice(index..(index + consumed), replacement);
        changed = true;
        continue;
    }
    changed
}

fn return_guarded_continuation_rewrite(
    statements: &[HirStatement],
    index: usize,
) -> Option<(Vec<HirStatement>, usize)> {
    let HirStatement::If {
        condition: outer_condition,
        then_body: outer_then,
        else_body: None,
    } = statements.get(index)?
    else {
        return None;
    };
    if outer_then.statements.len() < 2 {
        return None;
    }
    let HirStatement::If {
        condition: skip_condition,
        then_body: skip_then,
        else_body: None,
    } = &outer_then.statements[0]
    else {
        return None;
    };
    let target = single_direct_goto_target(skip_then)?;
    let guarded_suffix = &outer_then.statements[1..];
    if guarded_suffix.iter().any(|statement| {
        matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
            || statement_is_terminal(statement)
    }) {
        return None;
    }

    let HirStatement::If {
        condition: return_condition,
        then_body: return_then,
        else_body: None,
    } = statements.get(index + 1)?
    else {
        return None;
    };
    if !body_is_terminal(return_then)
        || negate_condition(skip_condition.clone()) != *return_condition
    {
        return None;
    }

    let goto_pos = statements[(index + 2)..].iter().position(
        |statement| matches!(statement, HirStatement::Goto(HirTarget::Direct(label)) if label == target),
    )?;
    let goto_index = index + 2 + goto_pos;
    let middle = &statements[(index + 2)..goto_index];
    if middle.is_empty()
        || middle.iter().any(|statement| {
            matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
                || statement_is_terminal(statement)
        })
    {
        return None;
    }
    let Some(label_after_goto) = statements.get(goto_index + 1).and_then(label_name) else {
        return None;
    };
    if label_after_goto != target {
        return None;
    }

    let mut replacement = Vec::new();
    let mut return_body = Vec::new();
    return_body.push(HirStatement::If {
        condition: outer_condition.clone(),
        then_body: HirBlock {
            statements: guarded_suffix.to_vec(),
        },
        else_body: None,
    });
    return_body.extend(return_then.statements.clone());
    replacement.push(HirStatement::If {
        condition: return_condition.clone(),
        then_body: HirBlock {
            statements: return_body,
        },
        else_body: None,
    });
    replacement.push(HirStatement::If {
        condition: negate_condition(outer_condition.clone()),
        then_body: HirBlock {
            statements: middle.to_vec(),
        },
        else_body: None,
    });
    Some((replacement, goto_index - index + 1))
}

fn fold_if_fallthrough_labels(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        if let Some(next_label) = block
            .statements
            .get(index + 1)
            .and_then(label_name)
            .map(str::to_string)
        {
            if let HirStatement::If {
                then_body,
                else_body,
                ..
            } = &mut block.statements[index]
            {
                changed |= fold_inner_jump_to_label_in_block(then_body, &next_label);
                if let Some(else_body) = else_body {
                    changed |= fold_inner_jump_to_label_in_block(else_body, &next_label);
                }
            }
            let replacement = match &block.statements[index] {
                HirStatement::If {
                    condition,
                    then_body,
                    else_body: Some(else_body),
                } => {
                    if single_direct_goto_target(else_body) == Some(next_label.as_str()) {
                        Some(HirStatement::If {
                            condition: condition.clone(),
                            then_body: then_body.clone(),
                            else_body: None,
                        })
                    } else if single_direct_goto_target(then_body) == Some(next_label.as_str()) {
                        Some(HirStatement::If {
                            condition: negate_condition(condition.clone()),
                            then_body: else_body.clone(),
                            else_body: None,
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(replacement) = replacement {
                block.statements[index] = replacement;
                changed = true;
            }
        }

        match &mut block.statements[index] {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_if_fallthrough_labels(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_if_fallthrough_labels(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_if_fallthrough_labels(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_if_fallthrough_labels(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_if_fallthrough_labels(default);
                }
            }
            _ => {}
        }

        index += 1;
    }
    changed
}

fn fold_inner_jump_to_label_in_block(block: &mut HirBlock, next_label: &str) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        let Some((rewritten_if, suffix_len)) =
            inner_jump_to_label_rewrite(&block.statements, index, next_label)
        else {
            index += 1;
            continue;
        };
        block.statements[index] = rewritten_if;
        let remove_start = index + 1;
        let remove_end = remove_start + suffix_len;
        block.statements.drain(remove_start..remove_end);
        changed = true;
        index += 1;
    }
    changed
}

fn inner_jump_to_label_rewrite(
    statements: &[HirStatement],
    index: usize,
    next_label: &str,
) -> Option<(HirStatement, usize)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body: None,
    } = statements.get(index)?
    else {
        return None;
    };
    if single_direct_goto_target(then_body)? != next_label {
        return None;
    }
    let suffix = &statements[(index + 1)..];
    if suffix.is_empty()
        || suffix.iter().any(|statement| {
            matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
                || statement_is_terminal(statement)
        })
    {
        return None;
    }

    Some((
        HirStatement::If {
            condition: negate_condition(condition.clone()),
            then_body: HirBlock {
                statements: suffix.to_vec(),
            },
            else_body: None,
        },
        suffix.len(),
    ))
}

fn simplify_if_goto_chains(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        if let Some((replacement, consumed)) = simplify_if_goto_chain_at(&block.statements, index) {
            block.statements[index] = replacement;
            for _ in 0..consumed {
                block.statements.remove(index + 1);
            }
            changed = true;
        }
        index += 1;
    }
    changed
}

fn remove_fallthrough_gotos(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut new_statements = Vec::new();
    let mut index = 0;
    while index < block.statements.len() {
        if let HirStatement::Goto(HirTarget::Direct(target)) = &block.statements[index] {
            if let Some(next_label) = block.statements.get(index + 1).and_then(label_name) {
                if target == next_label {
                    changed = true;
                    index += 1;
                    continue;
                }
            }
        }
        new_statements.push(block.statements[index].clone());
        index += 1;
    }
    block.statements = new_statements;
    changed
}

fn recover_while_loops(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        let Some(label) = block
            .statements
            .get(index)
            .and_then(label_name)
            .map(str::to_string)
        else {
            index += 1;
            continue;
        };
        let Some(backedge_index) = find_backedge_if(&block.statements, index + 1, &label) else {
            index += 1;
            continue;
        };
        let body_statements = block.statements[(index + 1)..backedge_index].to_vec();
        let HirStatement::If {
            condition,
            then_body,
            else_body,
        } = &block.statements[backedge_index]
        else {
            index += 1;
            continue;
        };
        let true_target = single_direct_goto_target(then_body);
        let false_target = else_body.as_ref().and_then(single_direct_goto_target);
        let Some(loop_condition) = (if true_target == Some(label.as_str()) {
            Some(condition.clone())
        } else if false_target == Some(label.as_str()) {
            Some(negate_condition(condition.clone()))
        } else {
            None
        }) else {
            index += 1;
            continue;
        };

        let mut loop_body = body_statements;
        loop_body.push(HirStatement::If {
            condition: negate_condition(loop_condition),
            then_body: HirBlock {
                statements: vec![HirStatement::Break],
            },
            else_body: None,
        });

        block.statements.splice(
            index..=backedge_index,
            [HirStatement::Loop {
                body: HirBlock {
                    statements: loop_body,
                },
            }],
        );
        changed = true;
    }
    changed
}

fn fold_loop_breaks_to_while(block: &mut HirBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            HirStatement::Loop { body } => {
                if let Some(HirStatement::If {
                    condition,
                    then_body,
                    else_body,
                }) = body.statements.last()
                {
                    if else_body.is_none()
                        && matches!(then_body.statements.as_slice(), [HirStatement::Break])
                    {
                        let condition = negate_condition(condition.clone());
                        let mut assigned = BTreeSet::new();
                        collect_assigned_names_in_statements(
                            &body.statements[..body.statements.len() - 1],
                            &mut assigned,
                        );
                        if !expression_references_names(&condition, &assigned) {
                            body.statements.pop();
                            *statement = HirStatement::While {
                                condition,
                                body: body.clone(),
                            };
                            changed = true;
                        }
                    }
                }
            }
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_loop_breaks_to_while(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_loop_breaks_to_while(else_body);
                }
            }
            HirStatement::While { body, .. } => changed |= fold_loop_breaks_to_while(body),
            _ => {}
        }
    }
    changed
}

fn inline_terminal_label_gotos(block: &mut HirBlock) -> bool {
    let tail_labels = collect_terminal_label_tails(block);
    if tail_labels.is_empty() {
        return false;
    }
    let mut changed = false;
    let mut new_statements = Vec::new();
    for mut statement in std::mem::take(&mut block.statements) {
        changed |= inline_terminal_label_gotos_in_statement(&mut statement, &tail_labels);
        match statement {
            HirStatement::Goto(HirTarget::Direct(target)) => {
                if let Some(tail) = tail_labels.get(&target) {
                    new_statements.extend(tail.clone());
                    changed = true;
                } else {
                    new_statements.push(HirStatement::Goto(HirTarget::Direct(target)));
                }
            }
            other => new_statements.push(other),
        }
    }
    block.statements = new_statements;
    changed
}

fn eliminate_redundant_terminal_if_suffixes(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        match &mut block.statements[index] {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= eliminate_redundant_terminal_if_suffixes(then_body);
                if let Some(else_body) = else_body {
                    changed |= eliminate_redundant_terminal_if_suffixes(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= eliminate_redundant_terminal_if_suffixes(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= eliminate_redundant_terminal_if_suffixes(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= eliminate_redundant_terminal_if_suffixes(default);
                }
            }
            _ => {}
        }

        let remove_if = match &block.statements[index] {
            HirStatement::If {
                then_body,
                else_body: None,
                ..
            } if body_is_terminal(then_body) => {
                block_suffix_starts_with(&block.statements[(index + 1)..], &then_body.statements)
            }
            _ => false,
        };
        if remove_if {
            block.statements.remove(index);
            changed = true;
            continue;
        }

        index += 1;
    }
    changed
}

fn fold_shared_terminal_if_tails(block: &mut HirBlock) -> bool {
    let mut changed = false;
    let mut index = 0;
    while index < block.statements.len() {
        match &mut block.statements[index] {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= fold_shared_terminal_if_tails(then_body);
                if let Some(else_body) = else_body {
                    changed |= fold_shared_terminal_if_tails(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= fold_shared_terminal_if_tails(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= fold_shared_terminal_if_tails(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= fold_shared_terminal_if_tails(default);
                }
            }
            _ => {}
        }

        let Some((rewritten_if, tail_len, prefix_len)) =
            shared_terminal_if_tail_rewrite(&block.statements, index)
        else {
            index += 1;
            continue;
        };

        block.statements[index] = rewritten_if;
        let remove_start = index + 1;
        let remove_end = remove_start + prefix_len;
        block.statements.drain(remove_start..remove_end);
        let tail_start = block.statements.len() - tail_len;
        let tail = block.statements.split_off(tail_start);
        block.statements.extend(tail);
        changed = true;
        index += 1;
    }
    changed
}

fn prune_unreferenced_labels(block: &mut HirBlock) -> bool {
    let referenced = collect_label_references(block);
    let original_len = block.statements.len();
    block.statements.retain(|statement| match statement {
        HirStatement::Label(label) => referenced.contains(label),
        _ => true,
    });
    block.statements.len() != original_len
}

fn remove_unreachable_after_terminal(block: &mut HirBlock) -> bool {
    let mut changed = false;
    for statement in &mut block.statements {
        match statement {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                changed |= remove_unreachable_after_terminal(then_body);
                if let Some(else_body) = else_body {
                    changed |= remove_unreachable_after_terminal(else_body);
                }
            }
            HirStatement::While { body, .. } | HirStatement::Loop { body } => {
                changed |= remove_unreachable_after_terminal(body);
            }
            HirStatement::Switch { cases, default, .. } => {
                for case in cases {
                    changed |= remove_unreachable_after_terminal(&mut case.body);
                }
                if let Some(default) = default {
                    changed |= remove_unreachable_after_terminal(default);
                }
            }
            _ => {}
        }
    }
    let mut new_statements = Vec::new();
    let mut saw_terminal = false;
    for statement in std::mem::take(&mut block.statements) {
        if saw_terminal {
            if matches!(statement, HirStatement::Label(_)) {
                saw_terminal = false;
                new_statements.push(statement);
            } else {
                changed = true;
            }
            continue;
        }
        saw_terminal = statement_is_terminal(&statement);
        new_statements.push(statement);
    }
    block.statements = new_statements;
    changed
}

fn collect_label_returns(block: &HirBlock) -> BTreeMap<String, Vec<HirExpression>> {
    let mut result = BTreeMap::new();
    let mut index = 0;
    while index + 1 < block.statements.len() {
        if let HirStatement::Label(label) = &block.statements[index] {
            if let HirStatement::Return { values } = &block.statements[index + 1] {
                result.insert(label.clone(), values.clone());
            }
        }
        index += 1;
    }
    result
}

fn shared_terminal_if_tail_rewrite(
    statements: &[HirStatement],
    index: usize,
) -> Option<(HirStatement, usize, usize)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body: None,
    } = statements.get(index)?
    else {
        return None;
    };
    if !body_is_terminal(then_body) || then_body.statements.len() < 2 {
        return None;
    }

    let remaining = &statements[(index + 1)..];
    let tail_len = then_body.statements.len();
    if remaining.len() <= tail_len {
        return None;
    }
    if !block_suffix_starts_with(
        &remaining[(remaining.len() - tail_len)..],
        &then_body.statements,
    ) {
        return None;
    }

    let prefix = &remaining[..(remaining.len() - tail_len)];
    if prefix.is_empty()
        || prefix.iter().any(|statement| {
            matches!(statement, HirStatement::Label(_) | HirStatement::Goto(_))
                || statement_is_terminal(statement)
        })
    {
        return None;
    }

    Some((
        HirStatement::If {
            condition: negate_condition(condition.clone()),
            then_body: HirBlock {
                statements: prefix.to_vec(),
            },
            else_body: None,
        },
        tail_len,
        prefix.len(),
    ))
}

fn replace_return_gotos_in_statement(
    statement: &mut HirStatement,
    return_labels: &BTreeMap<String, Vec<HirExpression>>,
) -> bool {
    match statement {
        HirStatement::Goto(HirTarget::Direct(target)) => {
            if let Some(values) = return_labels.get(target) {
                *statement = HirStatement::Return {
                    values: values.clone(),
                };
                return true;
            }
            false
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            let mut changed = false;
            for statement in &mut then_body.statements {
                changed |= replace_return_gotos_in_statement(statement, return_labels);
            }
            if let Some(else_body) = else_body {
                for statement in &mut else_body.statements {
                    changed |= replace_return_gotos_in_statement(statement, return_labels);
                }
            }
            changed
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            let mut changed = false;
            for statement in &mut body.statements {
                changed |= replace_return_gotos_in_statement(statement, return_labels);
            }
            changed
        }
        _ => false,
    }
}

fn simplify_if_goto_chain_at(
    statements: &[HirStatement],
    index: usize,
) -> Option<(HirStatement, usize)> {
    let HirStatement::If {
        condition,
        then_body,
        else_body,
    } = &statements[index]
    else {
        return None;
    };
    let else_body = else_body.as_ref()?;
    if then_body.statements.len() == 1 && else_body.statements.len() == 1 {
        let then_target = single_direct_goto_target(then_body)?;
        let else_target = single_direct_goto_target(else_body)?;
        if let Some(HirStatement::Label(next_label)) = statements.get(index + 1) {
            if else_target == next_label {
                return Some((
                    HirStatement::If {
                        condition: condition.clone(),
                        then_body: HirBlock {
                            statements: vec![HirStatement::Goto(HirTarget::Direct(
                                then_target.to_string(),
                            ))],
                        },
                        else_body: None,
                    },
                    1,
                ));
            }
            if then_target == next_label {
                return Some((
                    HirStatement::If {
                        condition: negate_condition(condition.clone()),
                        then_body: HirBlock {
                            statements: vec![HirStatement::Goto(HirTarget::Direct(
                                else_target.to_string(),
                            ))],
                        },
                        else_body: None,
                    },
                    1,
                ));
            }
        }
    }
    None
}

fn single_direct_goto_target(block: &HirBlock) -> Option<&str> {
    match block.statements.as_slice() {
        [HirStatement::Goto(HirTarget::Direct(target))] => Some(target.as_str()),
        _ => None,
    }
}

fn find_backedge_if(statements: &[HirStatement], start: usize, label: &str) -> Option<usize> {
    statements
        .iter()
        .enumerate()
        .skip(start)
        .find_map(|(index, statement)| match statement {
            HirStatement::If {
                then_body,
                else_body,
                ..
            } => {
                let false_target = else_body.as_ref().and_then(single_direct_goto_target);
                let true_target = single_direct_goto_target(then_body);
                if true_target == Some(label) || false_target == Some(label) {
                    Some(index)
                } else {
                    None
                }
            }
            _ => None,
        })
}

fn label_name(statement: &HirStatement) -> Option<&str> {
    if let HirStatement::Label(label) = statement {
        Some(label.as_str())
    } else {
        None
    }
}

fn statement_is_terminal(statement: &HirStatement) -> bool {
    matches!(
        statement,
        HirStatement::Return { .. } | HirStatement::Trap | HirStatement::Unreachable
    )
}

fn collect_label_references(block: &HirBlock) -> BTreeSet<String> {
    let mut labels = BTreeSet::new();
    for statement in &block.statements {
        collect_label_references_in_statement(statement, &mut labels);
    }
    labels
}

fn collect_label_reference_counts(block: &HirBlock) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for statement in &block.statements {
        collect_label_reference_counts_in_statement(statement, &mut counts);
    }
    counts
}

fn collect_label_references_in_statement(statement: &HirStatement, labels: &mut BTreeSet<String>) {
    match statement {
        HirStatement::Goto(HirTarget::Direct(target)) => {
            labels.insert(target.clone());
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            for statement in &then_body.statements {
                collect_label_references_in_statement(statement, labels);
            }
            if let Some(else_body) = else_body {
                for statement in &else_body.statements {
                    collect_label_references_in_statement(statement, labels);
                }
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            for statement in &body.statements {
                collect_label_references_in_statement(statement, labels);
            }
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                for statement in &case.body.statements {
                    collect_label_references_in_statement(statement, labels);
                }
            }
            if let Some(default) = default {
                for statement in &default.statements {
                    collect_label_references_in_statement(statement, labels);
                }
            }
        }
        _ => {}
    }
}

fn collect_label_reference_counts_in_statement(
    statement: &HirStatement,
    counts: &mut BTreeMap<String, usize>,
) {
    match statement {
        HirStatement::Goto(HirTarget::Direct(target)) => {
            *counts.entry(target.clone()).or_insert(0) += 1;
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            for statement in &then_body.statements {
                collect_label_reference_counts_in_statement(statement, counts);
            }
            if let Some(else_body) = else_body {
                for statement in &else_body.statements {
                    collect_label_reference_counts_in_statement(statement, counts);
                }
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            for statement in &body.statements {
                collect_label_reference_counts_in_statement(statement, counts);
            }
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                for statement in &case.body.statements {
                    collect_label_reference_counts_in_statement(statement, counts);
                }
            }
            if let Some(default) = default {
                for statement in &default.statements {
                    collect_label_reference_counts_in_statement(statement, counts);
                }
            }
        }
        _ => {}
    }
}

fn negate_condition(condition: HirExpression) -> HirExpression {
    simplify_logical_not(condition, HirType::integer(1))
}

fn body_is_terminal(block: &HirBlock) -> bool {
    block.statements.last().is_some_and(statement_is_terminal)
}

fn block_suffix_starts_with(statements: &[HirStatement], prefix: &[HirStatement]) -> bool {
    statements.len() >= prefix.len() && statements[..prefix.len()] == *prefix
}

fn collect_terminal_label_tails(block: &HirBlock) -> BTreeMap<String, Vec<HirStatement>> {
    const MAX_SIMPLE_TERMINAL_TAIL_STATEMENTS: usize = 6;
    const MAX_SIMPLE_TERMINAL_TAIL_CLONE_COST: usize = 8;

    let label_ref_counts = collect_label_reference_counts(block);
    let mut result = BTreeMap::new();
    for index in 0..block.statements.len() {
        let Some(label) = block.statements.get(index).and_then(label_name) else {
            continue;
        };
        let tail = &block.statements[(index + 1)..];
        if tail.is_empty()
            || tail
                .iter()
                .any(|statement| matches!(statement, HirStatement::Label(_)))
        {
            continue;
        }
        let ref_count = label_ref_counts.get(label).copied().unwrap_or(0);
        if ref_count == 0 || ref_count > 2 {
            continue;
        }
        if matches!(tail.last(), Some(HirStatement::Return { .. })) {
            if tail.len() <= 4 {
                result.insert(label.to_string(), tail.to_vec());
                continue;
            }
            if tail.len() > MAX_SIMPLE_TERMINAL_TAIL_STATEMENTS {
                continue;
            }
            if region_clone_cost(tail) > MAX_SIMPLE_TERMINAL_TAIL_CLONE_COST {
                continue;
            }
            if tail[..(tail.len() - 1)].iter().any(|statement| {
                matches!(
                    statement,
                    HirStatement::Goto(_)
                        | HirStatement::While { .. }
                        | HirStatement::Loop { .. }
                        | HirStatement::Switch { .. }
                        | HirStatement::Trap
                        | HirStatement::Unreachable
                )
            }) {
                continue;
            }
            result.insert(label.to_string(), tail.to_vec());
            continue;
        }
        continue;
    }
    result
}

fn inline_terminal_label_gotos_in_statement(
    statement: &mut HirStatement,
    tails: &BTreeMap<String, Vec<HirStatement>>,
) -> bool {
    match statement {
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            let mut changed = false;
            if let [HirStatement::Goto(HirTarget::Direct(target))] = then_body.statements.as_slice()
            {
                if let Some(tail) = tails.get(target) {
                    then_body.statements = tail.clone();
                    changed = true;
                }
            } else {
                changed |= inline_terminal_label_gotos(then_body);
            }
            if let Some(else_body) = else_body {
                if let [HirStatement::Goto(HirTarget::Direct(target))] =
                    else_body.statements.as_slice()
                {
                    if let Some(tail) = tails.get(target) {
                        else_body.statements = tail.clone();
                        changed = true;
                    }
                } else {
                    changed |= inline_terminal_label_gotos(else_body);
                }
            }
            changed
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            inline_terminal_label_gotos(body)
        }
        HirStatement::Switch { cases, default, .. } => {
            let mut changed = false;
            for case in cases {
                changed |= inline_terminal_label_gotos(&mut case.body);
            }
            if let Some(default) = default {
                changed |= inline_terminal_label_gotos(default);
            }
            changed
        }
        _ => false,
    }
}

fn collect_assigned_names_in_statements(statements: &[HirStatement], names: &mut BTreeSet<String>) {
    for statement in statements {
        collect_assigned_names_in_statement(statement, names);
    }
}

fn collect_assigned_names_in_statement(statement: &HirStatement, names: &mut BTreeSet<String>) {
    match statement {
        HirStatement::Assign {
            target: crate::ir::hir::HirPlace::Named { name, .. },
            ..
        } => {
            names.insert(name.clone());
        }
        HirStatement::If {
            then_body,
            else_body,
            ..
        } => {
            collect_assigned_names_in_statements(&then_body.statements, names);
            if let Some(else_body) = else_body {
                collect_assigned_names_in_statements(&else_body.statements, names);
            }
        }
        HirStatement::While { body, .. } | HirStatement::Loop { body } => {
            collect_assigned_names_in_statements(&body.statements, names);
        }
        HirStatement::Switch { cases, default, .. } => {
            for case in cases {
                collect_assigned_names_in_statements(&case.body.statements, names);
            }
            if let Some(default) = default {
                collect_assigned_names_in_statements(&default.statements, names);
            }
        }
        _ => {}
    }
}

fn expression_references_names(expression: &HirExpression, names: &BTreeSet<String>) -> bool {
    match expression {
        HirExpression::Value(crate::ir::hir::HirValue::Named { name, .. }) => names.contains(name),
        HirExpression::Unary { value, .. }
        | HirExpression::Extract { value, .. }
        | HirExpression::Cast { value, .. }
        | HirExpression::Dereference { pointer: value, .. } => {
            expression_references_names(value, names)
        }
        HirExpression::Binary { lhs, rhs, .. }
        | HirExpression::Compare { lhs, rhs, .. }
        | HirExpression::FloatCompare { lhs, rhs, .. }
        | HirExpression::Index {
            base: lhs,
            index: rhs,
            ..
        } => expression_references_names(lhs, names) || expression_references_names(rhs, names),
        HirExpression::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            expression_references_names(condition, names)
                || expression_references_names(when_true, names)
                || expression_references_names(when_false, names)
        }
        HirExpression::Concat { parts, .. } => parts
            .iter()
            .any(|part| expression_references_names(part, names)),
        HirExpression::Load { address, .. } => expression_references_names(address, names),
        HirExpression::Call {
            target, arguments, ..
        } => {
            let target_refs = if let HirTarget::Indirect(target) = target {
                expression_references_names(target, names)
            } else {
                false
            };
            target_refs
                || arguments
                    .iter()
                    .any(|arg| expression_references_names(arg, names))
        }
        HirExpression::Intrinsic { arguments, .. } => arguments
            .iter()
            .any(|arg| expression_references_names(arg, names)),
        HirExpression::AddressOf { place, .. } => place_references_names(place, names),
        HirExpression::Value(_) => false,
    }
}

fn place_references_names(place: &crate::ir::hir::HirPlace, names: &BTreeSet<String>) -> bool {
    match place {
        crate::ir::hir::HirPlace::Named { name, .. } => names.contains(name),
        crate::ir::hir::HirPlace::Dereference { pointer, .. }
        | crate::ir::hir::HirPlace::Memory {
            address: pointer, ..
        } => expression_references_names(pointer, names),
        crate::ir::hir::HirPlace::Index { base, index, .. } => {
            expression_references_names(base, names) || expression_references_names(index, names)
        }
    }
}
