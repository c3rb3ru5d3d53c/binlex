use crate::ir::mir::analysis::mir_predecessors;
use crate::ir::mir::{Mir, MirBlock, MirControlTarget, MirOperationKind, MirTerminator, MirValue};
use std::collections::{HashMap, HashSet};

pub fn optimize_blocks(mir: &mut Mir) {
    loop {
        let predecessors = mir_predecessors(mir);
        let blocks_by_name: HashMap<String, MirBlock> = mir
            .blocks()
            .iter()
            .cloned()
            .map(|block| (block.name.clone(), block))
            .collect();

        let merge_plan = collect_merge_plan(mir, &predecessors, &blocks_by_name);
        if merge_plan.is_empty() {
            break;
        }

        apply_merge_plan(mir, &blocks_by_name, &merge_plan);
    }
}

fn collect_merge_plan(
    mir: &Mir,
    predecessors: &HashMap<String, Vec<String>>,
    blocks_by_name: &HashMap<String, MirBlock>,
) -> HashMap<String, (String, Vec<MirValue>)> {
    let mut plan = HashMap::<String, (String, Vec<MirValue>)>::new();
    let mut consumed_targets = HashSet::<String>::new();

    for block in mir.blocks() {
        let Some((target_name, arguments)) = jump_target(block) else {
            continue;
        };
        if block.name == target_name || consumed_targets.contains(&target_name) {
            continue;
        }

        let Some(target_block) = blocks_by_name.get(&target_name) else {
            continue;
        };
        if !target_block.parameters.is_empty() && target_block.parameters.len() != arguments.len() {
            continue;
        }

        let Some(preds) = predecessors.get(&target_name) else {
            continue;
        };
        if preds.len() != 1 || preds[0] != block.name {
            continue;
        }

        consumed_targets.insert(target_name.clone());
        plan.insert(block.name.clone(), (target_name, arguments));
    }

    plan
}

fn apply_merge_plan(
    mir: &mut Mir,
    blocks_by_name: &HashMap<String, MirBlock>,
    merge_plan: &HashMap<String, (String, Vec<MirValue>)>,
) {
    let merged_targets = merge_plan
        .values()
        .map(|(target, _)| target.clone())
        .collect::<HashSet<_>>();
    let mut new_blocks =
        Vec::with_capacity(mir.blocks().len().saturating_sub(merged_targets.len()));

    for block in mir.blocks().iter().cloned() {
        if merged_targets.contains(&block.name) {
            continue;
        }

        if let Some((target_name, arguments)) = merge_plan.get(&block.name) {
            let Some(target_block) = blocks_by_name.get(target_name).cloned() else {
                new_blocks.push(block);
                continue;
            };
            new_blocks.push(merged_block(block, target_block, arguments.clone()));
        } else {
            new_blocks.push(block);
        }
    }

    *mir.blocks_mut() = new_blocks;
}

fn jump_target(block: &MirBlock) -> Option<(String, Vec<MirValue>)> {
    let terminator = block.terminator.as_ref()?;
    match terminator {
        MirTerminator::Jump {
            target: MirControlTarget::Direct(target),
            arguments,
        } => Some((target.clone(), arguments.clone())),
        _ => None,
    }
}

fn merged_block(
    mut block: MirBlock,
    mut target_block: MirBlock,
    arguments: Vec<MirValue>,
) -> MirBlock {
    let replacements = target_block
        .parameters
        .iter()
        .zip(arguments)
        .filter_map(|(parameter, argument)| Some((parameter.name.as_ref()?.clone(), argument)))
        .collect::<HashMap<_, _>>();

    if !replacements.is_empty() {
        for operation in &mut target_block.operations {
            rewrite_operation(operation, &replacements);
        }
        if let Some(terminator) = target_block.terminator.as_mut() {
            rewrite_terminator(terminator, &replacements);
        }
    }
    target_block.parameters.clear();

    block.operations.extend(target_block.operations);
    block.terminator = target_block.terminator;
    block
}

fn rewrite_operation(
    operation: &mut crate::ir::mir::MirOperation,
    replacements: &HashMap<String, MirValue>,
) {
    match &mut operation.kind {
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::FAdd { lhs, rhs, .. }
        | MirOperationKind::FSub { lhs, rhs, .. }
        | MirOperationKind::FMul { lhs, rhs, .. }
        | MirOperationKind::FDiv { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::UDiv { lhs, rhs, .. }
        | MirOperationKind::SDiv { lhs, rhs, .. }
        | MirOperationKind::URem { lhs, rhs, .. }
        | MirOperationKind::SRem { lhs, rhs, .. }
        | MirOperationKind::RotateLeft { lhs, rhs, .. }
        | MirOperationKind::RotateRight { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. }
        | MirOperationKind::Fcmp { lhs, rhs, .. } => {
            rewrite_value(lhs, replacements);
            rewrite_value(rhs, replacements);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                rewrite_value(part, replacements);
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, replacements);
            rewrite_value(when_true, replacements);
            rewrite_value(when_false, replacements);
        }
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::Cast { value, .. } => rewrite_value(value, replacements),
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, replacements);
            rewrite_value(value, replacements);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_value(src_address, replacements);
            rewrite_value(dst_address, replacements);
            rewrite_value(count, replacements);
            rewrite_value(decrement, replacements);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, replacements);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, replacements: &HashMap<String, MirValue>) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, replacements);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, replacements);
            for argument in then_arguments {
                rewrite_value(argument, replacements);
            }
            for argument in else_arguments {
                rewrite_value(argument, replacements);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, replacements);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, replacements: &HashMap<String, MirValue>) {
    if let MirValue::Named { name, .. } = value {
        if let Some(replacement) = replacements.get(name) {
            *value = replacement.clone();
        }
    }
}
