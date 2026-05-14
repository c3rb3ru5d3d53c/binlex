use crate::ir::mir::analysis::mir_predecessors;
use crate::ir::mir::{Mir, MirOperationKind, MirTerminator, MirValue};
use std::collections::HashMap;

pub fn optimize_blocks(mir: &mut Mir) {
    loop {
        let predecessors = mir_predecessors(mir);
        let block_index_by_name: HashMap<String, usize> = mir
            .blocks()
            .iter()
            .enumerate()
            .map(|(index, block)| (block.name.clone(), index))
            .collect();

        let mut changed = false;

        for block_index in 0..mir.blocks().len() {
            let Some((target_name, arguments)) = jump_target(mir, block_index) else {
                continue;
            };

            let Some(&target_index) = block_index_by_name.get(&target_name) else {
                continue;
            };

            if target_index == block_index {
                continue;
            }

            let Some(target_block) = mir.blocks().get(target_index) else {
                continue;
            };

            if !target_block.parameters.is_empty()
                && target_block.parameters.len() != arguments.len()
            {
                continue;
            }

            let Some(preds) = predecessors.get(&target_name) else {
                continue;
            };

            if preds.len() != 1 || preds[0] != mir.blocks()[block_index].name {
                continue;
            }

            merge_successor_block(mir, block_index, target_index, arguments);
            changed = true;
            break;
        }

        if !changed {
            break;
        }
    }
}

fn jump_target(mir: &Mir, block_index: usize) -> Option<(String, Vec<crate::ir::mir::MirValue>)> {
    let terminator = mir.blocks().get(block_index)?.terminator.as_ref()?;
    match terminator {
        MirTerminator::Jump { target, arguments } => Some((target.clone(), arguments.clone())),
        _ => None,
    }
}

fn merge_successor_block(
    mir: &mut Mir,
    block_index: usize,
    target_index: usize,
    arguments: Vec<MirValue>,
) {
    let mut target_block = mir.blocks_mut().remove(target_index);
    let destination_index = if target_index < block_index {
        block_index - 1
    } else {
        block_index
    };

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

    let block = &mut mir.blocks_mut()[destination_index];
    block.operations.extend(target_block.operations);
    block.terminator = target_block.terminator;
}

fn rewrite_operation(
    operation: &mut crate::ir::mir::MirOperation,
    replacements: &HashMap<String, MirValue>,
) {
    match &mut operation.kind {
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. } => {
            rewrite_value(lhs, replacements);
            rewrite_value(rhs, replacements);
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
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::Cast { value, .. } => rewrite_value(value, replacements),
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, replacements);
            rewrite_value(value, replacements);
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
