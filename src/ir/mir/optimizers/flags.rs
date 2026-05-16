use crate::ir::mir::{Mir, MirOperationKind, MirValue};
use std::collections::{HashMap, HashSet, VecDeque};

pub fn optimize_flags(mir: &mut Mir) {
    let mut use_counts = build_use_counts(mir);
    let defs = build_defs(mir);
    let mut removed = HashSet::<(usize, usize)>::new();
    let mut queue = VecDeque::<String>::new();

    for (name, &(block_index, operation_index)) in &defs {
        if use_counts.get(name).copied().unwrap_or_default() != 0 {
            continue;
        }
        if should_remove_operation(
            &mir.blocks()[block_index].operations[operation_index].kind,
            name,
        ) {
            queue.push_back(name.clone());
        }
    }

    while let Some(name) = queue.pop_front() {
        let Some(&(block_index, operation_index)) = defs.get(&name) else {
            continue;
        };
        if !removed.insert((block_index, operation_index)) {
            continue;
        }

        let operation = &mir.blocks()[block_index].operations[operation_index];
        if !should_remove_operation(&operation.kind, &name) {
            continue;
        }

        for used in operation_uses(&operation.kind) {
            let Some(count) = use_counts.get_mut(&used) else {
                continue;
            };
            if *count == 0 {
                continue;
            }
            *count -= 1;
            if *count == 0 {
                if let Some(&(used_block, used_operation)) = defs.get(&used) {
                    let used_kind = &mir.blocks()[used_block].operations[used_operation].kind;
                    if should_remove_operation(used_kind, &used) {
                        queue.push_back(used);
                    }
                }
            }
        }
    }

    if removed.is_empty() {
        return;
    }

    for (block_index, block) in mir.blocks_mut().iter_mut().enumerate() {
        block.operations = block
            .operations
            .drain(..)
            .enumerate()
            .filter_map(|(operation_index, operation)| {
                (!removed.contains(&(block_index, operation_index))).then_some(operation)
            })
            .collect();
    }
}

fn build_defs(mir: &Mir) -> HashMap<String, (usize, usize)> {
    let mut defs = HashMap::new();
    for (block_index, block) in mir.blocks().iter().enumerate() {
        for (operation_index, operation) in block.operations.iter().enumerate() {
            if let Some(result) = operation.result.as_ref() {
                defs.insert(result.clone(), (block_index, operation_index));
            }
        }
    }
    defs
}

fn build_use_counts(mir: &Mir) -> HashMap<String, usize> {
    let mut counts = HashMap::<String, usize>::new();

    for block in mir.blocks() {
        for operation in &block.operations {
            for used in operation_uses(&operation.kind) {
                *counts.entry(used).or_default() += 1;
            }
        }
        if let Some(terminator) = block.terminator.as_ref() {
            for used in terminator_uses(terminator) {
                *counts.entry(used).or_default() += 1;
            }
        }
    }

    counts
}

fn operation_uses(kind: &MirOperationKind) -> Vec<String> {
    match kind {
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
        | MirOperationKind::Fcmp { lhs, rhs, .. } => vec_from_values([lhs, rhs]),
        MirOperationKind::Concat { parts, .. } => parts.iter().filter_map(named_value).collect(),
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => vec_from_values([condition, when_true, when_false]),
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::Cast { value, .. } => vec_from_values([value]),
        MirOperationKind::Store { address, value, .. } => vec_from_values([address, value]),
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => vec_from_values([src_address, dst_address, count, decrement]),
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            arguments.iter().filter_map(named_value).collect()
        }
    }
}

fn terminator_uses(terminator: &crate::ir::mir::MirTerminator) -> Vec<String> {
    match terminator {
        crate::ir::mir::MirTerminator::Jump { arguments, .. }
        | crate::ir::mir::MirTerminator::Return { values: arguments } => {
            arguments.iter().filter_map(named_value).collect()
        }
        crate::ir::mir::MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => std::iter::once(condition)
            .chain(then_arguments.iter())
            .chain(else_arguments.iter())
            .filter_map(named_value)
            .collect(),
        crate::ir::mir::MirTerminator::Trap | crate::ir::mir::MirTerminator::Unreachable => {
            Vec::new()
        }
    }
}

fn named_value(value: &MirValue) -> Option<String> {
    match value {
        MirValue::Named { name, .. } => Some(name.clone()),
        _ => None,
    }
}

fn vec_from_values<const N: usize>(values: [&MirValue; N]) -> Vec<String> {
    values.into_iter().filter_map(named_value).collect()
}

fn should_remove_operation(kind: &MirOperationKind, result: &str) -> bool {
    (is_flag_name(result) && is_flag_set(kind)) || is_dead_flag_producer(kind)
}

fn is_flag_name(name: &str) -> bool {
    matches!(name, "zf" | "sf" | "cf" | "of" | "pf" | "af")
}

fn is_flag_set(kind: &MirOperationKind) -> bool {
    matches!(kind, MirOperationKind::Copy { .. })
}

fn is_dead_flag_producer(kind: &MirOperationKind) -> bool {
    matches!(
        kind,
        MirOperationKind::Add { .. }
            | MirOperationKind::Sub { .. }
            | MirOperationKind::Mul { .. }
            | MirOperationKind::FAdd { .. }
            | MirOperationKind::FSub { .. }
            | MirOperationKind::FMul { .. }
            | MirOperationKind::FDiv { .. }
            | MirOperationKind::And { .. }
            | MirOperationKind::Or { .. }
            | MirOperationKind::Xor { .. }
            | MirOperationKind::Shl { .. }
            | MirOperationKind::LShr { .. }
            | MirOperationKind::AShr { .. }
            | MirOperationKind::UDiv { .. }
            | MirOperationKind::SDiv { .. }
            | MirOperationKind::URem { .. }
            | MirOperationKind::SRem { .. }
            | MirOperationKind::RotateLeft { .. }
            | MirOperationKind::RotateRight { .. }
            | MirOperationKind::Select { .. }
            | MirOperationKind::Concat { .. }
            | MirOperationKind::Extract { .. }
            | MirOperationKind::Neg { .. }
            | MirOperationKind::Not { .. }
            | MirOperationKind::Popcount { .. }
            | MirOperationKind::CountLeadingZeros { .. }
            | MirOperationKind::CountTrailingZeros { .. }
            | MirOperationKind::Icmp { .. }
            | MirOperationKind::Fcmp { .. }
            | MirOperationKind::Cast { .. }
            | MirOperationKind::MemoryCopy { .. }
    )
}
