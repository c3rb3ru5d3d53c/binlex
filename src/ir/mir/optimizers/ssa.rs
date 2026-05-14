use crate::ir::mir::analysis::{mir_predecessors, reverse_post_order};
use crate::ir::mir::{
    Mir, MirBlockParameter, MirOperation, MirOperationKind, MirTerminator, MirType, MirValue,
};
use std::collections::{BTreeSet, HashMap};

type VersionMap = HashMap<String, MirValue>;

#[derive(Clone, Debug)]
struct MergeParameter {
    base: String,
    name: String,
    ty: MirType,
}

pub fn optimize_ssa(mir: &mut Mir) {
    let predecessors = mir_predecessors(mir);
    let order = reverse_post_order(mir);
    let indices = mir
        .blocks()
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut outgoing = HashMap::<String, VersionMap>::new();
    let mut changed = true;

    while changed {
        changed = false;
        clear_ssa_edges(mir);
        let mut counters = HashMap::<String, usize>::new();

        for block_name in &order {
            let Some(index) = indices.get(block_name).copied() else {
                continue;
            };

            let (mut current, merges) = incoming_versions(block_name, &predecessors, &outgoing);

            for merge in &merges {
                current.insert(
                    merge.base.clone(),
                    MirValue::named(merge.name.clone(), merge.ty.clone()),
                );
            }

            wire_merge_arguments(mir, &indices, &predecessors, &outgoing, block_name, &merges);

            let block = &mut mir.blocks_mut()[index];
            block.parameters = merges
                .iter()
                .map(|merge| MirBlockParameter::new(Some(merge.name.clone()), merge.ty.clone()))
                .collect();

            for parameter in &block.parameters {
                if let Some(name) = parameter.name.as_ref() {
                    let base = base_name(name);
                    current.insert(base, MirValue::named(name.clone(), parameter.ty.clone()));
                }
            }

            for operation in &mut block.operations {
                rewrite_operation(operation, &current);
                if let Some(result) = operation.result.as_mut() {
                    let base = base_name(result);
                    let versioned = next_version(&base, &mut counters);
                    let ty = result_type(&operation.kind);
                    current.insert(base, MirValue::named(versioned.clone(), ty));
                    *result = versioned;
                }
            }

            if let Some(terminator) = block.terminator.as_mut() {
                rewrite_terminator(terminator, &current);
            }

            if outgoing.get(&block.name) != Some(&current) {
                outgoing.insert(block.name.clone(), current);
                changed = true;
            }
        }
    }
}

fn clear_ssa_edges(mir: &mut Mir) {
    for block in mir.blocks_mut() {
        block.parameters.clear();
        if let Some(terminator) = block.terminator.as_mut() {
            match terminator {
                MirTerminator::Jump { arguments, .. } => arguments.clear(),
                MirTerminator::CondBr {
                    then_arguments,
                    else_arguments,
                    ..
                } => {
                    then_arguments.clear();
                    else_arguments.clear();
                }
                MirTerminator::Return { .. } | MirTerminator::Trap | MirTerminator::Unreachable => {
                }
            }
        }
    }
}

fn incoming_versions(
    block: &str,
    predecessors: &HashMap<String, Vec<String>>,
    outgoing: &HashMap<String, VersionMap>,
) -> (VersionMap, Vec<MergeParameter>) {
    let Some(preds) = predecessors.get(block) else {
        return (VersionMap::new(), Vec::new());
    };
    let Some((first, rest)) = preds.split_first() else {
        return (VersionMap::new(), Vec::new());
    };
    let Some(first_versions) = outgoing.get(first) else {
        return (VersionMap::new(), Vec::new());
    };

    let mut shared = first_versions.clone();
    let mut merges = Vec::new();
    let all_names = preds
        .iter()
        .filter_map(|predecessor| outgoing.get(predecessor))
        .flat_map(|versions| versions.keys().cloned())
        .collect::<BTreeSet<_>>();

    for name in all_names {
        let base = base_name(&name);
        let Some(first_value) = first_versions.get(&base).cloned() else {
            shared.remove(&base);
            continue;
        };

        let mut agree = true;
        for predecessor in rest {
            let Some(value) = outgoing
                .get(predecessor)
                .and_then(|versions| versions.get(&base))
            else {
                agree = false;
                break;
            };
            if value != &first_value {
                agree = false;
                break;
            }
        }

        if agree {
            shared.insert(base, first_value);
            continue;
        }

        shared.remove(&base);
        if let Some(ty) = value_type(&first_value) {
            merges.push(MergeParameter {
                name: format!("{base}.phi.{block}"),
                base,
                ty,
            });
        }
    }

    (shared, merges)
}

fn wire_merge_arguments(
    mir: &mut Mir,
    indices: &HashMap<String, usize>,
    predecessors: &HashMap<String, Vec<String>>,
    outgoing: &HashMap<String, VersionMap>,
    block: &str,
    merges: &[MergeParameter],
) {
    let Some(preds) = predecessors.get(block) else {
        return;
    };

    for predecessor in preds {
        let Some(pred_index) = indices.get(predecessor).copied() else {
            continue;
        };
        let Some(outgoing_values) = outgoing.get(predecessor) else {
            continue;
        };

        let predecessor_block = &mut mir.blocks_mut()[pred_index];
        let Some(terminator) = predecessor_block.terminator.as_mut() else {
            continue;
        };

        for merge in merges {
            let Some(value) = outgoing_values.get(&merge.base).cloned() else {
                continue;
            };
            append_terminator_argument(terminator, block, value);
        }
    }
}

fn append_terminator_argument(terminator: &mut MirTerminator, target: &str, value: MirValue) {
    match terminator {
        MirTerminator::Jump {
            target: edge_target,
            arguments,
        } if edge_target == target => arguments.push(value),
        MirTerminator::CondBr {
            then_target,
            then_arguments,
            else_target,
            else_arguments,
            ..
        } => {
            if then_target == target {
                then_arguments.push(value.clone());
            }
            if else_target == target {
                else_arguments.push(value);
            }
        }
        MirTerminator::Jump { .. }
        | MirTerminator::Return { .. }
        | MirTerminator::Trap
        | MirTerminator::Unreachable => {}
    }
}

fn rewrite_operation(operation: &mut MirOperation, current: &VersionMap) {
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
            rewrite_value(lhs, current);
            rewrite_value(rhs, current);
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, current);
            rewrite_value(when_true, current);
            rewrite_value(when_false, current);
        }
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. } => rewrite_value(value, current),
        MirOperationKind::Load { address, .. } => {
            rewrite_value(address, current);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, current);
            rewrite_value(value, current);
        }
        MirOperationKind::Cast { value, .. } => {
            rewrite_value(value, current);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, current);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, current: &VersionMap) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, current);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, current);
            for argument in then_arguments {
                rewrite_value(argument, current);
            }
            for argument in else_arguments {
                rewrite_value(argument, current);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, current);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, current: &VersionMap) {
    if let MirValue::Named { name, .. } = value {
        let base = base_name(name);
        if let Some(versioned) = current.get(&base) {
            *value = versioned.clone();
        }
    }
}

fn result_type(kind: &MirOperationKind) -> MirType {
    match kind {
        MirOperationKind::Add { ty, .. }
        | MirOperationKind::Sub { ty, .. }
        | MirOperationKind::Mul { ty, .. }
        | MirOperationKind::And { ty, .. }
        | MirOperationKind::Or { ty, .. }
        | MirOperationKind::Xor { ty, .. }
        | MirOperationKind::Shl { ty, .. }
        | MirOperationKind::LShr { ty, .. }
        | MirOperationKind::AShr { ty, .. }
        | MirOperationKind::Select { ty, .. }
        | MirOperationKind::Extract { ty, .. }
        | MirOperationKind::Not { ty, .. }
        | MirOperationKind::Popcount { ty, .. }
        | MirOperationKind::Load { ty, .. }
        | MirOperationKind::Icmp { ty, .. }
        | MirOperationKind::Cast { ty, .. } => ty.clone(),
        MirOperationKind::Call { result_types, .. }
        | MirOperationKind::Intrinsic { result_types, .. } => {
            result_types.first().cloned().unwrap_or_else(MirType::void)
        }
        MirOperationKind::Store { .. } => MirType::void(),
    }
}

fn value_type(value: &MirValue) -> Option<MirType> {
    match value {
        MirValue::Named { ty, .. } | MirValue::Null { ty } | MirValue::Undef { ty } => {
            Some(ty.clone())
        }
        MirValue::Integer { bits, .. } => Some(MirType::integer(*bits)),
        MirValue::Boolean(_) => Some(MirType::integer(1)),
    }
}

fn next_version(base: &str, counters: &mut HashMap<String, usize>) -> String {
    let counter = counters.entry(base.to_string()).or_default();
    let versioned = format!("{base}.{}", *counter);
    *counter += 1;
    versioned
}

fn base_name(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((base, suffix)) if suffix.chars().all(|character| character.is_ascii_digit()) => {
            base.to_string()
        }
        _ => name.to_string(),
    }
}
