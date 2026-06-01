use crate::ir::mir::analysis::{mir_predecessors, mir_successors, reverse_post_order};
use crate::ir::mir::{
    Mir, MirBlockParameter, MirControlTarget, MirOperation, MirOperationKind, MirTerminator,
    MirType, MirValue,
};
use std::collections::{HashMap, HashSet};

type VersionMap = HashMap<String, MirValue>;

#[derive(Clone, Debug)]
struct MergeParameter {
    base: String,
    name: String,
    ty: MirType,
}

pub fn optimize_ssa(mir: &mut Mir) {
    let predecessors = mir_predecessors(mir);
    let successors = mir_successors(mir);
    let order = reverse_post_order(mir);
    let indices = mir
        .blocks()
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect::<HashMap<_, _>>();
    let live_in = live_in_bases(mir, &order, &successors);
    let mut outgoing = HashMap::<String, VersionMap>::new();
    clear_ssa_edges(mir);
    let mut counters = HashMap::<String, usize>::new();

    for block_name in &order {
        let Some(index) = indices.get(block_name).copied() else {
            continue;
        };

        let (mut current, merges) = incoming_versions(
            block_name,
            &predecessors,
            &outgoing,
            live_in.get(block_name),
        );

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

        outgoing.insert(block.name.clone(), current);
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
    live_in: Option<&HashSet<String>>,
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

    let mut shared = VersionMap::new();
    let mut merges = Vec::new();
    let Some(live_bases) = live_in else {
        return (shared, merges);
    };

    for base in live_bases {
        let Some(first_value) = first_versions.get(base).cloned() else {
            continue;
        };

        let mut agree = true;
        for predecessor in rest {
            let Some(value) = outgoing
                .get(predecessor)
                .and_then(|versions| versions.get(base))
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
            shared.insert(base.clone(), first_value);
            continue;
        }

        if let Some(ty) = value_type(&first_value) {
            merges.push(MergeParameter {
                name: format!("{base}.phi.{block}"),
                base: base.clone(),
                ty,
            });
        }
    }

    (shared, merges)
}

fn live_in_bases(
    mir: &Mir,
    order: &[String],
    successors: &HashMap<String, Vec<String>>,
) -> HashMap<String, HashSet<String>> {
    let mut uses = HashMap::<String, HashSet<String>>::new();
    let mut defs = HashMap::<String, HashSet<String>>::new();
    for block in mir.blocks() {
        let (block_uses, block_defs) = block_use_def(block);
        uses.insert(block.name.clone(), block_uses);
        defs.insert(block.name.clone(), block_defs);
    }

    let mut live_in = HashMap::<String, HashSet<String>>::new();
    let mut live_out = HashMap::<String, HashSet<String>>::new();

    loop {
        let mut changed = false;
        for block_name in order.iter().rev() {
            let mut out = HashSet::<String>::new();
            if let Some(edges) = successors.get(block_name) {
                for successor in edges {
                    if let Some(successor_live_in) = live_in.get(successor) {
                        out.extend(successor_live_in.iter().cloned());
                    }
                }
            }

            let mut incoming = uses.get(block_name).cloned().unwrap_or_default();
            let block_defs = defs.get(block_name).cloned().unwrap_or_default();
            for name in &out {
                if !block_defs.contains(name) {
                    incoming.insert(name.clone());
                }
            }

            if live_out.get(block_name) != Some(&out) {
                live_out.insert(block_name.clone(), out);
                changed = true;
            }
            if live_in.get(block_name) != Some(&incoming) {
                live_in.insert(block_name.clone(), incoming);
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    live_in
}

fn block_use_def(block: &crate::ir::mir::MirBlock) -> (HashSet<String>, HashSet<String>) {
    let mut uses = HashSet::<String>::new();
    let mut defs = HashSet::<String>::new();

    for operation in &block.operations {
        for used in operation_bases(&operation.kind) {
            if !defs.contains(&used) {
                uses.insert(used);
            }
        }
        if let Some(result) = operation.result.as_ref() {
            defs.insert(base_name(result));
        }
    }

    if let Some(terminator) = block.terminator.as_ref() {
        for used in terminator_bases(terminator) {
            if !defs.contains(&used) {
                uses.insert(used);
            }
        }
    }

    (uses, defs)
}

fn operation_bases(kind: &MirOperationKind) -> Vec<String> {
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
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => vec_from_values([condition, when_true, when_false]),
        MirOperationKind::Concat { parts, .. } => parts.iter().filter_map(value_base).collect(),
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::AddressOf { address: value, .. }
        | MirOperationKind::Cast { value, .. } => vec_from_values([value]),
        MirOperationKind::Store { address, value, .. } => vec_from_values([address, value]),
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => vec_from_values([src_address, dst_address, count, decrement]),
        MirOperationKind::Call {
            target, arguments, ..
        } => target_bases(target)
            .into_iter()
            .chain(arguments.iter().filter_map(value_base))
            .collect(),
        MirOperationKind::Intrinsic { arguments, .. } => {
            arguments.iter().filter_map(value_base).collect()
        }
    }
}

fn terminator_bases(terminator: &MirTerminator) -> Vec<String> {
    match terminator {
        MirTerminator::Jump { arguments, .. } | MirTerminator::Return { values: arguments } => {
            arguments.iter().filter_map(value_base).collect()
        }
        MirTerminator::CondBr {
            condition,
            then_target,
            then_arguments,
            else_target,
            else_arguments,
            ..
        } => std::iter::once(condition)
            .chain(then_arguments.iter())
            .chain(else_arguments.iter())
            .filter_map(value_base)
            .chain(target_bases(then_target))
            .chain(target_bases(else_target))
            .collect(),
        MirTerminator::Trap | MirTerminator::Unreachable => Vec::new(),
    }
}

fn value_base(value: &MirValue) -> Option<String> {
    match value {
        MirValue::Named { name, .. } => Some(base_name(name)),
        _ => None,
    }
}

fn target_bases(target: &MirControlTarget) -> Vec<String> {
    match target {
        MirControlTarget::Direct(_) => Vec::new(),
        MirControlTarget::FunctionIndirect(value) | MirControlTarget::BlockIndirect(value) => {
            value_base(value).into_iter().collect()
        }
    }
}

fn vec_from_values<const N: usize>(values: [&MirValue; N]) -> Vec<String> {
    values.into_iter().filter_map(value_base).collect()
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
        } => {
            if direct_target_name(edge_target) == Some(target) {
                arguments.push(value);
            }
        }
        MirTerminator::CondBr {
            then_target,
            then_arguments,
            else_target,
            else_arguments,
            ..
        } => {
            if matches!(then_target, MirControlTarget::Direct(name) if name == target) {
                then_arguments.push(value.clone());
            }
            if matches!(else_target, MirControlTarget::Direct(name) if name == target) {
                else_arguments.push(value);
            }
        }
        MirTerminator::Return { .. } | MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn direct_target_name(target: &MirControlTarget) -> Option<&str> {
    match target {
        MirControlTarget::Direct(name) => Some(name.as_str()),
        MirControlTarget::FunctionIndirect(_) | MirControlTarget::BlockIndirect(_) => None,
    }
}

fn rewrite_operation(operation: &mut MirOperation, current: &VersionMap) {
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
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                rewrite_value(part, current);
            }
        }
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Popcount { value, .. } => rewrite_value(value, current),
        MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. } => rewrite_value(value, current),
        MirOperationKind::Load { address, .. } | MirOperationKind::AddressOf { address, .. } => {
            rewrite_value(address, current);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, current);
            rewrite_value(value, current);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_value(src_address, current);
            rewrite_value(dst_address, current);
            rewrite_value(count, current);
            rewrite_value(decrement, current);
        }
        MirOperationKind::Cast { value, .. } => {
            rewrite_value(value, current);
        }
        MirOperationKind::Call {
            target, arguments, ..
        } => {
            rewrite_target(target, current);
            for argument in arguments {
                rewrite_value(argument, current);
            }
        }
        MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, current);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, current: &VersionMap) {
    match terminator {
        MirTerminator::Jump { target, arguments } => {
            rewrite_target(target, current);
            for argument in arguments {
                rewrite_value(argument, current);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_target,
            then_arguments,
            else_target,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, current);
            rewrite_target(then_target, current);
            rewrite_target(else_target, current);
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

fn rewrite_target(target: &mut MirControlTarget, current: &VersionMap) {
    match target {
        MirControlTarget::FunctionIndirect(value) | MirControlTarget::BlockIndirect(value) => {
            rewrite_value(value, current);
        }
        MirControlTarget::Direct(_) => {}
    }
}

fn result_type(kind: &MirOperationKind) -> MirType {
    match kind {
        MirOperationKind::Copy { ty, .. }
        | MirOperationKind::Add { ty, .. }
        | MirOperationKind::Sub { ty, .. }
        | MirOperationKind::Mul { ty, .. }
        | MirOperationKind::FAdd { ty, .. }
        | MirOperationKind::FSub { ty, .. }
        | MirOperationKind::FMul { ty, .. }
        | MirOperationKind::FDiv { ty, .. }
        | MirOperationKind::And { ty, .. }
        | MirOperationKind::Or { ty, .. }
        | MirOperationKind::Xor { ty, .. }
        | MirOperationKind::Shl { ty, .. }
        | MirOperationKind::LShr { ty, .. }
        | MirOperationKind::AShr { ty, .. }
        | MirOperationKind::UDiv { ty, .. }
        | MirOperationKind::SDiv { ty, .. }
        | MirOperationKind::URem { ty, .. }
        | MirOperationKind::SRem { ty, .. }
        | MirOperationKind::RotateLeft { ty, .. }
        | MirOperationKind::RotateRight { ty, .. }
        | MirOperationKind::Select { ty, .. }
        | MirOperationKind::Concat { ty, .. }
        | MirOperationKind::Extract { ty, .. }
        | MirOperationKind::Not { ty, .. }
        | MirOperationKind::Neg { ty, .. }
        | MirOperationKind::Popcount { ty, .. }
        | MirOperationKind::CountLeadingZeros { ty, .. }
        | MirOperationKind::CountTrailingZeros { ty, .. }
        | MirOperationKind::Load { ty, .. }
        | MirOperationKind::AddressOf { ty, .. }
        | MirOperationKind::Icmp { ty, .. }
        | MirOperationKind::Fcmp { ty, .. }
        | MirOperationKind::Cast { ty, .. } => ty.clone(),
        MirOperationKind::Call { result_types, .. }
        | MirOperationKind::Intrinsic { result_types, .. } => {
            result_types.first().cloned().unwrap_or_else(MirType::void)
        }
        MirOperationKind::Store { .. } | MirOperationKind::MemoryCopy { .. } => MirType::void(),
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
