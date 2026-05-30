use crate::ir::mir::analysis::{build_use_counts, mir_predecessors};
use crate::ir::mir::{Mir, MirControlTarget, MirTerminator, MirValue};
use std::collections::{HashMap, HashSet};

pub fn optimize_ssa_liveness(mir: &mut Mir) {
    let indices = mir
        .blocks()
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect::<HashMap<_, _>>();
    let predecessors = mir_predecessors(mir);

    loop {
        let mut changed = fold_trivial_block_parameters(mir, &indices, &predecessors);
        let uses = build_use_counts(mir);

        for block_index in 0..mir.blocks().len() {
            let block_name = mir.blocks()[block_index].name.clone();
            let keep_indices = mir.blocks()[block_index]
                .parameters
                .iter()
                .enumerate()
                .filter_map(|(index, parameter)| {
                    let name = parameter.name.as_ref()?;
                    if uses.contains_key(name) {
                        Some(index)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();

            if keep_indices.len() == mir.blocks()[block_index].parameters.len() {
                continue;
            }

            let old_len = mir.blocks()[block_index].parameters.len();
            mir.blocks_mut()[block_index].parameters = keep_selected(
                std::mem::take(&mut mir.blocks_mut()[block_index].parameters),
                &keep_indices,
            );
            changed |= mir.blocks()[block_index].parameters.len() != old_len;

            for predecessor in mir.blocks_mut() {
                let Some(terminator) = predecessor.terminator.as_mut() else {
                    continue;
                };
                trim_edge_arguments(terminator, &block_name, &keep_indices);
            }
        }

        if !changed {
            break;
        }
    }
}

fn keep_selected<T>(values: Vec<T>, keep_indices: &[usize]) -> Vec<T> {
    let keep = keep_indices.iter().copied().collect::<HashSet<_>>();
    values
        .into_iter()
        .enumerate()
        .filter_map(|(index, value)| keep.contains(&index).then_some(value))
        .collect()
}

fn trim_edge_arguments(terminator: &mut MirTerminator, target: &str, keep_indices: &[usize]) {
    match terminator {
        MirTerminator::Jump {
            target: edge_target,
            arguments,
        } => {
            if direct_target_name(edge_target) == Some(target) {
                *arguments = keep_selected(std::mem::take(arguments), keep_indices);
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
                *then_arguments = keep_selected(std::mem::take(then_arguments), keep_indices);
            }
            if matches!(else_target, MirControlTarget::Direct(name) if name == target) {
                *else_arguments = keep_selected(std::mem::take(else_arguments), keep_indices);
            }
        }
        MirTerminator::Return { .. } | MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn fold_trivial_block_parameters(
    mir: &mut Mir,
    indices: &HashMap<String, usize>,
    predecessors: &HashMap<String, Vec<String>>,
) -> bool {
    let mut changed = false;
    let block_names = mir
        .blocks()
        .iter()
        .map(|block| block.name.clone())
        .collect::<Vec<_>>();

    for block_name in block_names {
        let Some(block_index) = indices.get(&block_name).copied() else {
            continue;
        };

        let param_len = mir.blocks()[block_index].parameters.len();
        if param_len == 0 {
            continue;
        }

        let mut replacements = Vec::<(usize, MirValue)>::new();
        for param_index in 0..param_len {
            let Some(incoming) =
                incoming_argument_values(mir, indices, predecessors, &block_name, param_index)
            else {
                continue;
            };
            if incoming.is_empty() {
                continue;
            }
            let first = incoming[0].clone();
            if incoming.iter().all(|value| *value == first) {
                replacements.push((param_index, first));
            }
        }

        if replacements.is_empty() {
            continue;
        }

        for (param_index, replacement) in replacements.iter().rev() {
            let Some(name) = mir.blocks()[block_index].parameters[*param_index]
                .name
                .clone()
            else {
                continue;
            };
            replace_block_uses(&mut mir.blocks_mut()[block_index], &name, replacement);
            mir.blocks_mut()[block_index]
                .parameters
                .remove(*param_index);
            for predecessor in mir.blocks_mut() {
                let Some(terminator) = predecessor.terminator.as_mut() else {
                    continue;
                };
                remove_edge_argument(terminator, &block_name, *param_index);
            }
            changed = true;
        }
    }

    changed
}

fn incoming_argument_values(
    mir: &Mir,
    indices: &HashMap<String, usize>,
    predecessors: &HashMap<String, Vec<String>>,
    target: &str,
    param_index: usize,
) -> Option<Vec<MirValue>> {
    let mut values = Vec::new();
    let Some(preds) = predecessors.get(target) else {
        return Some(values);
    };
    for predecessor in preds {
        let index = indices.get(predecessor).copied()?;
        let block = &mir.blocks()[index];
        let terminator = block.terminator.as_ref()?;
        match terminator {
            MirTerminator::Jump {
                target: edge_target,
                arguments,
            } => {
                if direct_target_name(edge_target) == Some(target) {
                    values.push(arguments.get(param_index)?.clone());
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
                    values.push(then_arguments.get(param_index)?.clone());
                }
                if matches!(else_target, MirControlTarget::Direct(name) if name == target) {
                    values.push(else_arguments.get(param_index)?.clone());
                }
            }
            _ => {}
        }
    }
    Some(values)
}

fn replace_block_uses(block: &mut crate::ir::mir::MirBlock, name: &str, replacement: &MirValue) {
    for operation in &mut block.operations {
        replace_operation_uses(operation, name, replacement);
    }
    if let Some(terminator) = block.terminator.as_mut() {
        replace_terminator_uses(terminator, name, replacement);
    }
}

fn replace_operation_uses(
    operation: &mut crate::ir::mir::MirOperation,
    name: &str,
    replacement: &MirValue,
) {
    use crate::ir::mir::MirOperationKind;
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
            replace_value(lhs, name, replacement);
            replace_value(rhs, name, replacement);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                replace_value(part, name, replacement);
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            replace_value(condition, name, replacement);
            replace_value(when_true, name, replacement);
            replace_value(when_false, name, replacement);
        }
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Cast { value, .. }
        | MirOperationKind::Load { address: value, .. } => replace_value(value, name, replacement),
        MirOperationKind::Store { address, value, .. } => {
            replace_value(address, name, replacement);
            replace_value(value, name, replacement);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            replace_value(src_address, name, replacement);
            replace_value(dst_address, name, replacement);
            replace_value(count, name, replacement);
            replace_value(decrement, name, replacement);
        }
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                replace_value(argument, name, replacement);
            }
        }
    }
}

fn replace_terminator_uses(terminator: &mut MirTerminator, name: &str, replacement: &MirValue) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                replace_value(argument, name, replacement);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            replace_value(condition, name, replacement);
            for argument in then_arguments {
                replace_value(argument, name, replacement);
            }
            for argument in else_arguments {
                replace_value(argument, name, replacement);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                replace_value(value, name, replacement);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn replace_value(value: &mut MirValue, name: &str, replacement: &MirValue) {
    if matches!(value, MirValue::Named { name: current, .. } if current == name) {
        *value = replacement.clone();
    }
}

fn remove_edge_argument(terminator: &mut MirTerminator, target: &str, param_index: usize) {
    match terminator {
        MirTerminator::Jump {
            target: edge_target,
            arguments,
        } => {
            if direct_target_name(edge_target) == Some(target) && param_index < arguments.len() {
                arguments.remove(param_index);
            }
        }
        MirTerminator::CondBr {
            then_target,
            then_arguments,
            else_target,
            else_arguments,
            ..
        } => {
            if matches!(then_target, MirControlTarget::Direct(name) if name == target)
                && param_index < then_arguments.len()
            {
                then_arguments.remove(param_index);
            }
            if matches!(else_target, MirControlTarget::Direct(name) if name == target)
                && param_index < else_arguments.len()
            {
                else_arguments.remove(param_index);
            }
        }
        _ => {}
    }
}

fn direct_target_name(target: &MirControlTarget) -> Option<&str> {
    match target {
        MirControlTarget::Direct(name) => Some(name.as_str()),
        MirControlTarget::FunctionIndirect(_) | MirControlTarget::BlockIndirect(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::mir::{MirBlock, MirBlockParameter, MirOperation, MirOperationKind, MirType};

    #[test]
    fn does_not_fold_parameter_when_any_predecessor_lacks_argument() {
        let ty = MirType::integer(64);
        let mut mir = Mir::new(Some("test".to_string()));

        let mut entry = MirBlock::new("entry".to_string());
        entry.set_terminator(MirTerminator::CondBr {
            condition: MirValue::boolean(true),
            then_target: MirControlTarget::direct("merge".to_string()),
            then_arguments: vec![MirValue::integer(0, 64)],
            else_target: MirControlTarget::direct("loop".to_string()),
            else_arguments: Vec::new(),
        });
        mir.append_block(entry);

        let mut merge = MirBlock::new("merge".to_string());
        merge.append_parameter(MirBlockParameter::new(
            Some("value.phi.merge".to_string()),
            ty.clone(),
        ));
        merge.append_operation(MirOperation::new(
            Some("use_value".to_string()),
            MirOperationKind::Copy {
                value: MirValue::named("value.phi.merge".to_string(), ty.clone()),
                ty: ty.clone(),
            },
        ));
        merge.set_terminator(MirTerminator::Return {
            values: vec![MirValue::named("use_value".to_string(), ty.clone())],
        });
        mir.append_block(merge);

        let mut loop_block = MirBlock::new("loop".to_string());
        loop_block.set_terminator(MirTerminator::Jump {
            target: MirControlTarget::direct("merge".to_string()),
            arguments: Vec::new(),
        });
        mir.append_block(loop_block);

        optimize_ssa_liveness(&mut mir);

        let merge = mir
            .blocks()
            .iter()
            .find(|block| block.name == "merge")
            .expect("merge block");
        assert_eq!(merge.parameters.len(), 1);
    }
}
