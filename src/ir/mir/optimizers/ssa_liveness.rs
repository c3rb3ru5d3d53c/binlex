use crate::ir::mir::analysis::build_use_def;
use crate::ir::mir::{Mir, MirTerminator, MirValue};

pub fn optimize_ssa_liveness(mir: &mut Mir) {
    loop {
        let mut changed = fold_trivial_block_parameters(mir);
        let uses = build_use_def(mir).uses;

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
    values
        .into_iter()
        .enumerate()
        .filter_map(|(index, value)| keep_indices.contains(&index).then_some(value))
        .collect()
}

fn trim_edge_arguments(terminator: &mut MirTerminator, target: &str, keep_indices: &[usize]) {
    match terminator {
        MirTerminator::Jump {
            target: edge_target,
            arguments,
        } if edge_target == target => {
            *arguments = keep_selected(std::mem::take(arguments), keep_indices);
        }
        MirTerminator::CondBr {
            then_target,
            then_arguments,
            else_target,
            else_arguments,
            ..
        } => {
            if then_target == target {
                *then_arguments = keep_selected(std::mem::take(then_arguments), keep_indices);
            }
            if else_target == target {
                *else_arguments = keep_selected(std::mem::take(else_arguments), keep_indices);
            }
        }
        MirTerminator::Jump { .. }
        | MirTerminator::Return { .. }
        | MirTerminator::Trap
        | MirTerminator::Unreachable => {}
    }
}

fn fold_trivial_block_parameters(mir: &mut Mir) -> bool {
    let mut changed = false;
    let block_names = mir
        .blocks()
        .iter()
        .map(|block| block.name.clone())
        .collect::<Vec<_>>();

    for block_name in block_names {
        let Some(block_index) = mir
            .blocks()
            .iter()
            .position(|block| block.name == block_name)
        else {
            continue;
        };

        let param_len = mir.blocks()[block_index].parameters.len();
        if param_len == 0 {
            continue;
        }

        let mut replacements = Vec::<(usize, MirValue)>::new();
        for param_index in 0..param_len {
            let incoming = incoming_argument_values(mir, &block_name, param_index);
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

fn incoming_argument_values(mir: &Mir, target: &str, param_index: usize) -> Vec<MirValue> {
    let mut values = Vec::new();
    for block in mir.blocks() {
        let Some(terminator) = block.terminator.as_ref() else {
            continue;
        };
        match terminator {
            MirTerminator::Jump {
                target: edge_target,
                arguments,
            } if edge_target == target => {
                if let Some(value) = arguments.get(param_index) {
                    values.push(value.clone());
                }
            }
            MirTerminator::CondBr {
                then_target,
                then_arguments,
                else_target,
                else_arguments,
                ..
            } => {
                if then_target == target {
                    if let Some(value) = then_arguments.get(param_index) {
                        values.push(value.clone());
                    }
                }
                if else_target == target {
                    if let Some(value) = else_arguments.get(param_index) {
                        values.push(value.clone());
                    }
                }
            }
            _ => {}
        }
    }
    values
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
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. } => {
            replace_value(lhs, name, replacement);
            replace_value(rhs, name, replacement);
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
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::Cast { value, .. }
        | MirOperationKind::Load { address: value, .. } => replace_value(value, name, replacement),
        MirOperationKind::Store { address, value, .. } => {
            replace_value(address, name, replacement);
            replace_value(value, name, replacement);
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
        } if edge_target == target => {
            if param_index < arguments.len() {
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
            if then_target == target && param_index < then_arguments.len() {
                then_arguments.remove(param_index);
            }
            if else_target == target && param_index < else_arguments.len() {
                else_arguments.remove(param_index);
            }
        }
        _ => {}
    }
}
