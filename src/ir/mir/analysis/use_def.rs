use crate::ir::mir::{Mir, MirOperationKind, MirTerminator, MirValue};
use std::collections::HashMap;

#[derive(Clone, Debug, Default)]
pub struct MirUseDef {
    pub defs: HashMap<String, String>,
    pub uses: HashMap<String, Vec<String>>,
}

pub fn build_use_def(mir: &Mir) -> MirUseDef {
    let mut data = MirUseDef::default();
    for block in mir.blocks() {
        for operation in &block.operations {
            if let Some(result) = operation.result.as_ref() {
                data.defs.insert(result.clone(), block.name.clone());
            }
            for name in operation_uses(&operation.kind) {
                data.uses.entry(name).or_default().push(block.name.clone());
            }
        }
        if let Some(terminator) = block.terminator.as_ref() {
            for name in terminator_uses(terminator) {
                data.uses.entry(name).or_default().push(block.name.clone());
            }
        }
    }
    data
}

fn operation_uses(kind: &MirOperationKind) -> Vec<String> {
    match kind {
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. } => vec_from_values([lhs, rhs]),
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => vec_from_values([condition, when_true, when_false]),
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. } => vec_from_values([value]),
        MirOperationKind::Load { address, .. } => vec_from_values([address]),
        MirOperationKind::Store { address, value, .. } => vec_from_values([address, value]),
        MirOperationKind::Cast { value, .. } => vec_from_values([value]),
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            arguments.iter().filter_map(named_value).collect()
        }
    }
}

fn terminator_uses(terminator: &MirTerminator) -> Vec<String> {
    match terminator {
        MirTerminator::Jump { arguments, .. } | MirTerminator::Return { values: arguments } => {
            arguments.iter().filter_map(named_value).collect()
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => std::iter::once(condition)
            .chain(then_arguments.iter())
            .chain(else_arguments.iter())
            .filter_map(named_value)
            .collect(),
        MirTerminator::Trap | MirTerminator::Unreachable => Vec::new(),
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
