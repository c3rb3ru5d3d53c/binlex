use crate::ir::mir::{Mir, MirControlTarget, MirOperationKind, MirTerminator, MirValue};
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

pub fn build_use_counts(mir: &Mir) -> HashMap<String, usize> {
    let mut counts = HashMap::<String, usize>::new();
    for block in mir.blocks() {
        for operation in &block.operations {
            record_operation_use_counts(&mut counts, &operation.kind);
        }
        if let Some(terminator) = block.terminator.as_ref() {
            record_terminator_use_counts(&mut counts, terminator);
        }
    }
    counts
}

fn operation_uses(kind: &MirOperationKind) -> Vec<String> {
    match kind {
        MirOperationKind::Copy { value, .. } => vec_from_values([value]),
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
        MirOperationKind::Concat { parts, .. } => parts.iter().filter_map(named_value).collect(),
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. } => vec_from_values([value]),
        MirOperationKind::Load { address, .. } => vec_from_values([address]),
        MirOperationKind::Store { address, value, .. } => vec_from_values([address, value]),
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => vec_from_values([src_address, dst_address, count, decrement]),
        MirOperationKind::Cast { value, .. } => vec_from_values([value]),
        MirOperationKind::Call {
            target, arguments, ..
        } => target_uses(target)
            .into_iter()
            .chain(arguments.iter().filter_map(named_value))
            .collect(),
        MirOperationKind::Intrinsic { arguments, .. } => {
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
            then_target,
            then_arguments,
            else_target,
            else_arguments,
            ..
        } => std::iter::once(condition)
            .chain(then_arguments.iter())
            .chain(else_arguments.iter())
            .filter_map(named_value)
            .chain(target_uses(then_target))
            .chain(target_uses(else_target))
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

fn record_named(counts: &mut HashMap<String, usize>, value: &MirValue) {
    if let Some(name) = named_value(value) {
        *counts.entry(name).or_default() += 1;
    }
}

fn record_operation_use_counts(counts: &mut HashMap<String, usize>, kind: &MirOperationKind) {
    match kind {
        MirOperationKind::Copy { value, .. } => record_named(counts, value),
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
            record_named(counts, lhs);
            record_named(counts, rhs);
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            record_named(counts, condition);
            record_named(counts, when_true);
            record_named(counts, when_false);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                record_named(counts, part);
            }
        }
        MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::Cast { value, .. } => record_named(counts, value),
        MirOperationKind::Store { address, value, .. } => {
            record_named(counts, address);
            record_named(counts, value);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            record_named(counts, src_address);
            record_named(counts, dst_address);
            record_named(counts, count);
            record_named(counts, decrement);
        }
        MirOperationKind::Call {
            target, arguments, ..
        } => {
            for name in target_uses(target) {
                *counts.entry(name).or_default() += 1;
            }
            for argument in arguments {
                record_named(counts, argument);
            }
        }
        MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                record_named(counts, argument);
            }
        }
    }
}

fn record_terminator_use_counts(counts: &mut HashMap<String, usize>, terminator: &MirTerminator) {
    match terminator {
        MirTerminator::Jump { arguments, .. } | MirTerminator::Return { values: arguments } => {
            for argument in arguments {
                record_named(counts, argument);
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
            record_named(counts, condition);
            for name in target_uses(then_target) {
                *counts.entry(name).or_default() += 1;
            }
            for name in target_uses(else_target) {
                *counts.entry(name).or_default() += 1;
            }
            for argument in then_arguments {
                record_named(counts, argument);
            }
            for argument in else_arguments {
                record_named(counts, argument);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn target_uses(target: &MirControlTarget) -> Vec<String> {
    match target {
        MirControlTarget::Direct(_) => Vec::new(),
        MirControlTarget::FunctionIndirect(value) | MirControlTarget::BlockIndirect(value) => {
            named_value(value).into_iter().collect()
        }
    }
}
