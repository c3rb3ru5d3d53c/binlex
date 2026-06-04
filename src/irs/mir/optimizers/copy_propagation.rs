use crate::irs::mir::analysis::{mir_predecessors, reverse_post_order};
use crate::irs::mir::{
    Mir, MirCastOperation, MirControlTarget, MirOperation, MirOperationKind, MirTerminator,
    MirValue,
};
use std::collections::HashMap;

type AliasMap = HashMap<String, MirValue>;

pub fn optimize_copy_propagation(mir: &mut Mir) {
    let predecessors = mir_predecessors(mir);
    let order = reverse_post_order(mir);
    let indices = mir
        .blocks()
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut outgoing = HashMap::<String, AliasMap>::new();
    let mut changed = true;

    while changed {
        changed = false;

        for block_name in &order {
            let Some(index) = indices.get(block_name).copied() else {
                continue;
            };
            let block = &mut mir.blocks_mut()[index];
            let mut aliases = incoming_aliases(&block.name, &predecessors, &outgoing);
            let original_len = block.operations.len();
            let mut normalized = Vec::with_capacity(original_len);
            let mut removed_alias = false;

            for mut operation in std::mem::take(&mut block.operations) {
                rewrite_operation(&mut operation, &aliases);

                if let Some((result, source)) = alias_from_operation(&operation) {
                    aliases.insert(result, source);
                    changed = true;
                    removed_alias = true;
                    continue;
                }

                if let Some(result) = operation.result.as_ref() {
                    aliases.remove(result);
                }
                normalized.push(operation);
            }

            if let Some(terminator) = block.terminator.as_mut() {
                rewrite_terminator(terminator, &aliases);
            }

            if removed_alias || normalized.len() != original_len {
                changed = true;
            }
            block.operations = normalized;

            if outgoing.get(&block.name) != Some(&aliases) {
                outgoing.insert(block.name.clone(), aliases);
                changed = true;
            }
        }
    }
}

fn incoming_aliases(
    block: &str,
    predecessors: &HashMap<String, Vec<String>>,
    outgoing: &HashMap<String, AliasMap>,
) -> AliasMap {
    let Some(preds) = predecessors.get(block) else {
        return AliasMap::new();
    };
    let Some((first, rest)) = preds.split_first() else {
        return AliasMap::new();
    };
    let Some(first_aliases) = outgoing.get(first) else {
        return AliasMap::new();
    };

    let mut shared = first_aliases.clone();
    for predecessor in rest {
        let Some(aliases) = outgoing.get(predecessor) else {
            shared.clear();
            break;
        };
        shared.retain(|name, value| aliases.get(name) == Some(value));
    }
    shared
}

fn alias_from_operation(operation: &MirOperation) -> Option<(String, MirValue)> {
    let result = operation.result.clone()?;
    match &operation.kind {
        MirOperationKind::Add { lhs, rhs, .. } => {
            if is_integer_zero(lhs) {
                Some((result, rhs.clone()))
            } else if is_integer_zero(rhs) {
                Some((result, lhs.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Sub { lhs, rhs, .. } => {
            if is_integer_zero(rhs) {
                Some((result, lhs.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Mul { lhs, rhs, .. } => {
            if is_integer_one(lhs) {
                Some((result, rhs.clone()))
            } else if is_integer_one(rhs) {
                Some((result, lhs.clone()))
            } else {
                None
            }
        }
        MirOperationKind::And { lhs, rhs, .. } | MirOperationKind::Or { lhs, rhs, .. } => {
            if lhs == rhs {
                Some((result, lhs.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Xor { lhs, rhs, ty } => {
            if lhs == rhs {
                Some((
                    result,
                    match ty {
                        crate::irs::mir::MirType::Integer(bits) => MirValue::integer(0, *bits),
                        _ => MirValue::boolean(false),
                    },
                ))
            } else {
                None
            }
        }
        MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. } => {
            if is_integer_zero(rhs) {
                Some((result, lhs.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => match condition {
            MirValue::Boolean(true) => Some((result, when_true.clone())),
            MirValue::Boolean(false) => Some((result, when_false.clone())),
            MirValue::Integer { value, .. } if *value == 0 => Some((result, when_false.clone())),
            MirValue::Integer { value, .. } if *value != 0 => Some((result, when_true.clone())),
            _ if when_true == when_false => Some((result, when_true.clone())),
            _ => None,
        },
        MirOperationKind::Copy { value, .. } => Some((result, value.clone())),
        MirOperationKind::Extract { value, lsb, ty } => {
            if *lsb == 0 {
                match value {
                    MirValue::Named { ty: value_ty, .. } if value_ty == ty => {
                        Some((result, value.clone()))
                    }
                    _ => None,
                }
            } else {
                None
            }
        }
        MirOperationKind::Concat { .. }
        | MirOperationKind::Neg { .. }
        | MirOperationKind::Not { .. }
        | MirOperationKind::Popcount { .. }
        | MirOperationKind::CountLeadingZeros { .. }
        | MirOperationKind::CountTrailingZeros { .. } => None,
        MirOperationKind::Cast {
            op: MirCastOperation::Bitcast,
            value,
            ..
        } => Some((result, value.clone())),
        MirOperationKind::Load { .. }
        | MirOperationKind::AddressOf { .. }
        | MirOperationKind::Store { .. }
        | MirOperationKind::MemoryCopy { .. }
        | MirOperationKind::Icmp { .. }
        | MirOperationKind::UDiv { .. }
        | MirOperationKind::SDiv { .. }
        | MirOperationKind::URem { .. }
        | MirOperationKind::SRem { .. }
        | MirOperationKind::RotateLeft { .. }
        | MirOperationKind::RotateRight { .. }
        | MirOperationKind::FAdd { .. }
        | MirOperationKind::FSub { .. }
        | MirOperationKind::FMul { .. }
        | MirOperationKind::FDiv { .. }
        | MirOperationKind::Fcmp { .. }
        | MirOperationKind::Call { .. }
        | MirOperationKind::Intrinsic { .. }
        | MirOperationKind::Cast { .. } => None,
    }
}

fn is_integer_zero(value: &MirValue) -> bool {
    matches!(value, MirValue::Integer { value: 0, .. })
}

fn is_integer_one(value: &MirValue) -> bool {
    matches!(value, MirValue::Integer { value: 1, .. })
}

fn rewrite_operation(operation: &mut MirOperation, aliases: &AliasMap) {
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
            rewrite_value(lhs, aliases);
            rewrite_value(rhs, aliases);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                rewrite_value(part, aliases);
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, aliases);
            rewrite_value(when_true, aliases);
            rewrite_value(when_false, aliases);
        }
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. } => rewrite_value(value, aliases),
        MirOperationKind::Load { address, .. } | MirOperationKind::AddressOf { address, .. } => {
            rewrite_value(address, aliases);
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, aliases);
            rewrite_value(value, aliases);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_value(src_address, aliases);
            rewrite_value(dst_address, aliases);
            rewrite_value(count, aliases);
            rewrite_value(decrement, aliases);
        }
        MirOperationKind::Cast { value, .. } => {
            rewrite_value(value, aliases);
        }
        MirOperationKind::Call {
            target, arguments, ..
        } => {
            rewrite_target(target, aliases);
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, aliases);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, aliases: &AliasMap) {
    match terminator {
        MirTerminator::Jump { target, arguments } => {
            rewrite_target(target, aliases);
            for argument in arguments {
                rewrite_value(argument, aliases);
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
            rewrite_value(condition, aliases);
            rewrite_target(then_target, aliases);
            rewrite_target(else_target, aliases);
            for argument in then_arguments {
                rewrite_value(argument, aliases);
            }
            for argument in else_arguments {
                rewrite_value(argument, aliases);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, aliases);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, aliases: &AliasMap) {
    if let MirValue::Named { name, .. } = value {
        if let Some(replacement) = aliases.get(name) {
            *value = replacement.clone();
        }
    }
}

fn rewrite_target(target: &mut MirControlTarget, aliases: &AliasMap) {
    match target {
        MirControlTarget::FunctionIndirect(value) | MirControlTarget::BlockIndirect(value) => {
            rewrite_value(value, aliases);
        }
        MirControlTarget::Direct(_) => {}
    }
}
