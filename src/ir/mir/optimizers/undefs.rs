use crate::ir::mir::analysis::{mir_predecessors, reverse_post_order};
use crate::ir::mir::{Mir, MirOperation, MirOperationKind, MirTerminator, MirType, MirValue};
use std::collections::HashMap;

type UndefMap = HashMap<String, MirValue>;

pub fn optimize_undefs(mir: &mut Mir) {
    let predecessors = mir_predecessors(mir);
    let order = reverse_post_order(mir);
    let indices = mir
        .blocks()
        .iter()
        .enumerate()
        .map(|(index, block)| (block.name.clone(), index))
        .collect::<HashMap<_, _>>();
    let mut outgoing = HashMap::<String, UndefMap>::new();
    let mut changed = true;

    while changed {
        changed = false;

        for block_name in &order {
            let Some(index) = indices.get(block_name).copied() else {
                continue;
            };
            let block = &mut mir.blocks_mut()[index];
            let mut undefs = incoming_undefs(&block.name, &predecessors, &outgoing);

            for operation in &mut block.operations {
                rewrite_operation(operation, &undefs);

                if let Some(result) = operation.result.as_ref() {
                    if let Some(value) = fold_undef(&operation.kind) {
                        undefs.insert(result.clone(), value);
                    } else {
                        undefs.remove(result);
                    }
                }
            }

            if let Some(terminator) = block.terminator.as_mut() {
                rewrite_terminator(terminator, &undefs);
            }

            if outgoing.get(&block.name) != Some(&undefs) {
                outgoing.insert(block.name.clone(), undefs);
                changed = true;
            }
        }
    }
}

fn incoming_undefs(
    block: &str,
    predecessors: &HashMap<String, Vec<String>>,
    outgoing: &HashMap<String, UndefMap>,
) -> UndefMap {
    let Some(preds) = predecessors.get(block) else {
        return UndefMap::new();
    };
    let Some((first, rest)) = preds.split_first() else {
        return UndefMap::new();
    };
    let Some(first_undefs) = outgoing.get(first) else {
        return UndefMap::new();
    };

    let mut shared = first_undefs.clone();
    for predecessor in rest {
        let Some(undefs) = outgoing.get(predecessor) else {
            shared.clear();
            break;
        };
        shared.retain(|name, value| undefs.get(name) == Some(value));
    }
    shared
}

fn rewrite_operation(operation: &mut MirOperation, undefs: &UndefMap) {
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
            rewrite_value(lhs, undefs);
            rewrite_value(rhs, undefs);
        }
        MirOperationKind::Concat { parts, .. } => {
            for part in parts {
                rewrite_value(part, undefs);
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_value(condition, undefs);
            rewrite_value(when_true, undefs);
            rewrite_value(when_false, undefs);
        }
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. } => rewrite_value(value, undefs),
        MirOperationKind::Load { address, .. } | MirOperationKind::AddressOf { address, .. } => {
            rewrite_value(address, undefs)
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_value(address, undefs);
            rewrite_value(value, undefs);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_value(src_address, undefs);
            rewrite_value(dst_address, undefs);
            rewrite_value(count, undefs);
            rewrite_value(decrement, undefs);
        }
        MirOperationKind::Cast { value, .. } => rewrite_value(value, undefs),
        MirOperationKind::Call { arguments, .. }
        | MirOperationKind::Intrinsic { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, undefs);
            }
        }
    }
}

fn rewrite_terminator(terminator: &mut MirTerminator, undefs: &UndefMap) {
    match terminator {
        MirTerminator::Jump { arguments, .. } => {
            for argument in arguments {
                rewrite_value(argument, undefs);
            }
        }
        MirTerminator::CondBr {
            condition,
            then_arguments,
            else_arguments,
            ..
        } => {
            rewrite_value(condition, undefs);
            for argument in then_arguments {
                rewrite_value(argument, undefs);
            }
            for argument in else_arguments {
                rewrite_value(argument, undefs);
            }
        }
        MirTerminator::Return { values } => {
            for value in values {
                rewrite_value(value, undefs);
            }
        }
        MirTerminator::Trap | MirTerminator::Unreachable => {}
    }
}

fn rewrite_value(value: &mut MirValue, undefs: &UndefMap) {
    if let MirValue::Named { name, .. } = value {
        if let Some(replacement) = undefs.get(name) {
            *value = replacement.clone();
        }
    }
}

fn fold_undef(kind: &MirOperationKind) -> Option<MirValue> {
    match kind {
        MirOperationKind::Add { lhs, rhs, ty }
        | MirOperationKind::Sub { lhs, rhs, ty }
        | MirOperationKind::Mul { lhs, rhs, ty }
        | MirOperationKind::FAdd { lhs, rhs, ty }
        | MirOperationKind::FSub { lhs, rhs, ty }
        | MirOperationKind::FMul { lhs, rhs, ty }
        | MirOperationKind::FDiv { lhs, rhs, ty }
        | MirOperationKind::And { lhs, rhs, ty }
        | MirOperationKind::Or { lhs, rhs, ty }
        | MirOperationKind::Xor { lhs, rhs, ty }
        | MirOperationKind::Shl { lhs, rhs, ty }
        | MirOperationKind::LShr { lhs, rhs, ty }
        | MirOperationKind::AShr { lhs, rhs, ty } => {
            if is_undef(lhs) || is_undef(rhs) {
                Some(MirValue::undef(ty.clone()))
            } else {
                None
            }
        }
        MirOperationKind::UDiv { lhs, rhs, ty }
        | MirOperationKind::SDiv { lhs, rhs, ty }
        | MirOperationKind::URem { lhs, rhs, ty }
        | MirOperationKind::SRem { lhs, rhs, ty }
        | MirOperationKind::RotateLeft { lhs, rhs, ty }
        | MirOperationKind::RotateRight { lhs, rhs, ty } => {
            if is_undef(lhs) || is_undef(rhs) {
                Some(MirValue::undef(ty.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Concat { parts, ty } => {
            if parts.iter().any(is_undef) {
                Some(MirValue::undef(ty.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ty,
        } => {
            if when_true == when_false {
                Some(when_true.clone())
            } else if is_undef(condition) || is_undef(when_true) || is_undef(when_false) {
                Some(MirValue::undef(ty.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Copy { value, ty } => {
            if is_undef(value) {
                Some(MirValue::undef(ty.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Extract { value, ty, .. }
        | MirOperationKind::Neg { value, ty }
        | MirOperationKind::Not { value, ty }
        | MirOperationKind::Popcount { value, ty }
        | MirOperationKind::CountLeadingZeros { value, ty }
        | MirOperationKind::CountTrailingZeros { value, ty }
        | MirOperationKind::AddressOf {
            address: value, ty, ..
        }
        | MirOperationKind::Cast { value, ty, .. } => {
            if is_undef(value) {
                Some(MirValue::undef(ty.clone()))
            } else {
                None
            }
        }
        MirOperationKind::Icmp { lhs, rhs, .. } | MirOperationKind::Fcmp { lhs, rhs, .. } => {
            if is_undef(lhs) || is_undef(rhs) {
                Some(MirValue::undef(MirType::integer(1)))
            } else {
                None
            }
        }
        MirOperationKind::Load { .. }
        | MirOperationKind::Store { .. }
        | MirOperationKind::MemoryCopy { .. }
        | MirOperationKind::Call { .. }
        | MirOperationKind::Intrinsic { .. } => None,
    }
}

fn is_undef(value: &MirValue) -> bool {
    matches!(value, MirValue::Undef { .. })
}
