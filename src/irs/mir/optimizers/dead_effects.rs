use crate::irs::mir::analysis::build_use_counts;
use crate::irs::mir::{Mir, MirAddressSpace, MirOperation, MirOperationKind, MirValue};
use std::collections::HashSet;

pub fn optimize_dead_effects(mir: &mut Mir) {
    loop {
        let uses = build_use_counts(mir);
        let mut changed = false;

        for block in mir.blocks_mut() {
            let before = block.operations.len();
            block.operations.retain(|operation| {
                let Some(result) = operation.result.as_ref() else {
                    return true;
                };
                uses.contains_key(result) || !is_dead_effect_candidate(&operation.kind)
            });
            block.operations = remove_dead_local_slot_stores(std::mem::take(&mut block.operations));
            changed |= block.operations.len() != before;
        }

        if !changed {
            break;
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LocalSlotCell {
    address_space: MirAddressSpace,
    address: MirValue,
}

fn remove_dead_local_slot_stores(operations: Vec<MirOperation>) -> Vec<MirOperation> {
    let mut live = HashSet::<LocalSlotCell>::new();
    let mut barrier = false;
    let mut kept = Vec::with_capacity(operations.len());

    for operation in operations.into_iter().rev() {
        match &operation.kind {
            MirOperationKind::Load {
                address_space,
                address,
                ..
            } if is_local_slot_space(address_space) => {
                live.insert(LocalSlotCell {
                    address_space: address_space.clone(),
                    address: address.clone(),
                });
                kept.push(operation);
            }
            MirOperationKind::Store {
                address_space,
                address,
                ..
            } if is_local_slot_space(address_space) => {
                let cell = LocalSlotCell {
                    address_space: address_space.clone(),
                    address: address.clone(),
                };
                if barrier || live.remove(&cell) {
                    kept.push(operation);
                }
            }
            MirOperationKind::Call { .. } => {
                kept.push(operation);
            }
            MirOperationKind::Intrinsic { .. } => {
                barrier = true;
                live.clear();
                kept.push(operation);
            }
            _ => kept.push(operation),
        }
    }

    kept.reverse();
    kept
}

fn is_local_slot_space(space: &MirAddressSpace) -> bool {
    matches!(
        space,
        MirAddressSpace::Local { .. }
            | MirAddressSpace::Argument { .. }
            | MirAddressSpace::Spill { .. }
            | MirAddressSpace::Incoming { .. }
            | MirAddressSpace::SavedFrame { .. }
            | MirAddressSpace::ReturnAddress { .. }
    )
}

fn is_dead_effect_candidate(kind: &MirOperationKind) -> bool {
    match kind {
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
        | MirOperationKind::Select { .. }
        | MirOperationKind::Concat { .. }
        | MirOperationKind::Extract { .. }
        | MirOperationKind::Neg { .. }
        | MirOperationKind::Not { .. }
        | MirOperationKind::Popcount { .. }
        | MirOperationKind::Load { .. }
        | MirOperationKind::Icmp { .. }
        | MirOperationKind::Fcmp { .. }
        | MirOperationKind::Cast { .. } => true,
        MirOperationKind::Intrinsic { name, .. } => name.starts_with("mir.call_clobber."),
        _ => false,
    }
}
