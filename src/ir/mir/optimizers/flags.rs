use crate::ir::mir::analysis::build_use_def;
use crate::ir::mir::{Mir, MirOperationKind};

pub fn optimize_flags(mir: &mut Mir) {
    loop {
        let uses = build_use_def(mir).uses;
        let mut changed = false;

        for block in mir.blocks_mut() {
            let before = block.operations.len();
            block.operations.retain(|operation| {
                let Some(result) = operation.result.as_ref() else {
                    return true;
                };
                if !is_flag_name(result) {
                    return true;
                }
                !is_flag_set(&operation.kind) || uses.contains_key(result)
            });
            changed |= before != block.operations.len();
        }

        if prune_dead_flag_producers(mir) {
            changed = true;
        }

        if !changed {
            break;
        }
    }
}

fn prune_dead_flag_producers(mir: &mut Mir) -> bool {
    let uses = build_use_def(mir).uses;
    let mut changed = false;

    for block in mir.blocks_mut() {
        let before = block.operations.len();
        block.operations.retain(|operation| {
            let Some(result) = operation.result.as_ref() else {
                return true;
            };
            uses.contains_key(result) || !is_dead_flag_producer(&operation.kind)
        });
        changed |= before != block.operations.len();
    }

    changed
}

fn is_flag_name(name: &str) -> bool {
    matches!(name, "zf" | "sf" | "cf" | "of" | "pf" | "af")
}

fn is_flag_set(kind: &MirOperationKind) -> bool {
    matches!(
        kind,
        MirOperationKind::Intrinsic { name, .. } if name == "lir.set"
    )
}

fn is_dead_flag_producer(kind: &MirOperationKind) -> bool {
    matches!(
        kind,
        MirOperationKind::Add { .. }
            | MirOperationKind::Sub { .. }
            | MirOperationKind::Mul { .. }
            | MirOperationKind::And { .. }
            | MirOperationKind::Or { .. }
            | MirOperationKind::Xor { .. }
            | MirOperationKind::Shl { .. }
            | MirOperationKind::LShr { .. }
            | MirOperationKind::AShr { .. }
            | MirOperationKind::Select { .. }
            | MirOperationKind::Extract { .. }
            | MirOperationKind::Not { .. }
            | MirOperationKind::Popcount { .. }
            | MirOperationKind::Icmp { .. }
            | MirOperationKind::Cast { .. }
    )
}
