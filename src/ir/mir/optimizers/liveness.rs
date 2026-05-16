use crate::ir::mir::analysis::build_use_def;
use crate::ir::mir::{Mir, MirOperationKind};

pub fn optimize_liveness(mir: &mut Mir) {
    loop {
        let uses = build_use_def(mir).uses;
        let mut changed = false;

        for block in mir.blocks_mut() {
            for operation in &mut block.operations {
                let Some(result) = operation.result.as_ref() else {
                    continue;
                };
                if uses.contains_key(result) {
                    continue;
                }
                if matches!(&operation.kind, MirOperationKind::Call { .. }) {
                    operation.result = None;
                    changed = true;
                }
            }

            let before = block.operations.len();
            block.operations.retain(|operation| {
                let Some(result) = operation.result.as_ref() else {
                    return true;
                };
                uses.contains_key(result) || !is_dead_binding_candidate(&operation.kind)
            });
            changed |= before != block.operations.len();
        }

        if !changed {
            break;
        }
    }
}

fn is_dead_binding_candidate(kind: &MirOperationKind) -> bool {
    matches!(kind, MirOperationKind::Copy { .. })
}
