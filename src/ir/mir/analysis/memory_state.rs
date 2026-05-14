use crate::ir::mir::{Mir, MirOperationKind};

#[derive(Clone, Debug, Default)]
pub struct MirMemorySummary {
    pub loads: usize,
    pub stores: usize,
}

impl MirMemorySummary {
    pub fn from_mir(mir: &Mir) -> Self {
        let mut summary = Self::default();
        for block in mir.blocks() {
            for operation in &block.operations {
                match operation.kind {
                    MirOperationKind::Load { .. } => summary.loads += 1,
                    MirOperationKind::Store { .. } => summary.stores += 1,
                    _ => {}
                }
            }
        }
        summary
    }
}
