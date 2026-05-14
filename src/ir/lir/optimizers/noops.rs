use crate::ir::lir::{Lir, LirEffect, LirModule};

pub fn optimize_noops(lir: &mut Lir) {
    lir.effects
        .retain(|effect| !matches!(effect, LirEffect::Nop));
}

pub fn optimize_noops_module(module: &mut LirModule) {
    for lir in &mut module.semantics {
        optimize_noops(lir);
    }
}
