use crate::irs::lir::{Lir, LirEffect, LirFunction, LirModule};

pub fn optimize_noops(lir: &mut Lir) {
    lir.effects
        .retain(|effect| !matches!(effect, LirEffect::Nop));
}

pub fn optimize_noops_function(function: &mut LirFunction) {
    for block in &mut function.blocks {
        for lir in &mut block.instructions {
            optimize_noops(lir);
        }
    }
}

pub fn optimize_noops_module(module: &mut LirModule) {
    for function in &mut module.functions {
        optimize_noops_function(function);
    }
}
