use crate::ir::lir::optimizers::{
    optimize_branches, optimize_casts, optimize_constants, optimize_identities,
    optimize_intrinsics, optimize_noops,
};
use crate::ir::lir::{Lir, LirFunction, LirModule};

pub fn optimize(lir: &mut Lir) {
    optimize_intrinsics(lir);
    optimize_constants(lir);
    optimize_identities(lir);
    optimize_casts(lir);
    optimize_branches(lir);
    optimize_noops(lir);
}

pub fn optimize_function(function: &mut LirFunction) {
    for block in &mut function.blocks {
        for lir in &mut block.instructions {
            optimize(lir);
        }
    }
}

pub fn optimize_module(module: &mut LirModule) {
    for function in &mut module.functions {
        optimize_function(function);
    }
}
