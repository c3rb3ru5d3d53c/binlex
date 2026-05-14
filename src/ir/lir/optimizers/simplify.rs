use crate::ir::lir::optimizers::{
    optimize_branches, optimize_casts, optimize_constants, optimize_identities,
    optimize_intrinsics, optimize_noops,
};
use crate::ir::lir::{Lir, LirModule};

pub fn optimize_simplify(lir: &mut Lir) {
    optimize_intrinsics(lir);
    optimize_constants(lir);
    optimize_identities(lir);
    optimize_casts(lir);
    optimize_branches(lir);
    optimize_noops(lir);
}

pub fn optimize_simplify_module(module: &mut LirModule) {
    for lir in &mut module.semantics {
        optimize_simplify(lir);
    }
}
