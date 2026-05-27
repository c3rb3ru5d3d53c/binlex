use crate::ir::hir::{HirFunction, HirModule};

pub fn optimize_pointer_reads(_function: &mut HirFunction) {}

pub fn optimize_pointer_reads_module(module: &mut HirModule) {
    for function in &mut module.functions {
        optimize_pointer_reads(function);
    }
}
