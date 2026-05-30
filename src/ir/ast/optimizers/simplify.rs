use crate::ir::ast::{AstFunction, AstModule};

pub fn optimize_ast_function(_function: &mut AstFunction) {}

pub fn optimize_ast_module(module: &mut AstModule) {
    for function in &mut module.functions {
        optimize_ast_function(function);
    }
}
