use crate::Configuration;
use crate::ir::lir::{LirBlock, LirFunction, LirModule};
use crate::ir::vex::Lifter;
use std::io::Error;

pub fn from_lir_block(name: Option<String>, lir: &LirBlock) -> Result<Lifter, Error> {
    let function_name = name.or_else(|| lir.name.clone());
    let function = LirFunction {
        name: function_name,
        abi: None,
        blocks: vec![lir.clone()],
    };
    from_lir_function(function.name.clone(), &function)
}

pub fn from_lir_function(name: Option<String>, lir: &LirFunction) -> Result<Lifter, Error> {
    let module_name = name.or_else(|| lir.name.clone());
    let module = LirModule {
        name: module_name,
        functions: vec![LirFunction {
            name: lir.name.clone(),
            abi: lir.abi.clone(),
            blocks: lir.blocks.clone(),
        }],
        data: Vec::new(),
    };
    from_lir_module(module.name.clone(), &module)
}

pub fn from_lir_module(name: Option<String>, lir: &LirModule) -> Result<Lifter, Error> {
    let rendered = crate::ir::vex::lifter::render_lir_module(name.as_deref(), lir);
    Ok(Lifter::from_rendered_override(
        Configuration::default(),
        rendered,
    ))
}
