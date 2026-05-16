pub mod lifter;
pub mod optimizers;
pub mod prepare;
pub mod verify;

use crate::Configuration;
use crate::core::Architecture;
use crate::ir::lir::{LirBlock, LirCpu, LirFunction, LirInstruction, LirModule};
use serde::{Deserialize, Serialize};
use std::io::Error;

#[cfg(not(target_os = "windows"))]
use crate::ir::vex::VexJson;
pub use lifter::JittedFunction;
pub use lifter::Lifter;
pub use optimizers::Optimizers;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Reconstruct,
    Intrinsic,
    Lir,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LlvmJson {
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LiftersJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llvm: Option<LlvmJson>,
    #[cfg(not(target_os = "windows"))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vex: Option<VexJson>,
}

pub fn from_lir_block(name: Option<String>, lir: &LirBlock) -> Result<Lifter, Error> {
    let function_name = name.or_else(|| lir.name.clone());
    let function = LirFunction {
        name: function_name,
        abi: infer_abi_from_instructions(&lir.instructions),
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
    let cpu = infer_cpu_from_lir_module(lir)?;
    let mut lifter = Lifter::new(cpu, Configuration::default(), None)?;
    for (index, function) in lir.functions.iter().enumerate() {
        let function_name = function
            .name
            .clone()
            .or_else(|| name.clone())
            .unwrap_or_else(|| format!("function_{index}"));
        let function_module = LirModule {
            name: Some(function_name.clone()),
            functions: vec![LirFunction {
                name: Some(function_name.clone()),
                abi: function.abi.clone(),
                blocks: function.blocks.clone(),
            }],
            data: lir.data.clone(),
        };
        lifter.lift_function_semantics_named(
            &function_module,
            function.abi.as_ref(),
            &function_name,
        )?;
    }
    Ok(lifter)
}

fn infer_cpu_from_lir_module(lir: &LirModule) -> Result<LirCpu, Error> {
    lir.functions
        .iter()
        .find_map(infer_cpu_from_lir_function)
        .ok_or_else(|| Error::other("unable to infer LIR CPU for LLVM lowering"))
}

fn infer_cpu_from_lir_function(lir: &LirFunction) -> Option<LirCpu> {
    lir.abi.as_ref().map(|abi| abi.cpu.clone()).or_else(|| {
        infer_cpu_from_instructions(
            lir.blocks
                .iter()
                .flat_map(|block| block.instructions.iter()),
        )
    })
}

fn infer_abi_from_instructions(instructions: &[LirInstruction]) -> Option<crate::ir::lir::LirAbi> {
    instructions
        .iter()
        .find_map(|instruction| instruction.abi.clone())
}

fn infer_cpu_from_instructions<'a>(
    mut instructions: impl Iterator<Item = &'a LirInstruction>,
) -> Option<LirCpu> {
    instructions.find_map(|instruction| {
        instruction
            .abi
            .as_ref()
            .map(|abi| abi.cpu.clone())
            .or_else(|| {
                instruction
                    .encoding
                    .as_ref()
                    .and_then(|encoding| Architecture::from_string(&encoding.architecture).ok())
                    .and_then(|architecture| LirCpu::from_architecture(architecture).ok())
            })
    })
}
