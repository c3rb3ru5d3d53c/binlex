#[cfg(not(target_os = "windows"))]
pub mod vex;

use crate::Config;
use crate::controlflow::{Block, Function};
use crate::processing::processor::ProcessorDispatch;
use clap::ValueEnum;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, ValueEnum)]
pub enum ProcessorSelection {
    Vex,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProcessorTarget {
    Instruction,
    Block,
    Function,
}

pub type ProcessorOutputs = Vec<(&'static str, Value)>;

#[cfg(not(target_os = "windows"))]
pub fn enabled_processors_for_target(
    config: &Config,
    target: ProcessorTarget,
) -> Vec<&'static str> {
    let mut processors = Vec::new();
    if config.processors.enabled
        && config.processors.vex.enabled
        && match target {
            ProcessorTarget::Instruction => config.processors.vex.instructions.enabled,
            ProcessorTarget::Block => config.processors.vex.blocks.enabled,
            ProcessorTarget::Function => config.processors.vex.functions.enabled,
        }
    {
        processors.push("vex");
    }
    processors
}

#[cfg(target_os = "windows")]
pub fn enabled_processors_for_target(
    _config: &Config,
    _target: ProcessorTarget,
) -> Vec<&'static str> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
pub fn process_block(block: &Block<'_>, processor_name: &str) -> Option<Value> {
    match processor_name {
        "vex" => vex::process_block(block),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
pub fn process_block(_block: &Block<'_>, _processor_name: &str) -> Option<Value> {
    None
}

#[cfg(not(target_os = "windows"))]
pub fn process_function(function: &Function<'_>, processor_name: &str) -> Option<Value> {
    match processor_name {
        "vex" => vex::process_function(function),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
pub fn process_function(_function: &Function<'_>, _processor_name: &str) -> Option<Value> {
    None
}

pub fn apply_output(outputs: &mut BTreeMap<String, Value>, processor_name: &str, output: &Value) {
    outputs.insert(processor_name.to_string(), output.clone());
}

#[cfg(not(target_os = "windows"))]
pub fn dispatch_by_name(name: &str) -> Option<Box<dyn ProcessorDispatch>> {
    match name {
        "vex" => Some(Box::new(vex::VexProcessor)),
        _ => None,
    }
}

#[cfg(target_os = "windows")]
pub fn dispatch_by_name(_name: &str) -> Option<Box<dyn ProcessorDispatch>> {
    None
}
