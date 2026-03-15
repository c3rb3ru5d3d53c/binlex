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

pub trait EntityProcessor: Send + Sync {
    fn name(&self) -> &'static str;
    fn enabled_for_target(&self, config: &Config, target: ProcessorTarget) -> bool;
    fn process_block(&self, _block: &Block<'_>) -> Option<Value> {
        None
    }
    fn process_function(&self, _function: &Function<'_>) -> Option<Value> {
        None
    }
}

pub type ProcessorOutputs = Vec<(&'static str, Value)>;

#[cfg(not(target_os = "windows"))]
pub fn enabled_processors_for_target(
    config: &Config,
    target: ProcessorTarget,
) -> Vec<&'static dyn EntityProcessor> {
    available_entity_processors()
        .into_iter()
        .filter(|processor| processor.enabled_for_target(config, target))
        .collect()
}

#[cfg(target_os = "windows")]
pub fn enabled_processors_for_target(
    _config: &Config,
    _target: ProcessorTarget,
) -> Vec<&'static dyn EntityProcessor> {
    Vec::new()
}

#[cfg(not(target_os = "windows"))]
fn available_entity_processors() -> Vec<&'static dyn EntityProcessor> {
    vec![&vex::VexProcessor]
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
