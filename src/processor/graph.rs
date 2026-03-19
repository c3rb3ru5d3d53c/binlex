use crate::controlflow::{Block, Function, Instruction};
use serde_json::Value;
use std::collections::BTreeMap;

pub type ProcessorOutputs = Vec<(&'static str, Value)>;

pub trait GraphProcessor {
    fn instruction_json(instruction: &Instruction) -> Option<Value> {
        serde_json::to_value(instruction.process()).ok()
    }

    fn block_json(block: &Block<'_>) -> Option<Value> {
        serde_json::to_value(block.process_base()).ok()
    }

    fn function_json(function: &Function<'_>) -> Option<Value> {
        serde_json::to_value(function.process_base()).ok()
    }

    fn instruction(_: &Instruction) -> Option<Value> {
        None
    }

    fn block(_: &Block<'_>) -> Option<Value> {
        None
    }

    fn function(_: &Function<'_>) -> Option<Value> {
        None
    }
}

pub fn apply_output(outputs: &mut BTreeMap<String, Value>, processor_name: &str, output: &Value) {
    outputs.insert(processor_name.to_string(), output.clone());
}
