use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::processor::ProcessorContext;
use crate::runtime::{Processor, ProcessorError};
use serde_json::Value;
use std::collections::BTreeMap;

pub type ProcessorOutputs = Vec<(String, Value)>;

#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct OnGraphOptions {
    #[serde(default)]
    pub instructions: bool,
    #[serde(default)]
    pub blocks: bool,
    #[serde(default)]
    pub functions: bool,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct GraphProcessorFanout {
    #[serde(default)]
    pub instructions: BTreeMap<u64, Value>,
    #[serde(default)]
    pub blocks: BTreeMap<u64, Value>,
    #[serde(default)]
    pub functions: BTreeMap<u64, Value>,
}

pub trait GraphProcessor: Processor {
    fn on_graph_options() -> OnGraphOptions {
        OnGraphOptions::default()
    }

    fn instruction_message(instruction: &Instruction) -> Option<Value> {
        serde_json::to_value(instruction.process_base()).ok()
    }

    fn block_message(block: &Block<'_>) -> Option<Value> {
        serde_json::to_value(block.process_base()).ok()
    }

    fn function_message(function: &Function<'_>) -> Option<Value> {
        serde_json::to_value(function.process_base()).ok()
    }

    fn graph_message(_: &Graph) -> Option<Value> {
        None
    }

    fn request_message<C: ProcessorContext>(
        _: &C,
        data: Value,
    ) -> Result<Self::Request, ProcessorError> {
        serde_json::from_value(data)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))
    }

    fn response_message(response: Self::Response) -> Result<Value, ProcessorError> {
        serde_json::to_value(response)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))
    }

    fn on_instruction(_: &Instruction) -> Option<Value> {
        None
    }

    fn on_block(_: &Block<'_>) -> Option<Value> {
        None
    }

    fn on_function(_: &Function<'_>) -> Option<Value> {
        None
    }

    fn on_graph(_: &Graph) -> Option<GraphProcessorFanout> {
        None
    }
}

pub fn apply_output(outputs: &mut BTreeMap<String, Value>, processor_name: &str, output: &Value) {
    outputs.insert(processor_name.to_string(), output.clone());
}
