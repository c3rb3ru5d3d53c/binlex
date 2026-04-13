use crate::Config;
use crate::controlflow::{Graph, GraphSnapshot};
use crate::processor::ProcessorTarget;
use crate::server::dto::{ProcessEntityRequest, ProcessGraphRequest, ProcessorHttpRequest};
use crate::server::error::ServerError;
use crate::server::state::AppState;
use serde_json::{Map, Value};

pub fn execute(
    config: &Config,
    request: ProcessGraphRequest,
) -> Result<GraphSnapshot, ServerError> {
    let graph = Graph::from_snapshot(request.graph, config.clone())
        .map_err(|error| ServerError::processor(error.to_string()))?;
    graph
        .process()
        .map_err(|error| ServerError::processor(error.to_string()))?;
    Ok(graph.snapshot())
}

pub fn execute_entity(
    state: &AppState,
    request: ProcessEntityRequest,
) -> Result<Value, ServerError> {
    let (target, mut value) = match request {
        ProcessEntityRequest::Function { function } => (
            ProcessorTarget::Function,
            serde_json::to_value(function)
                .map_err(|error| ServerError::processor(error.to_string()))?,
        ),
        ProcessEntityRequest::Block { block } => (
            ProcessorTarget::Block,
            serde_json::to_value(block)
                .map_err(|error| ServerError::processor(error.to_string()))?,
        ),
        ProcessEntityRequest::Instruction { instruction } => (
            ProcessorTarget::Instruction,
            serde_json::to_value(instruction)
                .map_err(|error| ServerError::processor(error.to_string()))?,
        ),
    };

    for processor in crate::processor::enabled_processors_for_target(&state.config, target) {
        let data = value.clone();
        let request = ProcessorHttpRequest {
            binlex_version: crate::VERSION.to_string(),
            requires: processor.registration.requires.to_string(),
            data,
        };
        let output = crate::server::processors::execute(state, processor.name(), request)?;
        let outputs = value
            .as_object_mut()
            .ok_or_else(|| {
                ServerError::processor("entity payload must be a JSON object".to_string())
            })?
            .entry("processors".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        let outputs = outputs.as_object_mut().ok_or_else(|| {
            ServerError::processor("entity processors field must be an object".to_string())
        })?;
        outputs.insert(processor.name().to_string(), output);
    }

    Ok(value)
}
