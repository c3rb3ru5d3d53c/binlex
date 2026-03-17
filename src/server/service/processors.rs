use serde_json::Value;

use crate::processors;
use crate::server::dto::ProcessorHttpRequest;
use crate::server::error::ServerError;
use crate::server::state::AppState;

pub fn execute(
    state: &AppState,
    processor_name: &str,
    request: ProcessorHttpRequest,
) -> Result<Value, ServerError> {
    if !state.processor_enabled(processor_name) {
        return Err(ServerError::Processor(format!(
            "processor {} is disabled on this server",
            processor_name
        )));
    }
    processors::http_execute(state, processor_name, request.data)
}
