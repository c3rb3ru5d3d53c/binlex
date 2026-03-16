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
    processors::http_execute(state, processor_name, request.data)
}
