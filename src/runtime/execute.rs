use crate::config::ConfigProcessors;
use crate::processor::{JsonProcessor, ProcessorContext};
use crate::runtime::ProcessorError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
pub struct JsonProcessorRequest {
    pub config: String,
    pub data: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JsonProcessorResponse {
    pub data: String,
}

struct ProcessorConfigContext {
    processors: ConfigProcessors,
}

impl ProcessorContext for ProcessorConfigContext {
    fn processors(&self) -> &ConfigProcessors {
        &self.processors
    }
}

pub fn execute<P, C, F>(context: &C, data: Value, invoke: F) -> Result<Value, ProcessorError>
where
    P: JsonProcessor,
    C: ProcessorContext,
    F: FnOnce(P::Request) -> Result<P::Response, ProcessorError>,
{
    let request = <P as JsonProcessor>::request(context, data)?;
    let response = invoke(request)?;
    <P as JsonProcessor>::response(response)
}

pub fn execute_external<P>(
    request: JsonProcessorRequest,
) -> Result<JsonProcessorResponse, ProcessorError>
where
    P: JsonProcessor,
{
    let processors: ConfigProcessors = toml::from_str(&request.config)
        .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
    let context = ProcessorConfigContext { processors };
    let data: Value = serde_json::from_str(&request.data)
        .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
    let request = <P as JsonProcessor>::request(&context, data)?;
    let response = P::execute(request)?;
    Ok(JsonProcessorResponse {
        data: serde_json::to_string(&<P as JsonProcessor>::response(response)?)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
    })
}
