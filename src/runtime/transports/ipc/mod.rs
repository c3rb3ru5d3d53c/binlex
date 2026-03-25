use crate::processor::{JsonProcessor, ProcessorContext};
use crate::runtime::ProcessorError;
use crate::runtime::execute::JsonProcessorRequest;
use serde_json::Value;

pub mod local;
pub mod pool;
pub mod protocol;

pub use pool::ProcessorPool;

pub fn execute<P: JsonProcessor, C: ProcessorContext>(
    context: &C,
    data: Value,
) -> Result<Value, ProcessorError> {
    let pool = ProcessorPool::for_processor::<P>(context.processors())?;
    execute_with_pool::<P, C>(&pool, context, data)
}

pub fn execute_with_pool<P: JsonProcessor, C: ProcessorContext>(
    pool: &ProcessorPool,
    context: &C,
    data: Value,
) -> Result<Value, ProcessorError> {
    crate::runtime::execute::execute::<P, C, _>(context, data, |request| {
        pool.execute::<P>(&request)
    })
}

pub fn execute_external(
    processor_name: &str,
    config: &crate::config::ConfigProcessors,
    data: Value,
) -> Result<Value, ProcessorError> {
    let pool = ProcessorPool::for_external(config, processor_name)?;
    let response = pool.execute_json(&JsonProcessorRequest {
        config: toml::to_string(config)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
        data: serde_json::to_string(&data)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
    })?;
    serde_json::from_str(&response.data)
        .map_err(|error| ProcessorError::Serialization(error.to_string()))
}
