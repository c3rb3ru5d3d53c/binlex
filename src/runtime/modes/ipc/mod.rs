use crate::processor::{JsonProcessor, ProcessorContext};
use crate::runtime::ProcessorError;
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
    let request = <P as JsonProcessor>::request(context, data)?;
    let response = pool.execute::<P>(&request)?;
    <P as JsonProcessor>::response(response)
}
