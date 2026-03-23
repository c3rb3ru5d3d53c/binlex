use crate::processor::{JsonProcessor, ProcessorContext};
use crate::runtime::ProcessorError;
use serde_json::Value;

pub fn execute<P: JsonProcessor, C: ProcessorContext>(
    context: &C,
    data: Value,
) -> Result<Value, ProcessorError> {
    crate::runtime::execute::execute::<P, C, _>(context, data, P::execute)
}
