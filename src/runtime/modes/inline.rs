use crate::processor::{JsonProcessor, ProcessorContext};
use crate::runtime::ProcessorError;
use serde_json::Value;

pub fn execute<P: JsonProcessor, C: ProcessorContext>(
    context: &C,
    data: Value,
) -> Result<Value, ProcessorError> {
    let request = <P as JsonProcessor>::request(context, data)?;
    let response = P::execute(request)?;
    <P as JsonProcessor>::response(response)
}
