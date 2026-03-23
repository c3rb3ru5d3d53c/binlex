use crate::processor::{JsonProcessor, ProcessorContext};
use crate::runtime::ProcessorError;
use serde_json::Value;

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
