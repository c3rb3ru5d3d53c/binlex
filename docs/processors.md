# Custom Processors

Minimal skeleton for adding a custom processor.

## Example Skeleton

```rust
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::controlflow::{Block, Function, Instruction};
use crate::core::{Architecture, OperatingSystem, Transport};
use crate::processor::{GraphProcessor, JsonProcessor, ProcessorContext};
use crate::runtime::{Processor, ProcessorError};

#[derive(Serialize, Deserialize, Clone)]
pub enum ExampleRequest {
    Analyze { bytes: Vec<u8> },
}

#[derive(Serialize, Deserialize, Clone)]
pub enum ExampleResponse {
    Analyze { score: u32 },
}

#[derive(Default)]
pub struct ExampleProcessor;

impl Processor for ExampleProcessor {
    const NAME: &'static str = "example";
    type Request = ExampleRequest;
    type Response = ExampleResponse;

    fn request(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        match request {
            ExampleRequest::Analyze { bytes } => {
                Ok(ExampleResponse::Analyze { score: bytes.len() as u32 })
            }
        }
    }
}

impl JsonProcessor for ExampleProcessor {
    fn request<C: ProcessorContext>(_: &C, data: Value) -> Result<Self::Request, ProcessorError> {
        let bytes = serde_json::to_vec(&data)
            .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
        Ok(ExampleRequest::Analyze { bytes })
    }

    fn response(response: Self::Response) -> Result<Value, ProcessorError> {
        match response {
            ExampleResponse::Analyze { score } => Ok(json!({ "score": score })),
        }
    }
}

impl GraphProcessor for ExampleProcessor {
    fn instruction(instruction: &Instruction) -> Option<Value> {
        Some(json!({
            "address": instruction.address,
            "size": instruction.bytes.len()
        }))
    }

    fn block(block: &Block<'_>) -> Option<Value> {
        Some(json!({
            "address": block.address(),
            "size": block.size()
        }))
    }

    fn function(function: &Function<'_>) -> Option<Value> {
        Some(json!({
            "address": function.address(),
            "instructions": function.number_of_instructions()
        }))
    }
}

crate::processor!(ExampleProcessor {
    requires: ">=2.0.0 <3.0.0",
    operating_systems: [OperatingSystem::LINUX, OperatingSystem::MACOS],
    architectures: [Architecture::AMD64, Architecture::I386],
    enabled: false,
    transports: [Transport::INLINE, Transport::IPC, Transport::HTTP],
    instructions: { enabled: false },
    blocks: { enabled: false },
    functions: { enabled: true },
    inline: { enabled: true },
    ipc: { enabled: true },
    http: {
        enabled: false,
        options: {
            url: "http://127.0.0.1:5000",
            verify: false
        }
    },
});
```
