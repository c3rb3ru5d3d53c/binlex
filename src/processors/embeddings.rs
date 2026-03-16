use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::controlflow::{Block, Function, Instruction};
use crate::processing::error::ProcessorError;
use crate::processing::processor::Processor;
use crate::processors::GraphProcessor;

const DEFAULT_DIMENSIONS: usize = 64;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbeddingsRequest {
    pub data: Value,
    #[serde(default)]
    pub dimensions: Option<usize>,
    #[serde(default)]
    pub device: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EmbeddingsResponse {
    pub vector: Vec<f32>,
    pub data: Value,
}

pub struct EmbeddingsProcessor;

fn zero_vector(dimensions: usize) -> Vec<f32> {
    vec![0.0; dimensions.max(1)]
}

fn configured_dimensions(config: &crate::Config) -> usize {
    config
        .processors
        .processor(EmbeddingsProcessor::NAME)
        .and_then(|processor| processor.option_integer("dimensions"))
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_DIMENSIONS)
}

fn process_value(config: &crate::Config) -> Value {
    json!({
        "vector": zero_vector(configured_dimensions(config)),
    })
}

impl Processor for EmbeddingsProcessor {
    const NAME: &'static str = "embeddings";
    type Request = EmbeddingsRequest;
    type Response = EmbeddingsResponse;

    fn request(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        Ok(EmbeddingsResponse {
            vector: zero_vector(request.dimensions.unwrap_or(DEFAULT_DIMENSIONS)),
            data: request.data,
        })
    }
}

impl GraphProcessor for EmbeddingsProcessor {
    fn instruction(instruction: &Instruction) -> Option<Value> {
        Some(process_value(&instruction.config))
    }

    fn block(block: &Block<'_>) -> Option<Value> {
        Some(process_value(&block.cfg.config))
    }

    fn function(function: &Function<'_>) -> Option<Value> {
        Some(process_value(&function.cfg.config))
    }
}

crate::processor!(EmbeddingsProcessor {
    os: [linux, macos],
    enabled: false,
    modes: [ipc],
    mode: ipc,
    instructions: { enabled: true },
    blocks: { enabled: true },
    functions: { enabled: true },
    options: {
        dimensions: 64,
        device: "cpu"
    },
    server: {},
});
