use crate::Configuration;
use serde::{Deserialize, Serialize};
use std::io::Error;

pub mod llvm;

#[derive(Serialize, Deserialize, Clone)]
pub struct EmbeddingsJson {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llvm: Option<LlvmEmbeddingsJson>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct LlvmEmbeddingsJson {
    pub vector: Vec<f32>,
}

impl EmbeddingsJson {
    pub fn llvm(vector: Vec<f32>) -> Self {
        Self {
            llvm: Some(LlvmEmbeddingsJson { vector }),
        }
    }
}

pub fn embed_llvm_lifter(
    lifter: &crate::lifters::llvm::Lifter,
    config: &Configuration,
) -> Result<Vec<f32>, Error> {
    llvm::embed_lifter(lifter, config)
}
