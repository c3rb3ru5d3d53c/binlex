use crate::controlflow::{Block, Function, Instruction};
use crate::{Architecture, Configuration};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

pub mod llvm;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum EmbeddingBackend {
    #[default]
    Default,
    Llvm,
    Vex,
}

impl EmbeddingBackend {
    fn resolve(self) -> Self {
        match self {
            Self::Default => Self::Llvm,
            backend => backend,
        }
    }
}

impl Display for EmbeddingBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Default => "default",
            Self::Llvm => "llvm",
            Self::Vex => "vex",
        };
        write!(f, "{name}")
    }
}

pub struct Embedding {
    architecture: Architecture,
    configuration: Configuration,
    backend: EmbeddingBackend,
}

impl Embedding {
    pub fn new(
        architecture: Architecture,
        mut configuration: Configuration,
        backend: Option<EmbeddingBackend>,
        dimensions: Option<usize>,
    ) -> Self {
        configuration.embeddings.llvm.dimensions = dimensions.unwrap_or(64).max(1);
        Self {
            architecture,
            configuration,
            backend: backend.unwrap_or_default().resolve(),
        }
    }

    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    pub fn configuration(&self) -> &Configuration {
        &self.configuration
    }

    pub fn backend(&self) -> EmbeddingBackend {
        self.backend
    }

    pub fn embed_instruction(&self, instruction: &Instruction) -> Option<Vec<f32>> {
        match self.backend {
            EmbeddingBackend::Llvm => {
                llvm::instruction::embed(instruction, &self.configuration).ok()
            }
            EmbeddingBackend::Vex => None,
            EmbeddingBackend::Default => unreachable!(),
        }
    }

    pub fn embed_block(&self, block: &Block<'_>) -> Option<Vec<f32>> {
        match self.backend {
            EmbeddingBackend::Llvm => llvm::block::embed(block, &self.configuration).ok(),
            EmbeddingBackend::Vex => None,
            EmbeddingBackend::Default => unreachable!(),
        }
    }

    pub fn embed_function(&self, function: &Function<'_>) -> Option<Vec<f32>> {
        match self.backend {
            EmbeddingBackend::Llvm => llvm::function::embed(function, &self.configuration).ok(),
            EmbeddingBackend::Vex => None,
            EmbeddingBackend::Default => unreachable!(),
        }
    }
}

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
