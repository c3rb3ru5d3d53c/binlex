use crate::controlflow::{Block, Function, Instruction};
use crate::io::Stderr;
use serde::{Deserialize, Serialize};

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

pub struct InstructionEmbeddings<'a> {
    instruction: &'a Instruction,
}

pub struct BlockEmbeddings<'a, 'b> {
    block: &'a Block<'b>,
}

pub struct FunctionEmbeddings<'a, 'b> {
    function: &'a Function<'b>,
}

impl<'a> InstructionEmbeddings<'a> {
    pub(crate) fn new(instruction: &'a Instruction) -> Self {
        Self { instruction }
    }

    pub fn llvm(&self) -> Option<Vec<f32>> {
        if !self.instruction.config.instructions.embeddings.llvm.enabled {
            return None;
        }
        match llvm::instruction::embed(self.instruction) {
            Ok(vector) => Some(vector),
            Err(error) => {
                Stderr::print_debug(
                    &self.instruction.config,
                    format!(
                        "llvm instruction embedding skipped address=0x{:x} error={}",
                        self.instruction.address(),
                        error
                    ),
                );
                None
            }
        }
    }
}

impl<'a, 'b> BlockEmbeddings<'a, 'b> {
    pub(crate) fn new(block: &'a Block<'b>) -> Self {
        Self { block }
    }

    pub fn llvm(&self) -> Option<Vec<f32>> {
        if !self.block.cfg.config.blocks.embeddings.llvm.enabled {
            return None;
        }
        match llvm::block::embed(self.block) {
            Ok(vector) => Some(vector),
            Err(error) => {
                Stderr::print_debug(
                    &self.block.cfg.config,
                    format!(
                        "llvm block embedding skipped address=0x{:x} error={}",
                        self.block.address(),
                        error
                    ),
                );
                None
            }
        }
    }
}

impl<'a, 'b> FunctionEmbeddings<'a, 'b> {
    pub(crate) fn new(function: &'a Function<'b>) -> Self {
        Self { function }
    }

    pub fn llvm(&self) -> Option<Vec<f32>> {
        if !self.function.cfg.config.functions.embeddings.llvm.enabled {
            return None;
        }
        match llvm::function::embed(self.function) {
            Ok(vector) => Some(vector),
            Err(error) => {
                Stderr::print_debug(
                    &self.function.cfg.config,
                    format!(
                        "llvm function embedding skipped address=0x{:x} error={}",
                        self.function.address(),
                        error
                    ),
                );
                None
            }
        }
    }
}

impl Instruction {
    pub fn embeddings(&self) -> InstructionEmbeddings<'_> {
        InstructionEmbeddings::new(self)
    }
}

impl<'a> Block<'a> {
    pub fn embeddings(&self) -> BlockEmbeddings<'_, 'a> {
        BlockEmbeddings::new(self)
    }
}

impl<'a> Function<'a> {
    pub fn embeddings(&self) -> FunctionEmbeddings<'_, 'a> {
        FunctionEmbeddings::new(self)
    }
}
