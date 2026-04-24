use crate::Config;
use crate::controlflow::{Block, Function, Instruction};
use crate::lifters::llvm::{Lifter as LlvmLifter, Mode as LlvmMode};
use std::io::Error;

enum EntityRef<'a> {
    Instruction(&'a Instruction),
    Block(&'a Block<'a>),
    Function(&'a Function<'a>),
}

pub struct Llvm<'a> {
    entity: EntityRef<'a>,
    mode: Option<LlvmMode>,
}

impl<'a> Llvm<'a> {
    pub(crate) fn instruction(instruction: &'a Instruction) -> Self {
        Self {
            entity: EntityRef::Instruction(instruction),
            mode: None,
        }
    }

    pub(crate) fn block(block: &'a Block<'a>) -> Self {
        Self {
            entity: EntityRef::Block(block),
            mode: None,
        }
    }

    pub(crate) fn function(function: &'a Function<'a>) -> Self {
        Self {
            entity: EntityRef::Function(function),
            mode: None,
        }
    }

    pub fn reconstruct(mut self) -> Self {
        self.mode = Some(LlvmMode::Reconstruct);
        self
    }

    pub fn intrinsic(mut self) -> Self {
        self.mode = Some(LlvmMode::Intrinsic);
        self
    }

    pub fn semantic(mut self) -> Self {
        self.mode = Some(LlvmMode::Semantic);
        self
    }

    pub fn text(self) -> Result<String, Error> {
        let lifter = self.lift()?;
        Ok(lifter.text())
    }

    pub fn print(self) -> Result<(), Error> {
        let lifter = self.lift()?;
        lifter.print();
        Ok(())
    }

    pub fn bitcode(self) -> Result<Vec<u8>, Error> {
        let lifter = self.lift()?;
        Ok(lifter.bitcode())
    }

    pub fn object(self) -> Result<Vec<u8>, Error> {
        let lifter = self.lift()?;
        lifter.object()
    }

    pub fn lifter(self) -> Result<LlvmLifter, Error> {
        self.lift()
    }

    fn lift(self) -> Result<LlvmLifter, Error> {
        let mut config = self.config();
        if let Some(mode) = self.mode {
            config.lifters.llvm.mode = mode;
        }
        let mut lifter = LlvmLifter::new(config);
        match self.entity {
            EntityRef::Instruction(instruction) => lifter.lift_instruction(instruction)?,
            EntityRef::Block(block) => lifter.lift_block(block)?,
            EntityRef::Function(function) => lifter.lift_function(function)?,
        }
        Ok(lifter)
    }

    fn config(&self) -> Config {
        match self.entity {
            EntityRef::Instruction(instruction) => instruction.config.clone(),
            EntityRef::Block(block) => block.cfg.config.clone(),
            EntityRef::Function(function) => function.cfg.config.clone(),
        }
    }
}
