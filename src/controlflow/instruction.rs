// MIT License
//
// Copyright (c) [2025] [c3rb3ru5d3d53c]
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use crate::binary::Binary;
use crate::controlflow::Attributes;
use crate::controlflow::Graph;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::genetics::ChromosomeSimilarity;
use crate::Architecture;
use crate::Config;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::{collections::BTreeSet, io::Error};

/// Represents a single instruction in disassembled binary code.
///
/// This struct encapsulates metadata and properties of an instruction,
/// such as its address, type, and relationships with other instructions.
#[derive(Clone)]
pub struct Instruction {
    // The instruction architecture
    pub architecture: Architecture,
    /// The configuration
    pub config: Config,
    /// The address of the instruction in memory.
    pub address: u64,
    /// Indicates whether this instruction is part of a function prologue.
    pub is_prologue: bool,
    /// Indicates whether this instruction is the start of a basic block.
    pub is_block_start: bool,
    /// Indicates whether this instruction is the start of a function.
    pub is_function_start: bool,
    /// The raw bytes of the instruction.
    pub bytes: Vec<u8>,
    /// The signature pattern of the instruction.
    pub pattern: String,
    /// Indicates whether this instruction is a return instruction.
    pub is_return: bool,
    /// Indicates whether this instruction is a call instruction.
    pub is_call: bool,
    /// A set of functions that this instruction may belong to.
    pub functions: BTreeSet<u64>,
    /// Indicates whether this instruction is a jump instruction.
    pub is_jump: bool,
    /// Indicates whether this instruction is a conditional instruction.
    pub is_conditional: bool,
    /// Indicates whether this instruction is a trap instruction.
    pub is_trap: bool,
    /// A set of addresses this instruction may jump or branch to.
    pub to: BTreeSet<u64>,
    /// The number of edges (connections) for this instruction.
    pub edges: usize,
}

/// Represents a JSON-serializable view of an `Instruction`.
#[derive(Serialize, Deserialize, Clone)]
pub struct InstructionJson {
    /// The type of this entity, always `"instruction"`.
    #[serde(rename = "type")]
    pub type_: String,
    // The architecture of the instruction.
    pub architecture: String,
    /// The address of the instruction in memory.
    pub address: u64,
    /// Indicates whether this instruction is part of a function prologue.
    pub is_prologue: bool,
    /// Indicates whether this instruction is the start of a basic block.
    pub is_block_start: bool,
    /// Indicates whether this instruction is the start of a function.
    pub is_function_start: bool,
    /// Indicates whether this instruction is a call instruction.
    pub is_call: bool,
    /// Indicates whether this instruction is a return instruction.
    pub is_return: bool,
    /// Indicates whether this instruction is a jump instruction.
    pub is_jump: bool,
    /// Indicates whether this instruction is a trap instruction.
    pub is_trap: bool,
    /// Indicates whether this instruction is conditional.
    pub is_conditional: bool,
    /// The number of edges (connections) for this instruction.
    pub edges: usize,
    /// The raw bytes of the instruction in hexadecimal format.
    pub bytes: String,
    /// The size of the instruction in bytes.
    pub size: usize,
    /// The chromosome
    pub chromosome: ChromosomeJson,
    /// A set of functions that this instruction may belong to.
    pub functions: BTreeSet<u64>,
    /// A set of addresses for the blocks this instruction may branch to.
    pub blocks: BTreeSet<u64>,
    /// A set of addresses this instruction may jump or branch to.
    pub to: BTreeSet<u64>,
    /// The address of the next sequential instruction, if any.
    pub next: Option<u64>,
    /// Attributes
    pub attributes: Option<Value>,
}

impl InstructionJson {
    /// Converts a JSON string into a `InstructionJson` object.
    ///
    /// # Returns
    ///
    /// Returns `Ok(InstructionJson)` if the JSON is valid; otherwise, returns an `Err`.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

impl Instruction {
    /// Creates a new `Instruction` with the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address of the instruction.
    ///
    /// # Returns
    ///
    /// Returns a new `Instruction` with default values for its properties.
    #[allow(dead_code)]
    pub fn create(address: u64, architecture: Architecture, config: Config) -> Self {
        Self {
            address,
            is_prologue: false,
            is_block_start: false,
            is_function_start: false,
            bytes: Vec::<u8>::new(),
            pattern: String::new(),
            is_call: false,
            is_return: false,
            functions: BTreeSet::<u64>::new(),
            is_conditional: false,
            is_jump: false,
            to: BTreeSet::<u64>::new(),
            edges: 0,
            is_trap: false,
            architecture,
            config,
        }
    }

    /// Retrieves an `Instruction` from the control flow graph if available.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Instruction, Error>` containing the `Instruction`.
    pub fn new(address: u64, cfg: &Graph) -> Result<Instruction, Error> {
        let instruction = cfg.get_instruction(address);
        if instruction.is_none() {
            return Err(Error::other("instruction does not exist"));
        }
        Ok(instruction.unwrap())
    }

    /// Retrieves the set of addresses for the blocks this instruction may branch to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the block addresses.
    pub fn blocks(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::new();
        if !self.is_jump {
            return result;
        }
        for item in self.to.iter().copied().chain(self.next()) {
            result.insert(item);
        }
        result
    }

    /// Compares this instruction to another for similarity.
    ///
    /// # Returns
    ///
    /// Returns `Option<ChromosomeSimilarity>` representing the similarity between this instruction to another.
    pub fn compare(&self, rhs: &Instruction) -> Option<ChromosomeSimilarity> {
        self.chromosome().compare(&rhs.chromosome())
    }

    /// Retrieves the address of the next sequential instruction.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the address of the next instruction, or `None`
    /// if the current instruction is a return or trap instruction.
    pub fn next(&self) -> Option<u64> {
        if self.is_jump && !self.is_conditional {
            return None;
        }
        if self.is_return {
            return None;
        }
        if self.is_trap {
            return None;
        }
        Some(self.address + self.size() as u64)
    }

    /// Computes the size of the instruction in bytes.
    ///
    /// # Returns
    ///
    /// Returns the size of the instruction as a `usize`.
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    /// Converts the `Instruction` into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns an `InstructionJson` struct containing the properties of the instruction.
    #[allow(dead_code)]
    pub fn process(&self) -> InstructionJson {
        InstructionJson {
            type_: "instruction".to_string(),
            architecture: self.architecture.to_string(),
            address: self.address,
            is_block_start: self.is_block_start,
            bytes: Binary::to_hex(&self.bytes),
            size: self.size(),
            chromosome: self.chromosome_json(),
            is_return: self.is_return,
            is_trap: self.is_trap,
            is_call: self.is_call,
            is_jump: self.is_jump,
            is_conditional: self.is_conditional,
            is_function_start: self.is_function_start,
            is_prologue: self.is_prologue,
            edges: self.edges,
            functions: self.functions(),
            blocks: self.blocks(),
            to: self.to(),
            next: self.next(),
            attributes: None,
        }
    }

    pub fn pattern(&self) -> String {
        self.pattern.clone()
    }

    /// Retrieves the chromosome representing the instruction.
    ///
    /// # Returns
    ///
    /// Returns a `Chromosome` represnting the instruction.
    pub fn chromosome(&self) -> Chromosome {
        Chromosome::new(self.pattern.clone(), self.config.clone())
            .expect("failed to parse instruction chromosome")
    }

    /// Retrieves the chromosome representing the instruction.
    ///
    /// # Returns
    ///
    /// Returns a `ChromosomeJson` representing the instruction.
    pub fn chromosome_json(&self) -> ChromosomeJson {
        Chromosome::new(self.pattern.clone(), self.config.clone())
            .expect("failed to parse instruction chromosome")
            .process()
    }

    /// Retrieves the set of addresses this instruction may jump or branch to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the target addresses.
    pub fn to(&self) -> BTreeSet<u64> {
        self.to.clone()
    }

    /// Retrieves the set of functions this instruction may belong to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the function addresses.
    pub fn functions(&self) -> BTreeSet<u64> {
        self.functions.clone()
    }

    /// Converts the instruction into a JSON string representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
    pub fn json_with_attributes(&self, attributes: Attributes) -> Result<String, Error> {
        let raw = self.process_with_attributes(attributes);
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Processes the instruction into its JSON-serializable representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns a `BlockJson` instance containing the block's metadata and `Attributes`.
    pub fn process_with_attributes(&self, attributes: Attributes) -> InstructionJson {
        let mut result = self.process();
        result.attributes = Some(attributes.process());
        result
    }

    /// Converts the `Instruction` into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err(Error)` if serialization fails.
    #[allow(dead_code)]
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Prints the JSON representation of the `Instruction` to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }
}
