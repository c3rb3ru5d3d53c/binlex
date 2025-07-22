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
use crate::controlflow::graph::Graph;
use crate::controlflow::Attributes;
use crate::controlflow::Instruction;
use crate::controlflow::InstructionJson;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::genetics::ChromosomeSimilarity;
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use crate::Architecture;
use crate::Config;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::ThreadPoolBuilder;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;
use std::io::ErrorKind;

/// Represents the JSON-serializable structure of a control flow block.
#[derive(Serialize, Deserialize, Clone)]
pub struct BlockJson {
    /// The type of this entity, always `"block"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The architecture of the block.
    pub architecture: String,
    /// The starting address of the block.
    pub address: u64,
    /// The address of the next sequential block, if any.
    pub next: Option<u64>,
    /// A set of addresses this block may branch or jump to.
    pub to: BTreeSet<u64>,
    /// The number of edges (connections) this block has.
    pub edges: usize,
    /// Indicates whether this block starts with a function prologue.
    pub prologue: bool,
    /// Indicates whether this block contains a conditional instruction.
    pub conditional: bool,
    /// The chromosome of the block in JSON format.
    pub chromosome: ChromosomeJson,
    /// The size of the block in bytes.
    pub size: usize,
    /// The raw bytes of the block in hexadecimal format.
    pub bytes: String,
    /// A map of function addresses related to this block.
    pub functions: BTreeMap<u64, u64>,
    // Blocks this blocks has as children.
    pub blocks: BTreeSet<u64>,
    /// The number of instructions in this block.
    pub number_of_instructions: usize,
    /// Instructions assocated with this block.
    pub instructions: Vec<InstructionJson>,
    /// The entropy of the block, if enabled.
    pub entropy: Option<f64>,
    /// The SHA-256 hash of the block, if enabled.
    pub sha256: Option<String>,
    /// The MinHash of the block, if enabled.
    pub minhash: Option<String>,
    /// The TLSH of the block, if enabled.
    pub tlsh: Option<String>,
    /// Indicates whether the block is contiguous.
    pub contiguous: bool,
    /// Attributes
    pub attributes: Option<Value>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct BlockJsonDeserializer {
    pub json: BlockJson,
    pub config: Config,
}

impl BlockJsonDeserializer {
    #[allow(dead_code)]
    pub fn new(string: String, config: Config) -> Result<Self, Error> {
        let json: BlockJson =
            serde_json::from_str(&string).map_err(|error| Error::other(format!("{}", error)))?;
        if json.type_ != "block" {
            return Err(Error::other("deserialized JSON is not a function type"));
        }
        Ok(Self {
            json,
            config: config.clone(),
        })
    }

    #[allow(dead_code)]
    pub fn chromosome(&self) -> Chromosome {
        Chromosome::new(self.json.chromosome.pattern.clone(), self.config.clone())
            .expect("invalid chromosome")
    }

    #[allow(dead_code)]
    pub fn compare(&self, rhs: &BlockJsonDeserializer) -> Option<ChromosomeSimilarity> {
        self.chromosome().compare(&rhs.chromosome())
    }

    #[allow(dead_code)]
    pub fn compare_many(
        &self,
        rhs_blocks: Vec<BlockJsonDeserializer>,
    ) -> Result<BTreeMap<u64, ChromosomeSimilarity>, Error> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(self.config.general.threads)
            .build()
            .map_err(|error| Error::other(format!("{}", error)))?;
        pool.install(|| {
            let result = rhs_blocks
                .par_iter()
                .filter_map(|block| self.compare(block).map(|sim| (block.address(), sim)))
                .collect();
            Ok(result)
        })
    }

    #[allow(dead_code)]
    pub fn blocks(&self) -> BTreeSet<u64> {
        self.json.blocks.clone()
    }

    #[allow(dead_code)]
    pub fn edges(&self) -> usize {
        self.json.edges
    }

    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<String> {
        self.json.tlsh.clone()
    }

    #[allow(dead_code)]
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.json.functions.clone()
    }

    #[allow(dead_code)]
    pub fn architecture(&self) -> Result<Architecture, Error> {
        match Architecture::from_string(&self.json.architecture) {
            Ok(result) => Ok(result),
            Err(error) => Err(Error::new(ErrorKind::Unsupported, format!("{}", error))),
        }
    }

    #[allow(dead_code)]
    pub fn entropy(&self) -> Option<f64> {
        self.json.entropy
    }

    #[allow(dead_code)]
    pub fn address(&self) -> u64 {
        self.json.address
    }

    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.json.size
    }

    #[allow(dead_code)]
    pub fn next(&self) -> Option<u64> {
        self.json.next
    }

    #[allow(dead_code)]
    pub fn to(&self) -> BTreeSet<u64> {
        self.json.to.clone()
    }

    #[allow(dead_code)]
    pub fn number_of_instructions(&self) -> usize {
        self.json.number_of_instructions
    }

    #[allow(dead_code)]
    pub fn minhash(&self) -> Option<String> {
        self.json.minhash.clone()
    }

    #[allow(dead_code)]
    pub fn contiguous(&self) -> bool {
        self.json.contiguous
    }
    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<String> {
        self.json.sha256.clone()
    }

    #[allow(dead_code)]
    pub fn conditional(&self) -> bool {
        self.json.conditional
    }

    #[allow(dead_code)]
    pub fn json(&self) -> Result<String, Error> {
        let result = serde_json::to_string(&self.json)?;
        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }
}

/// Represents a control flow block within a graph.
#[derive(Clone)]
pub struct Block<'block> {
    /// The starting address of the block.
    pub address: u64,
    /// The control flow graph this block belongs to.
    pub cfg: &'block Graph,
    /// The terminating instruction of the block.
    pub terminator: Instruction,
}

impl<'block> Block<'block> {
    /// Creates a new `Block` instance for the given address in the control flow graph.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address of the block.
    /// * `cfg` - A reference to the control flow graph the block belongs to.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Block)` if the block is valid and contiguous; otherwise,
    /// returns an `Err` with an appropriate error message.
    pub fn new(address: u64, cfg: &'block Graph) -> Result<Self, Error> {
        if !cfg.blocks.is_valid(address) {
            return Err(Error::other(format!(
                "Block -> 0x{:x}: is not valid",
                address
            )));
        }

        let mut terminator: Option<Instruction> = None;

        let mut previous_address: Option<u64> = None;
        for entry in cfg.listing.range(address..) {
            let instruction = entry.value();
            if let Some(prev_addr) = previous_address {
                if instruction.address != prev_addr {
                    return Err(Error::other(format!(
                        "Block -> 0x{:x}: is not contiguous",
                        address
                    )));
                }
            }
            previous_address = Some(instruction.address + instruction.size() as u64);
            if instruction.is_jump
                || instruction.is_trap
                || instruction.is_return
                || (address != instruction.address && instruction.is_block_start)
            {
                terminator = Some(instruction.clone());
                break;
            }
        }

        if terminator.is_none() {
            return Err(Error::other(format!(
                "Block -> 0x{:x}: has no end instruction",
                address
            )));
        }

        Ok(Self {
            address,
            cfg,
            terminator: terminator.unwrap(),
        })
    }

    /// Gets the address of the block.
    pub fn address(&self) -> u64 {
        self.address
    }

    #[allow(dead_code)]
    /// Get the architecture of the block.
    pub fn architecture(&self) -> Architecture {
        self.cfg.architecture
    }

    /// Prints the JSON representation of the block to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }

    /// Compares this block to another for similarity.
    ///
    /// # Returns
    ///
    /// Returns `Option<ChromosomeSimilarity>` representing the similarity between this block to another.
    pub fn compare(&self, rhs: &Block) -> Option<ChromosomeSimilarity> {
        self.chromosome().compare(&rhs.chromosome())
    }

    /// Compares this block to many other blocks for similarity.
    ///
    /// # Returns
    ///
    /// Returns `Vec<ChromosomeSimilarity>` representing the similarity between this block to other blocks.
    pub fn compare_many(
        &self,
        rhs_blocks: Vec<Block>,
    ) -> Result<BTreeMap<u64, ChromosomeSimilarity>, Error> {
        let pool = ThreadPoolBuilder::new()
            .num_threads(self.cfg.config.general.threads)
            .build()
            .map_err(|error| Error::other(format!("{}", error)))?;
        pool.install(|| {
            let result = rhs_blocks
                .par_iter()
                .filter_map(|block| self.compare(block).map(|sim| (block.address(), sim)))
                .collect();
            Ok(result)
        })
    }

    /// Converts the block into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Converts the block into a JSON string representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
    pub fn json_with_attributes(&self, attributes: Attributes) -> Result<String, Error> {
        let raw = self.process_with_attributes(attributes);
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Processes the block into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns a `BlockJson` instance containing the block's metadata and related information.
    pub fn process(&self) -> BlockJson {
        BlockJson {
            type_: "block".to_string(),
            address: self.address,
            architecture: self.architecture().to_string(),
            next: self.next(),
            to: self.terminator.to(),
            edges: self.edges(),
            chromosome: self.chromosome_json(),
            prologue: self.prologue(),
            conditional: self.terminator.is_conditional,
            size: self.size(),
            bytes: Binary::to_hex(&self.bytes()),
            number_of_instructions: self.number_of_instructions(),
            instructions: self.instructions_json(),
            functions: self.functions(),
            blocks: self.blocks(),
            entropy: self.entropy(),
            sha256: self.sha256(),
            minhash: self.minhash(),
            tlsh: self.tlsh(),
            contiguous: true,
            attributes: None,
        }
    }

    /// Blocks are contiguous.
    pub fn contiguous(&self) -> bool {
        true
    }

    /// Retrives the instructions associated with the block.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<Instruction>` representing the instructions associated with a block.
    pub fn instructions(&self) -> Vec<Instruction> {
        let mut result = Vec::<Instruction>::new();
        for entry in self.cfg.listing.range(self.address..) {
            let address = *entry.key();
            let instruction =
                Instruction::new(*entry.key(), self.cfg).expect("failed to retrieve instruction");
            result.push(instruction);
            if address >= self.terminator.address {
                break;
            }
        }
        result
    }

    /// Retrives the instructions associated with the block.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<InstructionJson>` representing the instructions associated with a block.
    pub fn instructions_json(&self) -> Vec<InstructionJson> {
        let mut result = Vec::<InstructionJson>::new();
        if !self.cfg.config.blocks.instructions.enabled {
            return result;
        }
        for entry in self.cfg.listing.range(self.address..) {
            let instruction = entry.value();
            result.push(instruction.process());
            if instruction.address >= self.terminator.address {
                break;
            }
        }
        result
    }

    /// Processes the block into its JSON-serializable representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns a `BlockJson` instance containing the block's metadata and `Attributes`.
    pub fn process_with_attributes(&self, attributes: Attributes) -> BlockJson {
        let mut result = self.process();
        result.attributes = Some(attributes.process());
        result
    }

    /// Determines whether the block starts with a function prologue.
    ///
    /// # Returns
    ///
    /// Returns `true` if the block starts with a prologue; otherwise, `false`.
    pub fn prologue(&self) -> bool {
        if let Some(entry) = self.cfg.listing.get(&self.address) {
            return entry.value().is_prologue;
        }
        false
    }

    /// Retrieves the number of edges (connections) this block has.
    ///
    /// # Returns
    ///
    /// Returns the number of edges as a `usize`.
    pub fn edges(&self) -> usize {
        self.terminator.edges
    }

    /// Retrieves the address of the next sequential block, if any.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the address of the next block if it is
    /// conditional or has specific ending conditions. Returns `None` otherwise.
    pub fn next(&self) -> Option<u64> {
        if !self.terminator.is_conditional {
            return None;
        }
        if self.terminator.address == self.address {
            return None;
        }
        if self.terminator.is_block_start {
            return Some(self.terminator.address);
        }
        if self.terminator.is_return {
            return None;
        }
        if self.terminator.is_trap {
            return None;
        }
        if self.terminator.is_block_start {
            return Some(self.terminator.address);
        }
        self.terminator.next()
    }

    /// Retrieves the set of addresses this block may jump or branch to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the target addresses.
    pub fn to(&self) -> BTreeSet<u64> {
        self.terminator.to()
    }

    pub fn blocks(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::new();
        for item in self.to().iter().copied().chain(self.next()) {
            result.insert(item);
        }
        result
    }

    /// Retrieves a chromosome representing this block.
    ///
    /// # Returns
    ///
    /// Returns a `Chromosome` representing this block.
    pub fn chromosome(&self) -> Chromosome {
        Chromosome::new(self.pattern(), self.cfg.config.clone())
            .expect("failed to parse block chromosome")
    }

    /// Generates a signature for the block using its address range and control flow graph.
    ///
    /// # Returns
    ///
    /// Returns a `SignatureJson` representing the block's signature.
    pub fn chromosome_json(&self) -> ChromosomeJson {
        Chromosome::new(self.pattern(), self.cfg.config.clone())
            .unwrap()
            .process()
    }

    /// Retrieves the pattern string representation of the chromosome.
    ///
    /// # Returns
    ///
    /// Returns a `Option<String>` containing the pattern representation of the chromosome.
    pub fn pattern(&self) -> String {
        let mut result = String::new();
        for entry in self
            .cfg
            .listing
            .range(self.address..self.address + self.size() as u64)
        {
            let instruction = entry.value();
            result += instruction.pattern.as_str();
        }
        result
    }

    /// Retrieves the function addresses associated with this block.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeMap<u64, u64>` where each key is an instruction address
    /// and each value is the address of the function containing that instruction.
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        for entry in self.cfg.listing.range(self.address..self.end()) {
            let instruction = entry.value();
            for function_address in instruction.functions.clone() {
                result.insert(instruction.address, function_address);
            }
        }
        result
    }

    /// Computes the entropy of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if entropy calculation is disabled.
    pub fn entropy(&self) -> Option<f64> {
        if !self.cfg.config.blocks.heuristics.entropy.enabled {
            return None;
        }
        Binary::entropy(&self.bytes())
    }

    /// Computes the TLSH of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the TLSH, or `None` if TLSH is disabled or the block size is too small.
    pub fn tlsh(&self) -> Option<String> {
        if !self.cfg.config.blocks.hashing.tlsh.enabled {
            return None;
        }
        TLSH::new(
            &self.bytes(),
            self.cfg.config.blocks.hashing.tlsh.minimum_byte_size,
        )
        .hexdigest()
    }

    /// Computes the MinHash of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the MinHash, or `None` if MinHash is disabled or the block's size exceeds the configured maximum.
    pub fn minhash(&self) -> Option<String> {
        if !self.cfg.config.blocks.hashing.minhash.enabled {
            return None;
        }
        if self.bytes().len() > self.cfg.config.blocks.hashing.minhash.maximum_byte_size
            && self
                .cfg
                .config
                .blocks
                .hashing
                .minhash
                .maximum_byte_size_enabled
        {
            return None;
        }
        MinHash32::new(
            &self.bytes(),
            self.cfg.config.blocks.hashing.minhash.number_of_hashes,
            self.cfg.config.blocks.hashing.minhash.shingle_size,
            self.cfg.config.blocks.hashing.minhash.seed,
        )
        .hexdigest()
    }

    /// Computes the SHA-256 hash of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hash, or `None` if SHA-256 is disabled.
    pub fn sha256(&self) -> Option<String> {
        if !self.cfg.config.blocks.hashing.sha256.enabled {
            return None;
        }
        SHA256::new(&self.bytes()).hexdigest()
    }

    /// Retrieves the size of the block in bytes.
    ///
    /// # Returns
    ///
    /// Returns the size as a `usize`.
    pub fn size(&self) -> usize {
        (self.end() - self.address) as usize
    }

    /// Retrieves the raw bytes of the block.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u8>` containing the bytes of the block.
    pub fn bytes(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        for entry in self.cfg.listing.range(self.address..self.end()) {
            let instruction = entry.value();
            result.extend(instruction.bytes.clone());
        }
        result
    }

    /// Counts the number of instructions in the block.
    ///
    /// # Returns
    ///
    /// Returns the number of instructions as a `usize`.
    pub fn number_of_instructions(&self) -> usize {
        let mut result: usize = 0;
        for _ in self
            .cfg
            .listing
            .range(self.address..=self.terminator.address)
        {
            result += 1;
        }
        result
    }

    /// Retrieves the address of the block's last instruction.
    ///
    /// # Returns
    ///
    /// Returns the address as a `u64`.
    #[allow(dead_code)]
    pub fn end(&self) -> u64 {
        if self.terminator.is_jump {
            return self.terminator.address + self.terminator.size() as u64;
        }
        if self.address == self.terminator.address {
            return self.terminator.address + self.terminator.size() as u64;
        }
        if self.terminator.is_block_start {
            return self.terminator.address;
        }
        if self.terminator.is_return {
            return self.terminator.address + self.terminator.size() as u64;
        }
        if let Some(next) = self.next() {
            return next;
        }
        self.terminator.address
    }
}
