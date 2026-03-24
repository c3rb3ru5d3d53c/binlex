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

use crate::Architecture;
use crate::Config;
use crate::controlflow::Instruction;
use crate::controlflow::graph::Graph;
use crate::entropy;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use crate::hex;
use crate::imaging::{PNG, Palette, SVG};
use crate::metadata::Attributes;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<u64>,
    /// A set of addresses this block may branch or jump to.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub to: BTreeSet<u64>,
    /// The number of edges (connections) this block has.
    pub edges: usize,
    /// Indicates whether this block contains a conditional instruction.
    pub conditional: bool,
    /// The chromosome of the block in JSON format.
    pub chromosome: ChromosomeJson,
    /// The size of the block in bytes.
    pub size: usize,
    /// The raw bytes of the block in hexadecimal format.
    pub bytes: String,
    /// A map of function addresses related to this block.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub functions: BTreeMap<u64, u64>,
    // Blocks this blocks has as children.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub blocks: BTreeSet<u64>,
    /// The number of instructions in this block.
    pub number_of_instructions: usize,
    /// Instruction addresses associated with this block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instructions: Vec<u64>,
    /// The entropy of the block, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// The SHA-256 hash of the block, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The MinHash of the block, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minhash: Option<String>,
    /// The TLSH of the block, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
    /// Indicates whether the block is contiguous.
    pub contiguous: bool,
    /// Optional processor outputs attached by post-processing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processors: Option<BTreeMap<String, Value>>,
    /// Attributes
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
        let bytes = hex::decode(&self.json.bytes).expect("invalid block bytes");
        let mask = if self.json.chromosome.mask.is_empty() {
            vec![0; bytes.len()]
        } else {
            hex::decode(&self.json.chromosome.mask).expect("invalid block chromosome mask")
        };
        Chromosome::new(bytes, mask, self.config.clone()).expect("invalid chromosome")
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
    pub fn processors(&self) -> Option<BTreeMap<String, Value>> {
        self.json.processors.clone()
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
        let mut previous_instruction: Option<Instruction> = None;
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
            if address != instruction.address && instruction.is_block_start {
                terminator = previous_instruction.clone();
                break;
            }
            previous_address = Some(instruction.address + instruction.size() as u64);
            if instruction.is_jump || instruction.is_trap || instruction.is_return {
                terminator = Some(instruction.clone());
                break;
            }
            previous_instruction = Some(instruction.clone());
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
    pub fn process_base(&self) -> BlockJson {
        let bytes = self.bytes();
        let chromosome = self.chromosome();
        let size = bytes.len();
        let instructions = self.instruction_addresses();
        let functions = self.functions();
        let blocks = self.blocks();
        let entropy = if self.cfg.config.blocks.entropy.enabled {
            self.entropy()
        } else {
            None
        };
        let sha256 = if self.cfg.config.blocks.sha256.enabled {
            self.sha256().and_then(|hash| hash.hexdigest())
        } else {
            None
        };
        let minhash = if self.cfg.config.blocks.minhash.enabled {
            self.minhash().and_then(|hash| hash.hexdigest())
        } else {
            None
        };
        let tlsh = if self.cfg.config.blocks.tlsh.enabled {
            self.tlsh().and_then(|hash| hash.hexdigest())
        } else {
            None
        };

        BlockJson {
            type_: "block".to_string(),
            address: self.address,
            architecture: self.architecture().to_string(),
            next: self.next(),
            to: self.terminator.to(),
            edges: self.edges(),
            chromosome: chromosome.process(),
            conditional: self.terminator.is_conditional,
            size,
            bytes: hex::encode(&bytes),
            number_of_instructions: self.number_of_instructions(),
            instructions,
            functions,
            blocks,
            entropy,
            sha256,
            minhash,
            tlsh,
            contiguous: true,
            processors: None,
            attributes: None,
        }
    }

    pub fn process(&self) -> BlockJson {
        let mut json = self.process_base();
        if let Some(outputs) = self
            .cfg
            .processor_outputs(crate::processor::ProcessorTarget::Block, self.address)
        {
            for (processor_name, output) in &outputs {
                crate::processor::apply_output(
                    json.processors.get_or_insert_with(Default::default),
                    processor_name,
                    output,
                );
            }
        } else {
            for processor in crate::processor::enabled_processors_for_target(
                &self.cfg.config,
                crate::processor::ProcessorTarget::Block,
            ) {
                if let Some(output) = processor.process_block(self) {
                    crate::processor::apply_output(
                        json.processors.get_or_insert_with(Default::default),
                        processor.name(),
                        &output,
                    );
                }
            }
        }

        json
    }

    /// Return all processor outputs attached to this block.
    pub fn processors(&self) -> BTreeMap<String, Value> {
        self.process().processors.unwrap_or_default()
    }

    /// Return a single processor output by name or an empty object when absent.
    pub fn processor(&self, name: &str) -> Value {
        self.processors()
            .get(name)
            .cloned()
            .unwrap_or_else(|| Value::Object(Default::default()))
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

    /// Retrieves the instruction addresses associated with the block.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u64>` representing the instruction addresses associated with a block.
    pub fn instruction_addresses(&self) -> Vec<u64> {
        let mut result = Vec::<u64>::new();
        for entry in self.cfg.listing.range(self.address..) {
            let instruction = entry.value();
            result.push(instruction.address);
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
        let mut raw_bytes = Vec::new();
        let mut wildcard_mask = Vec::new();
        for entry in self
            .cfg
            .listing
            .range(self.address..self.address + self.size() as u64)
        {
            let instruction = entry.value();
            raw_bytes.extend_from_slice(&instruction.bytes);
            if instruction.chromosome_mask.len() == instruction.bytes.len() {
                wildcard_mask.extend_from_slice(&instruction.chromosome_mask);
            } else {
                wildcard_mask.extend(std::iter::repeat_n(0, instruction.bytes.len()));
            }
        }
        Chromosome::new(raw_bytes, wildcard_mask, self.cfg.config.clone())
            .expect("failed to build block chromosome")
    }

    /// Generates a signature for the block using its address range and control flow graph.
    ///
    /// # Returns
    ///
    /// Returns a `SignatureJson` representing the block's signature.
    pub fn chromosome_json(&self) -> ChromosomeJson {
        self.chromosome().process()
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

    /// Computes the entropy of the block's bytes.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if it cannot be computed.
    pub fn entropy(&self) -> Option<f64> {
        entropy::shannon(&self.bytes())
    }

    /// Computes the TLSH of the block's bytes.
    ///
    /// # Returns
    ///
    /// Returns `Some(TLSH)` containing the TLSH object, or `None` if the block size is too small.
    pub fn tlsh(&self) -> Option<TLSH<'static>> {
        Some(TLSH::from_bytes(
            self.bytes(),
            self.cfg.config.blocks.tlsh.minimum_byte_size,
        ))
    }

    /// Computes the MinHash of the block's bytes.
    ///
    /// # Returns
    ///
    /// Returns `Some(MinHash32)` containing the MinHash object, or `None` if the block's size exceeds the configured maximum.
    pub fn minhash(&self) -> Option<MinHash32<'static>> {
        let bytes = self.bytes();
        if bytes.len() > self.cfg.config.blocks.minhash.maximum_byte_size
            && self.cfg.config.blocks.minhash.maximum_byte_size_enabled
        {
            return None;
        }
        Some(MinHash32::from_bytes(
            bytes,
            self.cfg.config.blocks.minhash.number_of_hashes,
            self.cfg.config.blocks.minhash.shingle_size,
            self.cfg.config.blocks.minhash.seed,
        ))
    }

    /// Computes the SHA-256 hash of the block's bytes.
    ///
    /// # Returns
    ///
    /// Returns `Some(SHA256)` containing the hash object.
    pub fn sha256(&self) -> Option<SHA256<'static>> {
        Some(SHA256::from_bytes(self.bytes()))
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

    /// Renders the block bytes as a PNG image using default imaging settings.
    pub fn png(&self) -> PNG {
        PNG::new(&self.bytes(), Palette::Grayscale, self.cfg.config.clone())
    }

    /// Renders the block bytes as an SVG image using default imaging settings.
    pub fn svg(&self) -> SVG {
        SVG::new(&self.bytes(), Palette::Grayscale, self.cfg.config.clone())
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
