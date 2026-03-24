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
use crate::controlflow::Block;
use crate::controlflow::Graph;
use crate::controlflow::GraphQueue;
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
use std::io::Error;

/// Represents a JSON-serializable structure containing metadata about a function.
#[derive(Serialize, Deserialize, Clone)]
pub struct FunctionJson {
    /// The type of this entity, typically `"function"`.
    #[serde(rename = "type")]
    pub type_: String,
    /// The architecture of the function.
    pub architecture: String,
    /// The starting address of the function.
    pub address: u64,
    /// The number of edges (connections) in the function.
    pub edges: usize,
    /// The chromosome of the function in JSON format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chromosome: Option<ChromosomeJson>,
    /// The size of the function in bytes, if available.
    pub size: usize,
    /// The raw bytes of the function in hexadecimal format, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
    /// A map of functions associated with the function.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub functions: BTreeMap<u64, u64>,
    /// The set of block addresses contained within the function.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<u64>,
    /// The number of instructions in the function.
    pub number_of_instructions: usize,
    /// Number of blocks
    pub number_of_blocks: usize,
    /// The cyclomatic complexity of the function.
    pub cyclomatic_complexity: usize,
    /// Average Instructions per Block
    pub average_instructions_per_block: f64,
    /// The entropy of the function, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// The SHA-256 hash of the function, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The MinHash of the function, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minhash: Option<String>,
    /// The TLSH of the function, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
    /// Indicates whether the function is contiguous.
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
pub struct FunctionJsonDeserializer {
    pub json: FunctionJson,
    pub config: Config,
}

impl FunctionJsonDeserializer {
    #[allow(dead_code)]
    pub fn new(string: String, config: Config) -> Result<Self, Error> {
        let json: FunctionJson =
            serde_json::from_str(&string).map_err(|error| Error::other(format!("{}", error)))?;
        if json.type_ != "function" {
            return Err(Error::other("feserialized json is not a function type"));
        }
        Ok(Self {
            json,
            config: config.clone(),
        })
    }

    #[allow(dead_code)]
    pub fn address(&self) -> u64 {
        self.json.address
    }

    pub fn blocks(&self) -> Vec<u64> {
        self.json.blocks.clone()
    }

    #[allow(dead_code)]
    pub fn bytes(&self) -> Option<Vec<u8>> {
        self.json.bytes.as_ref()?;
        hex::decode(&self.json.bytes.clone().unwrap()).ok()
    }

    #[allow(dead_code)]
    pub fn average_instructions_per_block(&self) -> f64 {
        self.json.average_instructions_per_block
    }

    #[allow(dead_code)]
    pub fn cyclomatic_complexity(&self) -> usize {
        self.json.cyclomatic_complexity
    }

    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.json.size
    }

    #[allow(dead_code)]
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.json.functions.clone()
    }

    #[allow(dead_code)]
    pub fn architecture(&self) -> Result<Architecture, Error> {
        Architecture::from_string(&self.json.architecture)
    }

    #[allow(dead_code)]
    pub fn entropy(&self) -> Option<f64> {
        self.json.entropy
    }

    #[allow(dead_code)]
    pub fn sha256(&self) -> Option<String> {
        self.json.sha256.clone()
    }

    #[allow(dead_code)]
    pub fn tlsh(&self) -> Option<String> {
        self.json.tlsh.clone()
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
    pub fn edges(&self) -> usize {
        self.json.edges
    }

    #[allow(dead_code)]
    pub fn chromosome(&self) -> Option<Chromosome> {
        let chromosome = self.json.chromosome.clone();
        chromosome.as_ref()?;
        let bytes = self.bytes()?;
        let mask = if chromosome.as_ref()?.mask.is_empty() {
            vec![0; bytes.len()]
        } else {
            hex::decode(&chromosome.unwrap().mask).ok()?
        };
        Chromosome::new(bytes, mask, self.config.clone()).ok()
    }

    #[allow(dead_code)]
    pub fn number_of_blocks(&self) -> usize {
        self.json.number_of_blocks
    }

    #[allow(dead_code)]
    pub fn number_of_instructions(&self) -> usize {
        self.json.number_of_instructions
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

/// Represents a control flow function within a graph.
#[derive(Clone)]
pub struct Function<'function> {
    /// The starting address of the function.
    pub address: u64,
    /// The control flow graph this function belongs to.
    pub cfg: &'function Graph,
    /// The blocks that make up the function, mapped by their start addresses.
    pub blocks: BTreeMap<u64, Block<'function>>,
}

impl<'function> Function<'function> {
    /// Creates a new `Function` instance for the given address in the control flow graph.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address of the function.
    /// * `cfg` - A reference to the control flow graph the function belongs to.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Function)` if the function is valid; otherwise,
    /// returns an `Err` with an appropriate error message.
    pub fn new(address: u64, cfg: &'function Graph) -> Result<Self, Error> {
        if !cfg.functions.is_valid(address) {
            return Err(Error::other(format!(
                "Function -> 0x{:x}: is not valid",
                address
            )));
        }

        let mut blocks = BTreeMap::<u64, Block>::new();

        let mut queue = GraphQueue::new();

        queue.enqueue(address);

        while let Some(block_address) = queue.dequeue() {
            queue.insert_processed(block_address);
            if cfg.blocks.is_invalid(block_address) {
                return Err(Error::other(format!(
                    "Function -> 0x{:x} -> Block -> 0x{:x}: is invalid",
                    address, block_address
                )));
            }
            if let Ok(block) = Block::new(block_address, cfg) {
                queue.enqueue_extend(block.blocks());
                blocks.insert(block_address, block);
            }
        }

        Ok(Self {
            address,
            cfg,
            blocks,
        })
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    #[allow(dead_code)]
    pub fn architecture(&self) -> Architecture {
        self.cfg.architecture
    }

    /// Calculates the average instructions per block in the function.
    ///
    /// # Returns
    ///
    /// Returns a `usize` representing the average instrucitons per block.
    pub fn average_instructions_per_block(&self) -> f64 {
        self.number_of_instructions() as f64 / self.blocks.len() as f64
    }

    /// Calculates the cyclomatic complexity of the function.
    ///
    /// # Returns
    ///
    /// Returns a `usize` representing the cyclomatic complexity.
    pub fn cyclomatic_complexity(&self) -> usize {
        let nodes = self.blocks.len();
        let edges = self.edges();
        let components = 1;
        if edges < nodes {
            return 0;
        }
        edges - nodes + 2 * components
    }

    /// Processes the function into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns a `FunctionJson` struct containing metadata about the function.
    pub fn process_base(&self) -> FunctionJson {
        let contiguous = self.contiguous();
        let size = self.size();
        let bytes = if contiguous { self.bytes() } else { None };
        let bytes_hex = bytes.as_ref().map(|bytes| hex::encode(bytes));
        let chromosome = if contiguous {
            self.chromosome().map(|chromosome| chromosome.process())
        } else {
            None
        };
        let entropy = if self.cfg.config.functions.entropy.enabled {
            self.entropy()
        } else {
            None
        };
        let sha256 = if self.cfg.config.functions.sha256.enabled {
            self.sha256().and_then(|hash| hash.hexdigest())
        } else {
            None
        };
        let tlsh = if self.cfg.config.functions.tlsh.enabled {
            self.tlsh().and_then(|hash| hash.hexdigest())
        } else {
            None
        };
        let minhash = if self.cfg.config.functions.minhash.enabled {
            self.minhash().and_then(|hash| hash.hexdigest())
        } else {
            None
        };

        FunctionJson {
            address: self.address,
            type_: "function".to_string(),
            edges: self.edges(),
            chromosome,
            bytes: bytes_hex,
            size,
            functions: self.functions(),
            blocks: self.block_addresses(),
            number_of_blocks: self.number_of_blocks(),
            number_of_instructions: self.number_of_instructions(),
            cyclomatic_complexity: self.cyclomatic_complexity(),
            average_instructions_per_block: self.average_instructions_per_block(),
            entropy,
            sha256,
            minhash,
            tlsh,
            contiguous,
            processors: None,
            architecture: self.architecture().to_string(),
            attributes: None,
        }
    }

    pub fn process(&self) -> FunctionJson {
        let mut json = self.process_base();
        if let Some(outputs) = self
            .cfg
            .processor_outputs(crate::processor::ProcessorTarget::Function, self.address)
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
                crate::processor::ProcessorTarget::Function,
            ) {
                if let Some(output) = processor.process_function(self) {
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

    /// Return all processor outputs attached to this function.
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

    /// Retrives the number of blocks in the function.
    ///
    /// # Returns
    ///
    /// Returns `usize` representing the number of blocks in the function.
    pub fn number_of_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Processes the function into its JSON-serializable representation including `Attributes`
    ///
    /// # Returns
    ///
    /// Returns a `FunctionJson` instance containing the function's metadata and `Attributes`.
    pub fn process_with_attributes(&self, attributes: Attributes) -> FunctionJson {
        let mut result = self.process();
        result.attributes = Some(attributes.process());
        result
    }

    /// Prints the JSON representation of the function to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }

    /// Converts the function metadata into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Converts the function metadata into a JSON string representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
    pub fn json_with_attributes(&self, attributes: Attributes) -> Result<String, Error> {
        let raw = self.process_with_attributes(attributes);
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Generates the function's chromosome if the function is contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(Chromosome)` if the function is contiguous; otherwise, `None`.
    pub fn chromosome(&self) -> Option<Chromosome> {
        if !self.contiguous() {
            return None;
        }
        let bytes = self.bytes()?;
        let end = self.end()?;
        let mut wildcard_mask = Vec::with_capacity(bytes.len());
        for entry in self.cfg.listing.range(self.address..end) {
            let instruction = entry.value();
            if instruction.chromosome_mask.len() == instruction.bytes.len() {
                wildcard_mask.extend_from_slice(&instruction.chromosome_mask);
            } else {
                wildcard_mask.extend(std::iter::repeat_n(0, instruction.bytes.len()));
            }
        }
        Chromosome::new(bytes, wildcard_mask, self.cfg.config.clone()).ok()
    }

    /// Generates the function's chromosome JSON if the function is contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(ChromosomeJson)` if the function is contiguous; otherwise, `None`.
    pub fn chromosome_json(&self) -> Option<ChromosomeJson> {
        if !self.contiguous() {
            return None;
        }
        Some(self.chromosome()?.process())
    }

    /// Retrieves the pattern string representation of the chromosome.
    ///
    /// # Returns
    ///
    /// Returns a `Option<String>` containing the pattern representation of the chromosome.
    pub fn pattern(&self) -> Option<String> {
        if !self.contiguous() {
            return None;
        }
        let mut result = String::new();
        for entry in self
            .cfg
            .listing
            .range(self.address..self.address + self.size() as u64)
        {
            let instruction = entry.value();
            result += instruction.pattern.as_str();
        }
        Some(result)
    }

    /// Retrieves the total number of instructions in the function.
    ///
    /// # Returns
    ///
    /// Returns the number of instructions as a `usize`.
    pub fn number_of_instructions(&self) -> usize {
        self.blocks
            .values()
            .map(|block| block.number_of_instructions())
            .sum()
    }

    /// Indicates whether this function starts with a prologue.
    ///
    /// # Returns
    ///
    /// Returns `true` if the function starts with a prologue; otherwise, `false`.
    pub fn prologue(&self) -> bool {
        if let Some((_, block)) = self.blocks.iter().next() {
            return block.prologue();
        }
        false
    }

    /// Retrieves the blocks associated with this function.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<Block>` representing the blocks associated with this function.
    pub fn blocks(&self) -> Vec<Block<'_>> {
        self.blocks
            .keys()
            .filter_map(|&block_address| Block::new(block_address, self.cfg).ok())
            .collect()
    }

    /// Retrieves the blocks associated with this function.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<u64>` representing the block addresses associated with this function.
    pub fn block_addresses(&self) -> Vec<u64> {
        let mut result = Vec::<u64>::new();
        result.extend(self.blocks.keys().copied());
        result
    }

    /// Retrieves the number of edges (connections) in the function.
    ///
    /// # Returns
    ///
    /// Returns the number of edges as a `usize`.
    pub fn edges(&self) -> usize {
        self.blocks.values().map(|block| block.edges()).sum()
    }

    /// Retrieves the size of the function in bytes, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(usize)` if the function is contiguous; otherwise, `None`.
    pub fn size(&self) -> usize {
        if self.blocks.is_empty() {
            return 0;
        }
        let end = self
            .blocks
            .values()
            .map(|b| b.address + b.size() as u64)
            .max()
            .unwrap_or(self.address);
        (end - self.address) as usize
    }

    /// Retrieves the address of the function's last instruction, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the address, or `None` if the function is not contiguous.
    pub fn end(&self) -> Option<u64> {
        if !self.contiguous() {
            return None;
        }
        if let Some((_, block)) = self.blocks.iter().last() {
            return Some(block.end());
        }
        None
    }

    /// Retrieves the raw bytes of the function, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(Vec<u8>)` containing the bytes, or `None` if the function is not contiguous.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        if self.blocks.is_empty() {
            return None;
        }
        let end = self
            .blocks
            .values()
            .map(|b| b.address + b.size() as u64)
            .max()
            .unwrap_or(self.address);
        let mut bytes = Vec::<u8>::new();
        let mut pc = self.address;
        while pc < end {
            let instruction = match self.cfg.get_instruction(pc) {
                Some(i) => i,
                None => return None,
            };
            bytes.extend(&instruction.bytes);
            pc += instruction.size() as u64;
        }
        Some(bytes)
    }

    /// Renders the function bytes as a PNG image using default imaging settings.
    pub fn png(&self) -> Option<PNG> {
        self.bytes()
            .map(|bytes| PNG::new(&bytes, Palette::Grayscale, self.cfg.config.clone()))
    }

    /// Renders the function bytes as an SVG image using default imaging settings.
    pub fn svg(&self) -> Option<SVG> {
        self.bytes()
            .map(|bytes| SVG::new(&bytes, Palette::Grayscale, self.cfg.config.clone()))
    }

    /// Computes the SHA-256 hash of the function's bytes, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(SHA256)` containing the hash object, or `None` if the function is not contiguous.
    pub fn sha256(&self) -> Option<SHA256<'static>> {
        if !self.contiguous() {
            return None;
        }
        self.bytes().map(SHA256::from_bytes)
    }

    /// Computes the entropy of the function's bytes.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if it cannot be computed.
    pub fn entropy(&self) -> Option<f64> {
        if self.contiguous() {
            return self.bytes().and_then(|bytes| entropy::shannon(&bytes));
        }

        let entropi: Vec<f64> = self
            .blocks
            .values()
            .filter_map(|block| block.entropy())
            .collect();

        if entropi.is_empty() {
            Some(0.0)
        } else {
            Some(entropi.iter().sum::<f64>() / entropi.len() as f64)
        }
    }

    /// Computes the TLSH of the function's bytes, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(TLSH)` containing the TLSH object, or `None` if the function is not contiguous.
    pub fn tlsh(&self) -> Option<TLSH<'static>> {
        if !self.contiguous() {
            return None;
        }
        self.bytes()
            .map(|bytes| TLSH::from_bytes(bytes, self.cfg.config.functions.tlsh.minimum_byte_size))
    }

    /// Computes the MinHash of the function's bytes, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(MinHash32)` containing the MinHash object, or `None` if the function is not contiguous.
    pub fn minhash(&self) -> Option<MinHash32<'static>> {
        if !self.contiguous() {
            return None;
        }
        if let Some(bytes) = self.bytes() {
            if bytes.len() > self.cfg.config.functions.minhash.maximum_byte_size
                && self.cfg.config.functions.minhash.maximum_byte_size_enabled
            {
                return None;
            }
            return Some(MinHash32::from_bytes(
                bytes,
                self.cfg.config.functions.minhash.number_of_hashes,
                self.cfg.config.functions.minhash.shingle_size,
                self.cfg.config.functions.minhash.seed,
            ));
        }
        None
    }

    /// Retrieves the functions associated with this function.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeMap<u64, u64>` containing function addresses.
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.blocks
            .values()
            .flat_map(|block| block.functions())
            .collect()
    }

    /// Checks whether the function is contiguous in memory.
    ///
    /// # Returns
    ///
    /// Returns `true` if the function is contiguous; otherwise, `false`.
    pub fn contiguous(&self) -> bool {
        if self.blocks.is_empty() {
            return false;
        }
        let end = self
            .blocks
            .values()
            .map(|b| b.address + b.size() as u64)
            .max()
            .unwrap_or(self.address);
        let mut pc = self.address;
        while pc < end {
            match self.cfg.get_instruction(pc) {
                Some(instr) => pc += instr.size() as u64,
                None => return false,
            }
        }
        true
    }
}
