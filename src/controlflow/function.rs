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

use super::block::BlockJsonDeserializer;
use crate::binary::Binary;
use crate::controlflow::Attributes;
use crate::controlflow::Block;
use crate::controlflow::BlockJson;
use crate::controlflow::Graph;
use crate::controlflow::GraphQueue;
use crate::genetics::chromosome::ChromosomeSimilarityScore;
use crate::genetics::chromosome::HomologousChromosome;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::genetics::ChromosomeSimilarity;
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use crate::Architecture;
use crate::Config;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Error;
use std::io::ErrorKind;

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
    /// Indicates whether this function starts with a prologue.
    pub prologue: bool,
    /// The chromosome of the function in JSON format.
    pub chromosome: Option<ChromosomeJson>,
    /// Chromosome MinHash Ratio
    pub chromosome_minhash_ratio: f64,
    /// Chromosome TLSH Ratio
    pub chromosome_tlsh_ratio: f64,
    /// Minhash Ratio
    pub minhash_ratio: f64,
    /// TLSH ratio
    pub tlsh_ratio: f64,
    /// The size of the function in bytes, if available.
    pub size: usize,
    /// The raw bytes of the function in hexadecimal format, if available.
    pub bytes: Option<String>,
    /// A map of functions associated with the function.
    pub functions: BTreeMap<u64, u64>,
    /// The set of blocks contained within the function.
    pub blocks: Vec<BlockJson>,
    /// The number of instructions in the function.
    pub number_of_instructions: usize,
    /// Number of blocks
    pub number_of_blocks: usize,
    /// The cyclomatic complexity of the function.
    pub cyclomatic_complexity: usize,
    /// Average Instructions per Block
    pub average_instructions_per_block: f64,
    /// The entropy of the function, if enabled.
    pub entropy: Option<f64>,
    /// The SHA-256 hash of the function, if enabled.
    pub sha256: Option<String>,
    /// The MinHash of the function, if enabled.
    pub minhash: Option<String>,
    /// The TLSH of the function, if enabled.
    pub tlsh: Option<String>,
    /// Indicates whether the function is contiguous.
    pub contiguous: bool,
    /// Attributes
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

    pub fn blocks(&self) -> Vec<BlockJsonDeserializer> {
        let mut result = Vec::<BlockJsonDeserializer>::new();
        for block in &self.json.blocks {
            let block_json_seserializer = BlockJsonDeserializer {
                json: block.clone(),
                config: self.config.clone(),
            };
            result.push(block_json_seserializer);
        }
        result
    }

    #[allow(dead_code)]
    pub fn bytes(&self) -> Option<Vec<u8>> {
        self.json.bytes.as_ref()?;
        Binary::from_hex(&self.json.bytes.clone().unwrap()).ok()
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
    pub fn tlsh_ratio(&self) -> f64 {
        self.json.tlsh_ratio
    }

    #[allow(dead_code)]
    pub fn minhash_ratio(&self) -> f64 {
        self.json.minhash_ratio
    }

    #[allow(dead_code)]
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.json.functions.clone()
    }

    #[allow(dead_code)]
    pub fn chromosome_tlsh_ratio(&self) -> f64 {
        self.json.chromosome_tlsh_ratio
    }

    #[allow(dead_code)]
    pub fn chromosome_minhash_ratio(&self) -> f64 {
        self.json.chromosome_minhash_ratio
    }

    #[allow(dead_code)]
    pub fn prologue(&self) -> bool {
        self.json.prologue
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

    pub fn compare(
        &self,
        rhs: &FunctionJsonDeserializer,
    ) -> Result<Option<ChromosomeSimilarity>, Error> {
        if self.contiguous() && rhs.contiguous() {
            let lhs_chromosome = self.chromosome();
            let rhs_chromosome = rhs.chromosome();
            if lhs_chromosome.is_none() && rhs_chromosome.is_none() {
                return Ok(None);
            }
            return Ok(self
                .chromosome()
                .unwrap()
                .compare(&rhs.chromosome().unwrap()));
        }

        let mut minhashes = Vec::<f64>::new();
        let mut tls_values = Vec::<f64>::new();

        for lhs_block in self.blocks() {
            let mut best_minhash: Option<f64> = None;
            let mut best_tls: Option<f64> = None;

            let results = match lhs_block.compare_many(rhs.blocks()) {
                Ok(results) => results,
                Err(error) => {
                    return Err(Error::new(ErrorKind::InvalidData, format!("{}", error)));
                }
            };

            for (_, similarity) in results {
                let minhash = similarity.score().minhash();
                let tlsh = similarity.score.minhash();
                if minhash.is_none() && tlsh.is_none() {
                    continue;
                }
                if let Some(mh) = minhash {
                    best_minhash = Some(best_minhash.map_or(mh, |prev| prev.max(mh)));
                }

                if let Some(t) = tlsh {
                    best_tls = Some(best_tls.map_or(t, |prev| prev.min(t)));
                }
            }

            if let Some(mh) = best_minhash {
                minhashes.push(mh);
            }

            if let Some(t) = best_tls {
                tls_values.push(t);
            }
        }

        if !minhashes.is_empty() || !tls_values.is_empty() {
            let minhash_average = {
                let avg = minhashes.iter().sum::<f64>() / minhashes.len() as f64;
                if avg > 0.0 {
                    Some(avg)
                } else {
                    None
                }
            };

            let tlsh_average = {
                let avg = tls_values.iter().sum::<f64>() / tls_values.len() as f64;
                if avg > 0.0 {
                    Some(avg)
                } else {
                    None
                }
            };

            if minhash_average.is_none() && tlsh_average.is_none() {
                return Ok(None);
            }

            return Ok(Some(ChromosomeSimilarity {
                score: ChromosomeSimilarityScore {
                    minhash: minhash_average,
                    tlsh: tlsh_average,
                },
                homologues: Vec::<HomologousChromosome>::new(),
            }));
        }

        Ok(None)
    }

    pub fn compare_many(
        &self,
        rhs_functions: Vec<FunctionJsonDeserializer>,
    ) -> Result<BTreeMap<u64, ChromosomeSimilarity>, Error> {
        rhs_functions
            .iter()
            .filter_map(|function| match self.compare(function) {
                Ok(Some(similarity)) => Some(Ok((function.address(), similarity))),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            })
            .collect()
    }

    #[allow(dead_code)]
    pub fn edges(&self) -> usize {
        self.json.edges
    }

    #[allow(dead_code)]
    pub fn chromosome(&self) -> Option<Chromosome> {
        let chromosome = self.json.chromosome.clone();
        chromosome.as_ref()?;
        Chromosome::new(chromosome.unwrap().pattern.clone(), self.config.clone()).ok()
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
    pub fn process(&self) -> FunctionJson {
        FunctionJson {
            address: self.address,
            type_: "function".to_string(),
            edges: self.edges(),
            prologue: self.prologue(),
            chromosome: self.chromosome_json(),
            chromosome_minhash_ratio: self.chromosome_minhash_ratio(),
            chromosome_tlsh_ratio: self.chromosome_tlsh_ratio(),
            minhash_ratio: self.minhash_ratio(),
            tlsh_ratio: self.tlsh_ratio(),
            bytes: self.bytes_to_hex(),
            size: self.size(),
            functions: self.functions(),
            blocks: self.blocks_json(),
            number_of_blocks: self.number_of_blocks(),
            number_of_instructions: self.number_of_instructions(),
            cyclomatic_complexity: self.cyclomatic_complexity(),
            average_instructions_per_block: self.average_instructions_per_block(),
            entropy: self.entropy(),
            sha256: self.sha256(),
            minhash: self.minhash(),
            tlsh: self.tlsh(),
            contiguous: self.contiguous(),
            architecture: self.architecture().to_string(),
            attributes: None,
        }
    }

    /// Compares this block to another for similarity.
    ///
    /// # Returns
    ///
    /// Returns `Option<ChromosomeSimilarity>` representing the similarity between this block to another.
    pub fn compare(&self, rhs: &Function) -> Result<Option<ChromosomeSimilarity>, Error> {
        if self.contiguous() && rhs.contiguous() {
            let lhs_chromosome = self.chromosome();
            let rhs_chromosome = rhs.chromosome();
            if lhs_chromosome.is_none() && rhs_chromosome.is_none() {
                return Ok(None);
            }
            return Ok(self
                .chromosome()
                .unwrap()
                .compare(&rhs.chromosome().unwrap()));
        }

        let mut minhashes = Vec::<f64>::new();
        let mut tls_values = Vec::<f64>::new();

        for lhs_block in self.blocks() {
            let mut best_minhash: Option<f64> = None;
            let mut best_tls: Option<f64> = None;

            let results = match lhs_block.compare_many(rhs.blocks()) {
                Ok(results) => results,
                Err(error) => {
                    return Err(Error::new(ErrorKind::InvalidData, format!("{}", error)));
                }
            };

            for (_, similarity) in results {
                let minhash = similarity.score().minhash();
                let tlsh = similarity.score.minhash();
                if minhash.is_none() && tlsh.is_none() {
                    continue;
                }
                if let Some(mh) = minhash {
                    best_minhash = Some(best_minhash.map_or(mh, |prev| prev.max(mh)));
                }

                if let Some(t) = tlsh {
                    best_tls = Some(best_tls.map_or(t, |prev| prev.min(t)));
                }
            }

            if let Some(mh) = best_minhash {
                minhashes.push(mh);
            }

            if let Some(t) = best_tls {
                tls_values.push(t);
            }
        }

        if !minhashes.is_empty() || !tls_values.is_empty() {
            let minhash_average = {
                let avg = minhashes.iter().sum::<f64>() / minhashes.len() as f64;
                if avg > 0.0 {
                    Some(avg)
                } else {
                    None
                }
            };

            let tlsh_average = {
                let avg = tls_values.iter().sum::<f64>() / tls_values.len() as f64;
                if avg > 0.0 {
                    Some(avg)
                } else {
                    None
                }
            };

            if minhash_average.is_none() && tlsh_average.is_none() {
                return Ok(None);
            }

            return Ok(Some(ChromosomeSimilarity {
                score: ChromosomeSimilarityScore {
                    minhash: minhash_average,
                    tlsh: tlsh_average,
                },
                homologues: Vec::<HomologousChromosome>::new(),
            }));
        }

        Ok(None)
    }

    pub fn compare_many(
        &self,
        rhs_functions: Vec<Function>,
    ) -> Result<BTreeMap<u64, ChromosomeSimilarity>, Error> {
        let result: Result<BTreeMap<u64, ChromosomeSimilarity>, Error> = rhs_functions
            .iter()
            .filter_map(|function| match self.compare(function) {
                Ok(Some(similarity)) => Some(Ok((function.address(), similarity))),
                Ok(None) => None,
                Err(e) => Some(Err(e)),
            })
            .collect();

        result
    }

    pub fn chromosome_tlsh_ratio(&self) -> f64 {
        if self.contiguous() {
            return 1.0;
        }
        let mut tlsh_size: usize = 0;
        for block in self.blocks() {
            if block.chromosome().tlsh().is_some() {
                tlsh_size += block.size();
            }
        }
        tlsh_size as f64 / self.size() as f64
    }

    pub fn chromosome_minhash_ratio(&self) -> f64 {
        if self.contiguous() {
            return 1.0;
        }
        let mut minhash_size: usize = 0;
        for block in self.blocks() {
            if block.chromosome().minhash().is_some() {
                minhash_size += block.size();
            }
        }
        minhash_size as f64 / self.size() as f64
    }

    pub fn tlsh_ratio(&self) -> f64 {
        if self.contiguous() {
            return 1.0;
        }
        let mut tlsh_size: usize = 0;
        for block in self.blocks() {
            if block.tlsh().is_some() {
                tlsh_size += block.size();
            }
        }
        tlsh_size as f64 / self.size() as f64
    }

    pub fn minhash_ratio(&self) -> f64 {
        if self.contiguous() {
            return 1.0;
        }
        let mut minhash_size: usize = 0;
        for block in self.blocks() {
            if block.minhash().is_some() {
                minhash_size += block.size();
            }
        }
        minhash_size as f64 / self.size() as f64
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
        let bytes = self.bytes();
        bytes.as_ref()?;
        let pattern = self.pattern()?;
        let chromosome = Chromosome::new(pattern, self.cfg.config.clone()).ok()?;
        Some(chromosome)
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
        let bytes = self.bytes();
        bytes.as_ref()?;
        let pattern = self.pattern()?;
        let chromosome = Chromosome::new(pattern, self.cfg.config.clone()).ok()?;
        Some(chromosome.process())
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
    pub fn blocks(&self) -> Vec<Block> {
        if !self.cfg.config.functions.blocks.enabled {
            return Vec::new();
        }
        self.blocks
            .keys()
            .filter_map(|&block_address| Block::new(block_address, self.cfg).ok())
            .collect()
    }

    /// Retrieves the blocks associated with this function.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<BlockJson>` representing the blocks associated with this function.
    pub fn blocks_json(&self) -> Vec<BlockJson> {
        let mut result = Vec::<BlockJson>::new();
        if !self.cfg.config.functions.blocks.enabled {
            return result;
        }
        for block_address in self.blocks.keys() {
            let block = Block::new(*block_address, self.cfg)
                .expect("failed to get block associated with function");
            result.push(block.process());
        }
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

    /// Converts the function's bytes to a hexadecimal string, if available.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hexadecimal representation of the bytes, or `None` if unavailable.
    fn bytes_to_hex(&self) -> Option<String> {
        if let Some(bytes) = self.bytes() {
            return Some(Binary::to_hex(&bytes));
        }
        None
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

    /// Computes the SHA-256 hash of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hash, or `None` if SHA-256 is disabled or the function is not contiguous.
    pub fn sha256(&self) -> Option<String> {
        if !self.cfg.config.functions.hashing.sha256.enabled {
            return None;
        }
        if !self.contiguous() {
            return None;
        }
        if let Some(bytes) = self.bytes() {
            return SHA256::new(&bytes).hexdigest();
        }
        None
    }

    /// Computes the entropy of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if entropy calculation is disabled or the function is not contiguous.
    pub fn entropy(&self) -> Option<f64> {
        if !self.cfg.config.functions.heuristics.entropy.enabled {
            return None;
        }

        if self.contiguous() {
            return self.bytes().and_then(|bytes| Binary::entropy(&bytes));
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

    /// Computes the TLSH of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the TLSH, or `None` if TLSH is disabled or the function is not contiguous.
    pub fn tlsh(&self) -> Option<String> {
        if !self.cfg.config.functions.hashing.tlsh.enabled {
            return None;
        }
        if !self.contiguous() {
            return None;
        }
        if let Some(bytes) = self.bytes() {
            return TLSH::new(
                &bytes,
                self.cfg.config.functions.hashing.tlsh.minimum_byte_size,
            )
            .hexdigest();
        }
        None
    }

    /// Computes the MinHash of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the MinHash, or `None` if MinHash is disabled or the function is not contiguous.
    pub fn minhash(&self) -> Option<String> {
        if !self.cfg.config.functions.hashing.minhash.enabled {
            return None;
        }
        if !self.contiguous() {
            return None;
        }
        if let Some(bytes) = self.bytes() {
            if bytes.len() > self.cfg.config.functions.hashing.minhash.maximum_byte_size
                && self
                    .cfg
                    .config
                    .functions
                    .hashing
                    .minhash
                    .maximum_byte_size_enabled
            {
                return None;
            }
            return MinHash32::new(
                &bytes,
                self.cfg.config.functions.hashing.minhash.number_of_hashes,
                self.cfg.config.functions.hashing.minhash.shingle_size,
                self.cfg.config.functions.hashing.minhash.seed,
            )
            .hexdigest();
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
