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
use crate::Configuration;
use crate::controlflow::Block;
use crate::controlflow::EntityKind;
use crate::controlflow::Graph;
use crate::controlflow::Instruction;
use crate::embeddings::{Embedding, EmbeddingBackend, EmbeddingsJson};
use crate::entropy;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::SSDeep;
use crate::hashing::TLSH;
use crate::hex;
use crate::ir::ast::AstFunction;
use crate::ir::hir::HirFunction;
use crate::ir::lir::{
    LirAbi, LirCpu, LirEffect, LirExpression, LirFunction, LirLocation, LirOperationBinary,
    LirTerminator,
};
use crate::ir::llvm::{Lifter as LlvmLifter, LiftersJson, LlvmJson};
use crate::ir::mir::{
    MirAddressSpace, MirBlockParameter, MirControlTarget, MirFunction, MirOperationKind, MirType,
    MirValue,
};
#[cfg(not(target_os = "windows"))]
use crate::ir::vex::{Lifter as VexLifter, VexJson};
use crate::metadata::Attributes;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Error;

/// Represents a JSON-serializable structure containing metadata about a function.
#[derive(Serialize, Deserialize, Clone)]
pub struct FunctionJson {
    /// The kind of this entity, typically `"function"`.
    pub kind: EntityKind,
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
    /// A map of callsite addresses to directly called function addresses.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub callees: BTreeMap<u64, u64>,
    /// A map of callsite addresses to caller function addresses.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub callers: BTreeMap<u64, u64>,
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
    /// The ssdeep fuzzy hash of the function, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
    /// The MinHash of the function, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minhash: Option<String>,
    /// The TLSH of the function, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tlsh: Option<String>,
    /// The Markov-derived block importance scores, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub markov: Option<BTreeMap<u64, f64>>,
    /// Indicates whether the function is contiguous.
    pub contiguous: bool,
    /// Optional processor outputs attached by post-processing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processors: Option<BTreeMap<String, Value>>,
    /// Optional embeddings attached directly to this function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<EmbeddingsJson>,
    /// Attributes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Value>,
    /// Optional lifted representations attached to this function.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifters: Option<LiftersJson>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct FunctionJsonDeserializer {
    pub json: FunctionJson,
    pub config: Configuration,
}

impl FunctionJsonDeserializer {
    #[allow(dead_code)]
    pub fn new(string: String, config: Configuration) -> Result<Self, Error> {
        let json: FunctionJson =
            serde_json::from_str(&string).map_err(|error| Error::other(format!("{}", error)))?;
        if json.kind != EntityKind::Function {
            return Err(Error::other("deserialized JSON is not a function kind"));
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

    #[allow(dead_code)]
    pub fn kind(&self) -> EntityKind {
        self.json.kind
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
    pub fn callee_references(&self) -> BTreeMap<u64, u64> {
        self.json.callees.clone()
    }

    #[allow(dead_code)]
    pub fn caller_references(&self) -> BTreeMap<u64, u64> {
        self.json.callers.clone()
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
    pub fn ssdeep(&self) -> Option<String> {
        self.json.ssdeep.clone()
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
    pub fn markov(&self) -> Option<BTreeMap<u64, f64>> {
        self.json.markov.clone()
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
    fn contiguous_payload_bytes_and_mask(&self) -> Option<(Vec<u8>, Vec<u8>, u64)> {
        let end = self.effective_end()?;
        let mut bytes = Vec::new();
        let mut wildcard_mask = Vec::new();
        let mut pc = self.address;
        while pc < end {
            let instruction = self.cfg.get_instruction(pc)?;
            bytes.extend_from_slice(&instruction.bytes);
            if instruction.chromosome_mask.len() == instruction.bytes.len() {
                wildcard_mask.extend_from_slice(&instruction.chromosome_mask);
            } else {
                wildcard_mask.extend(std::iter::repeat_n(0, instruction.bytes.len()));
            }
            let size = instruction.size();
            if size == 0 {
                return None;
            }
            pc += size as u64;
        }
        Some((bytes, wildcard_mask, end))
    }

    fn block_payload_size(&self) -> usize {
        self.blocks.values().map(|block| block.size()).sum()
    }

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
        let block_addresses = cfg.function_block_addresses(address).ok_or_else(|| {
            Error::other(format!(
                "Function -> 0x{:x}: contains no valid blocks",
                address
            ))
        })?;
        for block_address in block_addresses {
            if cfg.blocks.is_invalid(block_address) {
                return Err(Error::other(format!(
                    "Function -> 0x{:x} -> Block -> 0x{:x}: is invalid",
                    address, block_address
                )));
            }
            if let Ok(block) = Block::new(block_address, cfg) {
                blocks.insert(block_address, block);
            }
        }

        if blocks.is_empty() {
            return Err(Error::other(format!(
                "Function -> 0x{:x}: contains no valid blocks",
                address
            )));
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
        self.process_base_with_references(self.callee_references(), self.caller_references())
    }

    pub fn process_base_with_references(
        &self,
        callee_references: BTreeMap<u64, u64>,
        caller_references: BTreeMap<u64, u64>,
    ) -> FunctionJson {
        let contiguous_payload = self.contiguous_payload_bytes_and_mask();
        let contiguous = contiguous_payload.is_some();
        let block_addresses = self.block_addresses();
        let number_of_blocks = block_addresses.len();
        let number_of_instructions: usize = self
            .blocks
            .values()
            .map(|block| block.number_of_instructions())
            .sum();
        let edges: usize = self.blocks.values().map(|block| block.edges()).sum();
        let size = contiguous_payload
            .as_ref()
            .map(|(bytes, _, _)| bytes.len())
            .unwrap_or_else(|| self.block_payload_size());
        let bytes = contiguous_payload
            .as_ref()
            .map(|(bytes, _, _)| bytes.clone());
        let bytes_hex = bytes.as_ref().map(|bytes| hex::encode(bytes));
        let chromosome = if contiguous {
            contiguous_payload
                .as_ref()
                .and_then(|(bytes, wildcard_mask, _)| {
                    Chromosome::new(
                        bytes.clone(),
                        wildcard_mask.clone(),
                        self.cfg.config.clone(),
                    )
                    .ok()
                    .map(|chromosome| chromosome.process())
                })
        } else {
            None
        };
        let entropy = if self.cfg.config.functions.entropy.enabled {
            if let Some((bytes, _, _)) = &contiguous_payload {
                entropy::shannon(bytes)
            } else {
                self.entropy()
            }
        } else {
            None
        };
        let sha256 = if self.cfg.config.functions.sha256.enabled {
            bytes
                .as_ref()
                .and_then(|bytes| SHA256::new(bytes).hexdigest())
        } else {
            None
        };
        let ssdeep = if self.cfg.config.functions.ssdeep.enabled {
            bytes
                .as_ref()
                .and_then(|bytes| SSDeep::new(bytes).hexdigest())
        } else {
            None
        };
        let tlsh = if self.cfg.config.functions.tlsh.enabled {
            bytes.as_ref().and_then(|bytes| {
                TLSH::new(bytes, self.cfg.config.functions.tlsh.minimum_byte_size).hexdigest()
            })
        } else {
            None
        };
        let minhash = if self.cfg.config.functions.minhash.enabled {
            bytes.as_ref().and_then(|bytes| {
                if bytes.len() > self.cfg.config.functions.minhash.maximum_byte_size
                    && self.cfg.config.functions.minhash.maximum_byte_size_enabled
                {
                    None
                } else {
                    MinHash32::new(
                        bytes,
                        self.cfg.config.functions.minhash.number_of_hashes,
                        self.cfg.config.functions.minhash.shingle_size,
                        self.cfg.config.functions.minhash.seed,
                    )
                    .hexdigest()
                }
            })
        } else {
            None
        };
        let markov = if self.cfg.config.functions.markov.enabled {
            Some(self.markov())
        } else {
            None
        };

        FunctionJson {
            address: self.address,
            kind: EntityKind::Function,
            edges,
            chromosome,
            bytes: bytes_hex,
            size,
            callees: callee_references,
            callers: caller_references,
            blocks: block_addresses,
            number_of_blocks,
            number_of_instructions,
            cyclomatic_complexity: if edges < number_of_blocks {
                0
            } else {
                edges - number_of_blocks + 2
            },
            average_instructions_per_block: if number_of_blocks == 0 {
                0.0
            } else {
                number_of_instructions as f64 / number_of_blocks as f64
            },
            entropy,
            sha256,
            ssdeep,
            minhash,
            tlsh,
            markov,
            contiguous,
            processors: None,
            embeddings: None,
            architecture: self.architecture().to_string(),
            attributes: None,
            lifters: self.lifters_json(),
        }
    }

    pub fn process(&self) -> FunctionJson {
        let mut json = self.process_base();
        self.apply_processors(&mut json);
        json
    }

    pub fn process_with_references(
        &self,
        callee_references: BTreeMap<u64, u64>,
        caller_references: BTreeMap<u64, u64>,
    ) -> FunctionJson {
        let mut json = self.process_base_with_references(callee_references, caller_references);
        self.apply_processors(&mut json);
        json
    }

    fn apply_processors(&self, json: &mut FunctionJson) {
        if crate::processor::enabled_processors_for_target(
            &self.cfg.config,
            crate::processor::ProcessorTarget::Graph,
        )
        .iter()
        .any(|processor| {
            self.cfg
                .processor_output(
                    crate::processor::ProcessorTarget::Function,
                    self.address,
                    processor.name(),
                )
                .is_none()
        }) {
            let _ = self.cfg.process_graph();
        }
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
        if self.cfg.config.functions.embeddings.llvm.enabled {
            if let Some(vector) = self.embedding() {
                json.embeddings = Some(EmbeddingsJson::llvm(vector));
            }
        }
    }

    /// Return all processor outputs attached to this function.
    pub fn processors(&self) -> BTreeMap<String, Value> {
        self.process().processors.unwrap_or_default()
    }

    /// Return an embedding vector for this function using the default backend and dimensions.
    pub fn embedding(&self) -> Option<Vec<f32>> {
        self.embedding_with_options(None, None)
    }

    /// Return an embedding vector for this function using optional backend and dimension overrides.
    pub fn embedding_with_options(
        &self,
        backend: Option<EmbeddingBackend>,
        dimensions: Option<usize>,
    ) -> Option<Vec<f32>> {
        Embedding::new(
            self.architecture(),
            self.cfg.config.clone(),
            backend,
            dimensions,
        )
        .embed_function(self)
    }

    pub fn llvm(&self, abi: Option<&LirAbi>, triple: Option<String>) -> Result<LlvmLifter, Error> {
        let mut lifter = if let Some(triple) = triple {
            let cpu = LirCpu::from_architecture(self.architecture())
                .map_err(|error| Error::other(error.to_string()))?;
            LlvmLifter::new(cpu, self.cfg.config.clone(), Some(triple))
                .map_err(|error| Error::other(error.to_string()))?
        } else {
            LlvmLifter::from_architecture(self.architecture(), self.cfg.config.clone())
        };
        lifter.lift_function(self, abi)?;
        Ok(lifter)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn vex(&self, abi: Option<&LirAbi>) -> Result<VexLifter, Error> {
        let mut lifter = VexLifter::new(self.cfg.config.clone());
        lifter.lift_function(self, abi)?;
        Ok(lifter)
    }

    fn lifters_json(&self) -> Option<LiftersJson> {
        let llvm = if self.cfg.config.functions.lifters.llvm.enabled {
            let mut lifter =
                LlvmLifter::from_architecture(self.architecture(), self.cfg.config.clone());
            lifter.lift_function(self, None).ok()?;
            Some(LlvmJson { text: lifter.ir() })
        } else {
            None
        };

        #[cfg(not(target_os = "windows"))]
        let vex = if self.cfg.config.lifters.vex.enabled
            && self.cfg.config.functions.lifters.vex.enabled
        {
            let mut lifter = VexLifter::new(self.cfg.config.clone());
            lifter.lift_function(self, None).ok()?;
            Some(VexJson { text: lifter.ir() })
        } else {
            None
        };

        #[cfg(not(target_os = "windows"))]
        if llvm.is_none() && vex.is_none() {
            return None;
        }

        #[cfg(target_os = "windows")]
        if llvm.is_none() {
            return None;
        }

        Some(LiftersJson {
            llvm,
            #[cfg(not(target_os = "windows"))]
            vex,
        })
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

    pub fn process_with_attributes_and_references(
        &self,
        attributes: Attributes,
        callee_references: BTreeMap<u64, u64>,
        caller_references: BTreeMap<u64, u64>,
    ) -> FunctionJson {
        let mut result = self.process_with_references(callee_references, caller_references);
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

    pub fn kind(&self) -> EntityKind {
        EntityKind::Function
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
        let (bytes, wildcard_mask, _) = self.contiguous_payload_bytes_and_mask()?;
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
        self.blocks.values().cloned().collect()
    }

    fn const_u64_value(expression: &LirExpression) -> Option<u64> {
        match expression {
            LirExpression::Const { value, .. } => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    fn read_register_name(expression: &LirExpression) -> Option<&str> {
        match expression {
            LirExpression::Read(location) => match location.as_ref() {
                LirLocation::Register { name, .. } => Some(name.as_str()),
                _ => None,
            },
            _ => None,
        }
    }

    fn resolve_indirect_symbol_address(
        encoding: Option<&crate::ir::lir::LirEncoding>,
        expression: &LirExpression,
        register_map: &BTreeMap<String, LirExpression>,
        depth: usize,
    ) -> Option<u64> {
        if depth > 4 {
            return None;
        }

        match expression {
            LirExpression::Binary {
                op, left, right, ..
            } if matches!(op, LirOperationBinary::Add)
                && matches!(Self::read_register_name(left), Some("rip" | "eip")) =>
            {
                let displacement = Self::const_u64_value(right)?;
                let encoding = encoding?;
                Some(encoding.address + encoding.bytes.len() as u64 + displacement)
            }
            LirExpression::Read(location) => {
                if let LirLocation::Register { name, .. } = location.as_ref()
                    && let Some(aliased) = register_map.get(name)
                {
                    return Self::resolve_indirect_symbol_address(
                        encoding,
                        aliased,
                        register_map,
                        depth + 1,
                    );
                }
                None
            }
            _ => Self::const_u64_value(expression),
        }
    }

    fn resolve_indirect_symbol_name(
        encoding: Option<&crate::ir::lir::LirEncoding>,
        target: &LirExpression,
        symbol_map: &BTreeMap<u64, String>,
        register_map: &BTreeMap<String, LirExpression>,
        depth: usize,
    ) -> Option<String> {
        if depth > 4 {
            return None;
        }

        if let LirExpression::Read(location) = target
            && let LirLocation::Register { name, .. } = location.as_ref()
            && let Some(aliased) = register_map.get(name)
        {
            return Self::resolve_indirect_symbol_name(
                encoding,
                aliased,
                symbol_map,
                register_map,
                depth + 1,
            );
        }

        let (space, addr) = match target {
            LirExpression::Load { space, addr, .. } => (space, addr.as_ref()),
            _ => return None,
        };

        if !matches!(space, crate::ir::lir::LirAddressSpace::Default) {
            return None;
        }

        let address = Self::resolve_indirect_symbol_address(encoding, addr, register_map, 0)?;
        symbol_map.get(&address).cloned()
    }

    fn resolve_symbol_name(
        encoding: Option<&crate::ir::lir::LirEncoding>,
        target: &LirExpression,
        symbol_map: &BTreeMap<u64, String>,
        register_map: &BTreeMap<String, LirExpression>,
    ) -> Option<String> {
        if let Some(address) = Self::const_u64_value(target) {
            if let Some(name) = symbol_map.get(&address) {
                return Some(name.clone());
            }
        }

        Self::resolve_indirect_symbol_name(encoding, target, symbol_map, register_map, 0)
    }

    fn canonicalize_indirect_target_address(
        encoding: Option<&crate::ir::lir::LirEncoding>,
        target: &mut LirExpression,
        register_map: &BTreeMap<String, LirExpression>,
    ) -> bool {
        let LirExpression::Load { space, addr, .. } = target else {
            return false;
        };
        if !matches!(space, crate::ir::lir::LirAddressSpace::Default) {
            return false;
        }
        let Some(address) = Self::resolve_indirect_symbol_address(encoding, addr, register_map, 0)
        else {
            return false;
        };
        if matches!(addr.as_ref(), LirExpression::Const { value, .. } if *value == address as u128)
        {
            return false;
        }
        let bits = addr.bits();
        *addr = Box::new(LirExpression::Const {
            value: address as u128,
            bits,
        });
        true
    }

    fn rewrite_lir_function_symbols(
        lir: &mut LirFunction,
        symbol_map: &BTreeMap<u64, String>,
    ) -> bool {
        if symbol_map.is_empty() {
            return false;
        }

        let mut changed = false;

        for block in &mut lir.blocks {
            let mut register_map = BTreeMap::<String, LirExpression>::new();

            for instruction in &mut block.instructions {
                let encoding = instruction.encoding.as_ref();
                for effect in &instruction.effects {
                    if let LirEffect::Set {
                        dst: LirLocation::Register { name, .. },
                        expression,
                    } = effect
                    {
                        register_map.insert(name.clone(), expression.clone());
                    }
                }

                match &mut instruction.terminator {
                    LirTerminator::Call { target, .. } | LirTerminator::Jump { target } => {
                        changed |= Self::canonicalize_indirect_target_address(
                            encoding,
                            target,
                            &register_map,
                        );
                        if let Some(name) =
                            Self::resolve_symbol_name(encoding, target, symbol_map, &register_map)
                        {
                            *target = LirExpression::Function {
                                name,
                                bits: target.bits(),
                            };
                            changed = true;
                        }
                    }
                    LirTerminator::Branch {
                        true_target,
                        false_target,
                        ..
                    } => {
                        changed |= Self::canonicalize_indirect_target_address(
                            encoding,
                            true_target,
                            &register_map,
                        );
                        if let Some(name) = Self::resolve_symbol_name(
                            encoding,
                            true_target,
                            symbol_map,
                            &register_map,
                        ) {
                            *true_target = LirExpression::Function {
                                name,
                                bits: true_target.bits(),
                            };
                            changed = true;
                        }
                        changed |= Self::canonicalize_indirect_target_address(
                            encoding,
                            false_target,
                            &register_map,
                        );
                        if let Some(name) = Self::resolve_symbol_name(
                            encoding,
                            false_target,
                            symbol_map,
                            &register_map,
                        ) {
                            *false_target = LirExpression::Function {
                                name,
                                bits: false_target.bits(),
                            };
                            changed = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        changed
    }

    fn lir_name_with_symbols(&self, symbol_map: &BTreeMap<u64, String>) -> String {
        symbol_map
            .get(&self.address)
            .cloned()
            .unwrap_or_else(|| format!("function_{:x}", self.address))
    }

    fn build_lir(&self, symbol_map: &BTreeMap<u64, String>) -> Result<LirFunction, Error> {
        let blocks = self
            .blocks()
            .into_iter()
            .map(|block| block.lir())
            .collect::<Result<Vec<_>, Error>>()?;
        let abi = blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find_map(|instruction| instruction.abi.clone());
        let mut lir = LirFunction {
            name: Some(self.lir_name_with_symbols(symbol_map)),
            abi,
            blocks,
        };
        Self::rewrite_lir_function_symbols(&mut lir, symbol_map);
        Ok(lir)
    }

    pub fn lir(&self) -> Result<LirFunction, Error> {
        self.build_lir(&self.cfg.symbols())
    }

    pub fn mir(&self) -> Result<MirFunction, Error> {
        let mut mir = MirFunction::from_lir(None, &self.lir()?)
            .map_err(|error| Error::other(error.to_string()))?;
        self.trim_mir_call_arguments(&mut mir, &self.cfg.symbols())?;
        self.apply_observed_import_signature(&mut mir, &self.cfg.symbols())?;
        apply_observed_call_argument_types(&mut mir);
        Ok(mir)
    }

    pub fn hir(&self) -> Result<HirFunction, Error> {
        let mir = self.mir()?;
        HirFunction::from_mir(None, &mir).map_err(|error| Error::other(error.to_string()))
    }

    pub fn ast(&self) -> Result<AstFunction, Error> {
        Ok(AstFunction::from_hir(&self.hir()?))
    }

    pub fn c(&self) -> Result<String, Error> {
        Ok(self.ast()?.c())
    }

    pub fn c_with_image(&self, image: &crate::formats::Image) -> Result<String, Error> {
        Ok(self.ast()?.c_with_image(image))
    }

    pub(crate) fn trim_mir_call_arguments(
        &self,
        mir: &mut MirFunction,
        symbol_map: &BTreeMap<u64, String>,
    ) -> Result<(), Error> {
        let entry_parameter_names = mir
            .entry_parameters
            .iter()
            .filter_map(|parameter| parameter.name.clone())
            .collect::<BTreeSet<_>>();
        let symbol_to_address = symbol_map
            .iter()
            .map(|(address, name)| (name.clone(), *address))
            .collect::<BTreeMap<_, _>>();

        for block in mir.blocks_mut() {
            for operation in &mut block.operations {
                let MirOperationKind::Call { target, .. } = &mut operation.kind else {
                    continue;
                };

                match target {
                    MirControlTarget::Direct(target) => {
                        let target_name = target.clone();
                        if import_prototype_arity(&target_name).is_some() {
                            trim_import_or_external_call_arguments(
                                operation,
                                &target_name,
                                &entry_parameter_names,
                            );
                            continue;
                        }
                        let Some(address) = symbol_to_address.get(target).copied() else {
                            trim_import_or_external_call_arguments(
                                operation,
                                &target_name,
                                &entry_parameter_names,
                            );
                            continue;
                        };
                        if target.contains('!') {
                            trim_import_or_external_call_arguments(
                                operation,
                                &target_name,
                                &entry_parameter_names,
                            );
                            continue;
                        }
                        if address == self.address {
                            continue;
                        }
                        let Some(callee) = self.cfg.get_function(address) else {
                            trim_import_or_external_call_arguments(
                                operation,
                                &target_name,
                                &entry_parameter_names,
                            );
                            continue;
                        };
                        let mut callee_lir = callee.lir()?;
                        callee_lir.optimize();
                        let callee_mir = MirFunction::from_lir(None, &callee_lir)
                            .map_err(|error| Error::other(error.to_string()))?;
                        let keep = callee_mir.entry_parameters.len();
                        trim_local_call_metadata(operation, keep);
                    }
                    MirControlTarget::FunctionIndirect(_) | MirControlTarget::BlockIndirect(_) => {
                        trim_external_call_arguments(operation, &entry_parameter_names);
                    }
                }
            }
        }

        Ok(())
    }

    fn apply_observed_import_signature(
        &self,
        mir: &mut MirFunction,
        symbol_map: &BTreeMap<u64, String>,
    ) -> Result<(), Error> {
        let Some(symbol_name) = symbol_map.get(&self.address) else {
            return Ok(());
        };
        if !symbol_name.contains('!') || !mir.entry_parameters.is_empty() {
            return Ok(());
        }

        let mut observed = Vec::<Option<MirType>>::new();
        let callers = self
            .caller_references()
            .values()
            .copied()
            .collect::<BTreeSet<_>>();

        for caller_address in callers {
            if caller_address == self.address {
                continue;
            }
            let Some(caller) = self.cfg.get_function(caller_address) else {
                continue;
            };
            let caller_mir = caller.mir()?;
            let defs = build_mir_defs(&caller_mir);
            for block in caller_mir.blocks() {
                for operation in &block.operations {
                    let MirOperationKind::Call {
                        target: MirControlTarget::Direct(target),
                        arguments,
                        ..
                    } = &operation.kind
                    else {
                        continue;
                    };
                    if target != symbol_name {
                        continue;
                    }
                    for (index, argument) in arguments.iter().enumerate() {
                        let ty = observed_argument_type(argument, &defs, 0);
                        if observed.len() <= index {
                            observed.resize(index + 1, None);
                        }
                        merge_observed_type(&mut observed[index], ty);
                    }
                }
            }
        }

        if observed.is_empty() {
            return Ok(());
        }

        let entry_parameters = observed
            .into_iter()
            .enumerate()
            .filter_map(|(index, ty)| {
                ty.map(|ty| MirBlockParameter::new(Some(format!("arg{index}")), ty))
            })
            .collect::<Vec<_>>();

        if entry_parameters.is_empty() {
            return Ok(());
        }

        mir.entry_parameters = entry_parameters.clone();
        if let Some(entry_block) = mir.blocks_mut().first_mut() {
            entry_block.parameters = entry_parameters;
        }
        Ok(())
    }

    /// Retrieves all blocks that fall within the contiguous reconstruction region.
    ///
    /// This includes local directly reached code that may extend beyond the
    /// function's original CFG-owned blocks but still belongs to the same
    /// contiguous reconstruction span.
    pub fn reconstruction_blocks(&self) -> Vec<Block<'_>> {
        let Some(end) = self.effective_end() else {
            return self.blocks();
        };

        let mut result = Vec::<Block<'_>>::new();
        let mut seen = std::collections::BTreeSet::<u64>::new();
        for entry in self.cfg.listing.range(self.address..end) {
            let address = *entry.key();
            if !seen.insert(address) {
                continue;
            }
            if let Ok(block) = Block::new(address, self.cfg) {
                if block.address() >= self.address && block.end() <= end {
                    result.push(block);
                }
            }
        }
        result
    }

    /// Retrieves all instructions that fall within the contiguous reconstruction
    /// region, whether or not they were promoted to CFG block starts.
    pub fn reconstruction_instructions(&self) -> Vec<Instruction<'_>> {
        let Some(end) = self.effective_end() else {
            return Vec::new();
        };

        let mut result = Vec::<Instruction>::new();
        for entry in self.cfg.listing.range(self.address..end) {
            let address = *entry.key();
            if let Ok(instruction) = Instruction::new(address, self.cfg) {
                result.push(instruction);
            }
        }
        result
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

    /// Retrieves the function size in bytes.
    ///
    /// # Returns
    ///
    /// Returns the contiguous byte size when the function is contiguous, otherwise
    /// the aggregate size of the function's owned blocks.
    pub fn size(&self) -> usize {
        self.contiguous_payload_bytes_and_mask()
            .map(|(bytes, _, _)| bytes.len())
            .unwrap_or_else(|| self.block_payload_size())
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
        self.effective_end()
    }

    /// Retrieves the raw bytes of the function, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(Vec<u8>)` containing the bytes, or `None` if the function is not contiguous.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        self.collect_region_bytes(self.effective_end()?)
    }

    fn collect_region_bytes(&self, end: u64) -> Option<Vec<u8>> {
        if end < self.address {
            return None;
        }

        let mut bytes = Vec::<u8>::new();
        let mut pc = self.address;
        while pc < end {
            let instruction = self.cfg.get_instruction(pc)?;
            bytes.extend(&instruction.bytes);
            pc += instruction.size() as u64;
        }
        Some(bytes)
    }

    fn effective_end(&self) -> Option<u64> {
        if self.blocks.is_empty() {
            return None;
        }

        let mut end = self
            .blocks
            .values()
            .map(|b| b.address + b.size() as u64)
            .max()
            .unwrap_or(self.address);

        let mut queue: Vec<u64> = self.callee_references().values().copied().collect();
        let mut visited = std::collections::BTreeSet::<u64>::new();

        while let Some(callee_address) = queue.pop() {
            if !visited.insert(callee_address) {
                continue;
            }
            if callee_address < self.address {
                continue;
            }
            let callee = match Function::new(callee_address, self.cfg) {
                Ok(function) => function,
                Err(_) => continue,
            };
            let callee_end = callee
                .blocks
                .values()
                .map(|b| b.address + b.size() as u64)
                .max()
                .unwrap_or(callee_address);

            self.collect_region_bytes(callee_end)?;

            if callee_end > end {
                end = callee_end;
            }

            queue.extend(callee.callee_references().values().copied());
        }

        if self
            .cfg
            .listing
            .range(self.address..end)
            .any(|entry| entry.value().has_indirect_target())
        {
            let mut pc = end;
            while let Some(instruction) = self.cfg.get_instruction(pc) {
                pc += instruction.size() as u64;
                end = pc;
            }
        }

        Some(end)
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

    /// Computes the ssdeep hash of the function's bytes, if contiguous.
    pub fn ssdeep(&self) -> Option<SSDeep<'static>> {
        if !self.contiguous() {
            return None;
        }
        self.bytes().map(SSDeep::from_bytes)
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

    /// Retrieves the direct callsites within this function.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeMap<u64, u64>` containing `callsite -> callee` pairs.
    pub(crate) fn compute_callee_references(&self) -> BTreeMap<u64, u64> {
        self.blocks
            .values()
            .flat_map(|block| {
                block
                    .callee_references()
                    .into_iter()
                    .map(|reference| (reference.location, reference.address))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Retrieves the direct callsites within this function.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeMap<u64, u64>` containing `callsite -> callee` pairs.
    pub fn callee_references(&self) -> BTreeMap<u64, u64> {
        self.cfg.function_callee_references(self.address)
    }

    /// Retrieves the direct incoming callsites targeting this function.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeMap<u64, u64>` containing `callsite -> caller` pairs.
    pub fn caller_references(&self) -> BTreeMap<u64, u64> {
        self.cfg.function_caller_references(self.address)
    }

    /// Retrieves the directly called functions.
    pub fn callees(&self) -> Vec<Function<'function>> {
        let mut seen = BTreeSet::<u64>::new();
        let mut result = Vec::<Function<'function>>::new();

        for callee_address in self.callee_references().values().copied() {
            if !seen.insert(callee_address) {
                continue;
            }
            if let Ok(function) = Function::new(callee_address, self.cfg) {
                result.push(function);
            }
        }

        result
    }

    /// Retrieves the direct caller functions.
    pub fn callers(&self) -> Vec<Function<'function>> {
        let mut seen = BTreeSet::<u64>::new();
        let mut result = Vec::<Function<'function>>::new();

        for caller_address in self.caller_references().values().copied() {
            if !seen.insert(caller_address) {
                continue;
            }
            if let Ok(function) = Function::new(caller_address, self.cfg) {
                result.push(function);
            }
        }

        result
    }

    /// Computes normalized Markov-derived importance scores for blocks in the function.
    pub fn markov(&self) -> BTreeMap<u64, f64> {
        let addresses: Vec<u64> = self.blocks.keys().copied().collect();
        let n = addresses.len();

        if n == 0 {
            return BTreeMap::new();
        }

        if n == 1 {
            return BTreeMap::from([(addresses[0], 1.0)]);
        }

        let damping = self.cfg.config.functions.markov.damping;
        let tolerance = self.cfg.config.functions.markov.tolerance;
        let max_iterations = self.cfg.config.functions.markov.max_iterations;
        let base = (1.0 - damping) / n as f64;
        let block_set: std::collections::BTreeSet<u64> = addresses.iter().copied().collect();

        let outgoing: BTreeMap<u64, Vec<u64>> = self
            .blocks
            .iter()
            .map(|(&address, block)| {
                let targets = block
                    .successors()
                    .into_iter()
                    .map(|target| target.address())
                    .filter(|target| block_set.contains(target))
                    .collect::<Vec<_>>();
                (address, targets)
            })
            .collect();

        let mut scores: BTreeMap<u64, f64> = addresses
            .iter()
            .copied()
            .map(|address| (address, 1.0 / n as f64))
            .collect();

        for _ in 0..max_iterations {
            let mut next: BTreeMap<u64, f64> = addresses
                .iter()
                .copied()
                .map(|address| (address, base))
                .collect();

            for source in &addresses {
                let source_score = *scores.get(source).unwrap_or(&0.0);
                let targets = outgoing.get(source).map(Vec::as_slice).unwrap_or(&[]);

                if targets.is_empty() {
                    let share = damping * source_score / n as f64;
                    for target in &addresses {
                        if let Some(value) = next.get_mut(target) {
                            *value += share;
                        }
                    }
                } else {
                    let share = damping * source_score / targets.len() as f64;
                    for target in targets {
                        if let Some(value) = next.get_mut(target) {
                            *value += share;
                        }
                    }
                }
            }

            let delta: f64 = addresses
                .iter()
                .map(|address| {
                    let old = scores.get(address).copied().unwrap_or(0.0);
                    let new = next.get(address).copied().unwrap_or(0.0);
                    (new - old).abs()
                })
                .sum();

            scores = next;

            if delta < tolerance {
                break;
            }
        }

        let total: f64 = scores.values().sum();
        if total > 0.0 {
            for value in scores.values_mut() {
                *value /= total;
            }
        }

        scores
    }

    /// Checks whether the function is contiguous in memory.
    ///
    /// # Returns
    ///
    /// Returns `true` if the function is contiguous; otherwise, `false`.
    pub fn contiguous(&self) -> bool {
        self.contiguous_payload_bytes_and_mask().is_some()
    }
}

fn trim_import_or_external_call_arguments(
    operation: &mut crate::ir::mir::MirOperation,
    target: &str,
    entry_parameter_names: &BTreeSet<String>,
) {
    if let Some(arity) = import_prototype_arity(target) {
        trim_local_call_metadata(operation, arity);
    } else {
        trim_external_call_arguments(operation, entry_parameter_names);
    }
}

fn import_prototype_arity(target: &str) -> Option<usize> {
    let name = target
        .rsplit_once('!')
        .map(|(_, symbol)| symbol)
        .unwrap_or(target);
    match name {
        "DeviceIoControl" => Some(8),
        "GetLastError" => Some(0),
        "KernelBaseGetGlobalData" => Some(0),
        "CreateFileA" | "CreateFileW" => Some(7),
        "CloseHandle" | "NtClose" | "RtlSetLastWin32Error" | "SetLastError" => Some(1),
        "NtDeviceIoControlFile" | "ZwDeviceIoControlFile" => Some(10),
        "RtlAllocateHeap" | "RtlFreeHeap" | "RtlMoveMemory" | "RtlCopyMemory" | "memcpy"
        | "memmove" => Some(3),
        _ => None,
    }
}

fn trim_local_call_metadata(operation: &mut crate::ir::mir::MirOperation, keep: usize) {
    let MirOperationKind::Call {
        arguments,
        clobbers,
        memory_effects,
        ..
    } = &mut operation.kind
    else {
        return;
    };

    if keep < arguments.len() {
        arguments.truncate(keep);
    }

    clobbers.retain(
        |clobber| match clobber.register.trim_start_matches('%').strip_prefix("arg") {
            Some(index) => index
                .parse::<usize>()
                .ok()
                .is_some_and(|index| index < keep),
            None => true,
        },
    );

    if keep == 0 {
        memory_effects.retain(
            |effect| !matches!(effect, MirAddressSpace::Incoming { name } if name == "args"),
        );
    }
}

fn trim_external_call_arguments(
    operation: &mut crate::ir::mir::MirOperation,
    entry_parameter_names: &BTreeSet<String>,
) {
    let MirOperationKind::Call {
        arguments,
        clobbers,
        memory_effects,
        ..
    } = &mut operation.kind
    else {
        return;
    };

    let mut filtered_arguments = Vec::with_capacity(arguments.len());
    let mut uses_entry_arguments = false;
    for argument in arguments.iter() {
        if is_meaningful_external_argument(argument, entry_parameter_names) {
            filtered_arguments.push(argument.clone());
        }
        if argument_uses_entry_parameter(argument, entry_parameter_names) {
            uses_entry_arguments = true;
        }
    }

    *arguments = filtered_arguments;
    let keep = arguments.len();
    clobbers.retain(
        |clobber| match clobber.register.trim_start_matches('%').strip_prefix("arg") {
            Some(index) => index
                .parse::<usize>()
                .ok()
                .is_some_and(|index| index < keep),
            None => true,
        },
    );

    if !uses_entry_arguments {
        memory_effects.retain(
            |effect| !matches!(effect, MirAddressSpace::Incoming { name } if name == "args"),
        );
    }
}

fn is_meaningful_external_argument(
    argument: &crate::ir::mir::MirValue,
    entry_parameter_names: &BTreeSet<String>,
) -> bool {
    match argument {
        crate::ir::mir::MirValue::Named { name, .. } => {
            if name.starts_with("arg") && !entry_parameter_names.contains(name) {
                return false;
            }
            true
        }
        crate::ir::mir::MirValue::Undef { .. } => false,
        crate::ir::mir::MirValue::Integer { .. }
        | crate::ir::mir::MirValue::Boolean(_)
        | crate::ir::mir::MirValue::Null { .. } => true,
    }
}

fn argument_uses_entry_parameter(
    argument: &crate::ir::mir::MirValue,
    entry_parameter_names: &BTreeSet<String>,
) -> bool {
    match argument {
        crate::ir::mir::MirValue::Named { name, .. } => entry_parameter_names.contains(name),
        _ => false,
    }
}

fn mir_value_type(value: &MirValue) -> MirType {
    match value {
        MirValue::Named { ty, .. } | MirValue::Null { ty } | MirValue::Undef { ty } => ty.clone(),
        MirValue::Integer { bits, .. } => MirType::integer(*bits),
        MirValue::Boolean(_) => MirType::integer(1),
    }
}

fn observed_argument_type(
    value: &MirValue,
    defs: &BTreeMap<String, MirOperationKind>,
    depth: usize,
) -> MirType {
    if depth > 16 {
        return mir_value_type(value);
    }

    if is_pointer_like_value(value, defs, depth) {
        return MirType::pointer(MirType::integer(8));
    }

    match value {
        MirValue::Named { name, ty } => match defs.get(name) {
            Some(MirOperationKind::Copy { value, .. })
            | Some(MirOperationKind::Cast { value, .. }) => {
                observed_argument_type(value, defs, depth + 1)
            }
            _ => ty.clone(),
        },
        _ => mir_value_type(value),
    }
}

fn is_pointer_like_value(
    value: &MirValue,
    defs: &BTreeMap<String, MirOperationKind>,
    depth: usize,
) -> bool {
    if depth > 16 {
        return false;
    }

    match value {
        MirValue::Named { name, ty } => {
            if matches!(ty, MirType::Pointer { .. }) || name.starts_with("ptr.") {
                return true;
            }
            if matches!(name.as_str(), "pc" | "sp" | "fp") {
                return true;
            }
            match defs.get(name) {
                Some(MirOperationKind::Copy { value, .. })
                | Some(MirOperationKind::Cast { value, .. }) => {
                    is_pointer_like_value(value, defs, depth + 1)
                }
                Some(MirOperationKind::Load { address, .. }) => {
                    is_pointer_like_value(address, defs, depth + 1)
                }
                Some(MirOperationKind::Add { lhs, rhs, .. })
                | Some(MirOperationKind::Sub { lhs, rhs, .. }) => {
                    (is_pointer_like_value(lhs, defs, depth + 1)
                        && is_integer_like_value(rhs, defs, depth + 1))
                        || (is_pointer_like_value(rhs, defs, depth + 1)
                            && is_integer_like_value(lhs, defs, depth + 1))
                }
                _ => false,
            }
        }
        MirValue::Null { ty } => matches!(ty, MirType::Pointer { .. }),
        _ => false,
    }
}

fn is_integer_like_value(
    value: &MirValue,
    defs: &BTreeMap<String, MirOperationKind>,
    depth: usize,
) -> bool {
    if depth > 16 {
        return matches!(
            mir_value_type(value),
            MirType::Integer(_)
                | MirType::Float(_)
                | MirType::TypeDefinition { .. }
                | MirType::Structure { .. }
                | MirType::Union { .. }
        );
    }

    match value {
        MirValue::Integer { .. } | MirValue::Boolean(_) => true,
        MirValue::Named { name, ty } => {
            if matches!(
                ty,
                MirType::Integer(_)
                    | MirType::Float(_)
                    | MirType::TypeDefinition { .. }
                    | MirType::Structure { .. }
                    | MirType::Union { .. }
            ) {
                return true;
            }
            match defs.get(name) {
                Some(MirOperationKind::Copy { value, .. })
                | Some(MirOperationKind::Cast { value, .. }) => {
                    is_integer_like_value(value, defs, depth + 1)
                }
                _ => false,
            }
        }
        MirValue::Null { .. } | MirValue::Undef { .. } => false,
    }
}

fn build_mir_defs(mir: &MirFunction) -> BTreeMap<String, MirOperationKind> {
    mir.blocks()
        .iter()
        .flat_map(|block| block.operations.iter())
        .filter_map(|operation| {
            operation
                .result
                .clone()
                .map(|result| (result, operation.kind.clone()))
        })
        .collect()
}

fn apply_observed_call_argument_types(mir: &mut MirFunction) {
    let defs = build_mir_defs(mir);
    let mut updates = BTreeMap::<String, Option<MirType>>::new();

    for block in mir.blocks() {
        for operation in &block.operations {
            let MirOperationKind::Call {
                target,
                arguments,
                result_types,
                ..
            } = &operation.kind
            else {
                continue;
            };
            match target {
                MirControlTarget::Direct(target) => {
                    if !target.contains('!') {
                        continue;
                    }
                }
                MirControlTarget::FunctionIndirect(value)
                | MirControlTarget::BlockIndirect(value) => {
                    if let MirValue::Named { name, .. } = value {
                        let slot = updates.entry(name.clone()).or_insert(None);
                        merge_observed_type(
                            slot,
                            indirect_code_pointer_type(arguments, result_types, &defs),
                        );
                    }
                }
            }
            for argument in arguments {
                let MirValue::Named { name, .. } = argument else {
                    continue;
                };
                let ty = observed_argument_type(argument, &defs, 0);
                if matches!(ty, MirType::Pointer { .. }) {
                    let slot = updates.entry(name.clone()).or_insert(None);
                    merge_observed_type(slot, ty);
                }
            }
        }
    }

    for (name, ty) in updates {
        if let Some(ty) = ty {
            rewrite_named_type(mir, &name, &ty);
        }
    }
}

fn indirect_code_pointer_type(
    arguments: &[MirValue],
    result_types: &[MirType],
    defs: &BTreeMap<String, MirOperationKind>,
) -> MirType {
    let argument_types = arguments
        .iter()
        .map(|argument| observed_argument_type(argument, defs, 0))
        .collect::<Vec<_>>();
    MirType::pointer(MirType::function(argument_types, result_types.to_vec()))
}

fn rewrite_named_type(mir: &mut MirFunction, name: &str, ty: &MirType) {
    for parameter in &mut mir.entry_parameters {
        if parameter.name.as_deref() == Some(name) {
            parameter.ty = ty.clone();
        }
    }
    for block in mir.blocks_mut() {
        for parameter in &mut block.parameters {
            if parameter.name.as_deref() == Some(name) {
                parameter.ty = ty.clone();
            }
        }
        for operation in &mut block.operations {
            if operation.result.as_deref() == Some(name) {
                rewrite_operation_result_type(&mut operation.kind, ty);
            }
            rewrite_value_types_in_operation(&mut operation.kind, name, ty);
        }
        if let Some(terminator) = &mut block.terminator {
            rewrite_value_types_in_terminator(terminator, name, ty);
        }
    }
}

fn rewrite_operation_result_type(kind: &mut MirOperationKind, ty: &MirType) {
    match kind {
        MirOperationKind::Copy { ty: result_ty, .. }
        | MirOperationKind::Add { ty: result_ty, .. }
        | MirOperationKind::Sub { ty: result_ty, .. }
        | MirOperationKind::Mul { ty: result_ty, .. }
        | MirOperationKind::FAdd { ty: result_ty, .. }
        | MirOperationKind::FSub { ty: result_ty, .. }
        | MirOperationKind::FMul { ty: result_ty, .. }
        | MirOperationKind::FDiv { ty: result_ty, .. }
        | MirOperationKind::And { ty: result_ty, .. }
        | MirOperationKind::Or { ty: result_ty, .. }
        | MirOperationKind::Xor { ty: result_ty, .. }
        | MirOperationKind::Shl { ty: result_ty, .. }
        | MirOperationKind::LShr { ty: result_ty, .. }
        | MirOperationKind::AShr { ty: result_ty, .. }
        | MirOperationKind::UDiv { ty: result_ty, .. }
        | MirOperationKind::SDiv { ty: result_ty, .. }
        | MirOperationKind::URem { ty: result_ty, .. }
        | MirOperationKind::SRem { ty: result_ty, .. }
        | MirOperationKind::RotateLeft { ty: result_ty, .. }
        | MirOperationKind::RotateRight { ty: result_ty, .. }
        | MirOperationKind::Select { ty: result_ty, .. }
        | MirOperationKind::Concat { ty: result_ty, .. }
        | MirOperationKind::Extract { ty: result_ty, .. }
        | MirOperationKind::Not { ty: result_ty, .. }
        | MirOperationKind::Neg { ty: result_ty, .. }
        | MirOperationKind::Popcount { ty: result_ty, .. }
        | MirOperationKind::CountLeadingZeros { ty: result_ty, .. }
        | MirOperationKind::CountTrailingZeros { ty: result_ty, .. }
        | MirOperationKind::Load { ty: result_ty, .. }
        | MirOperationKind::AddressOf { ty: result_ty, .. }
        | MirOperationKind::Cast { ty: result_ty, .. }
        | MirOperationKind::Icmp { ty: result_ty, .. }
        | MirOperationKind::Fcmp { ty: result_ty, .. } => *result_ty = ty.clone(),
        MirOperationKind::Call { result_types, .. }
        | MirOperationKind::Intrinsic { result_types, .. } => {
            if let Some(first) = result_types.first_mut() {
                *first = ty.clone();
            }
        }
        MirOperationKind::Store { .. } | MirOperationKind::MemoryCopy { .. } => {}
    }
}

fn rewrite_value_types_in_operation(kind: &mut MirOperationKind, name: &str, ty: &MirType) {
    match kind {
        MirOperationKind::Copy { value, .. }
        | MirOperationKind::Extract { value, .. }
        | MirOperationKind::Not { value, .. }
        | MirOperationKind::Neg { value, .. }
        | MirOperationKind::Popcount { value, .. }
        | MirOperationKind::CountLeadingZeros { value, .. }
        | MirOperationKind::CountTrailingZeros { value, .. }
        | MirOperationKind::Load { address: value, .. }
        | MirOperationKind::AddressOf { address: value, .. }
        | MirOperationKind::Cast { value, .. } => rewrite_named_value_type(value, name, ty),
        MirOperationKind::Add { lhs, rhs, .. }
        | MirOperationKind::Sub { lhs, rhs, .. }
        | MirOperationKind::Mul { lhs, rhs, .. }
        | MirOperationKind::FAdd { lhs, rhs, .. }
        | MirOperationKind::FSub { lhs, rhs, .. }
        | MirOperationKind::FMul { lhs, rhs, .. }
        | MirOperationKind::FDiv { lhs, rhs, .. }
        | MirOperationKind::And { lhs, rhs, .. }
        | MirOperationKind::Or { lhs, rhs, .. }
        | MirOperationKind::Xor { lhs, rhs, .. }
        | MirOperationKind::Shl { lhs, rhs, .. }
        | MirOperationKind::LShr { lhs, rhs, .. }
        | MirOperationKind::AShr { lhs, rhs, .. }
        | MirOperationKind::UDiv { lhs, rhs, .. }
        | MirOperationKind::SDiv { lhs, rhs, .. }
        | MirOperationKind::URem { lhs, rhs, .. }
        | MirOperationKind::SRem { lhs, rhs, .. }
        | MirOperationKind::RotateLeft { lhs, rhs, .. }
        | MirOperationKind::RotateRight { lhs, rhs, .. }
        | MirOperationKind::Icmp { lhs, rhs, .. }
        | MirOperationKind::Fcmp { lhs, rhs, .. } => {
            rewrite_named_value_type(lhs, name, ty);
            rewrite_named_value_type(rhs, name, ty);
        }
        MirOperationKind::Select {
            condition,
            when_true,
            when_false,
            ..
        } => {
            rewrite_named_value_type(condition, name, ty);
            rewrite_named_value_type(when_true, name, ty);
            rewrite_named_value_type(when_false, name, ty);
        }
        MirOperationKind::Concat { parts, .. }
        | MirOperationKind::Intrinsic {
            arguments: parts, ..
        } => {
            for part in parts {
                rewrite_named_value_type(part, name, ty);
            }
        }
        MirOperationKind::Store { address, value, .. } => {
            rewrite_named_value_type(address, name, ty);
            rewrite_named_value_type(value, name, ty);
        }
        MirOperationKind::MemoryCopy {
            src_address,
            dst_address,
            count,
            decrement,
            ..
        } => {
            rewrite_named_value_type(src_address, name, ty);
            rewrite_named_value_type(dst_address, name, ty);
            rewrite_named_value_type(count, name, ty);
            rewrite_named_value_type(decrement, name, ty);
        }
        MirOperationKind::Call {
            target, arguments, ..
        } => {
            match target {
                MirControlTarget::FunctionIndirect(value)
                | MirControlTarget::BlockIndirect(value) => {
                    rewrite_named_value_type(value, name, ty)
                }
                MirControlTarget::Direct(_) => {}
            }
            for argument in arguments {
                rewrite_named_value_type(argument, name, ty);
            }
        }
    }
}

fn rewrite_value_types_in_terminator(
    terminator: &mut crate::ir::mir::MirTerminator,
    name: &str,
    ty: &MirType,
) {
    match terminator {
        crate::ir::mir::MirTerminator::Jump { target, arguments } => {
            rewrite_control_target_value_type(target, name, ty);
            for argument in arguments {
                rewrite_named_value_type(argument, name, ty);
            }
        }
        crate::ir::mir::MirTerminator::CondBr {
            condition,
            then_target,
            then_arguments,
            else_target,
            else_arguments,
        } => {
            rewrite_named_value_type(condition, name, ty);
            rewrite_control_target_value_type(then_target, name, ty);
            rewrite_control_target_value_type(else_target, name, ty);
            for argument in then_arguments {
                rewrite_named_value_type(argument, name, ty);
            }
            for argument in else_arguments {
                rewrite_named_value_type(argument, name, ty);
            }
        }
        crate::ir::mir::MirTerminator::Return { values } => {
            for value in values {
                rewrite_named_value_type(value, name, ty);
            }
        }
        crate::ir::mir::MirTerminator::Trap | crate::ir::mir::MirTerminator::Unreachable => {}
    }
}

fn rewrite_control_target_value_type(target: &mut MirControlTarget, name: &str, ty: &MirType) {
    match target {
        MirControlTarget::FunctionIndirect(value) | MirControlTarget::BlockIndirect(value) => {
            rewrite_named_value_type(value, name, ty);
        }
        MirControlTarget::Direct(_) => {}
    }
}

fn rewrite_named_value_type(value: &mut MirValue, name: &str, ty: &MirType) {
    if let MirValue::Named {
        name: value_name,
        ty: value_ty,
    } = value
        && value_name == name
    {
        *value_ty = ty.clone();
    }
}

fn merge_observed_type(slot: &mut Option<MirType>, ty: MirType) {
    match slot {
        None => *slot = Some(ty),
        Some(existing) if *existing == ty => {}
        Some(existing) => merge_mir_type(existing, ty),
    }
}

fn merge_mir_type(existing: &mut MirType, ty: MirType) {
    match (existing, ty) {
        (MirType::Integer(existing_bits), MirType::Integer(bits)) => {
            *existing_bits = (*existing_bits).max(bits);
        }
        (MirType::Float(existing_bits), MirType::Float(bits)) => {
            *existing_bits = (*existing_bits).max(bits);
        }
        (MirType::Pointer { pointee: existing }, MirType::Pointer { pointee }) => {
            merge_mir_type(existing.as_mut(), *pointee);
        }
        (
            MirType::Function {
                parameters: existing_parameters,
                returns: existing_returns,
            },
            MirType::Function {
                parameters,
                returns,
            },
        ) => {
            merge_mir_type_lists(existing_parameters, parameters);
            merge_mir_type_lists(existing_returns, returns);
        }
        (existing, ty) => {
            if matches!(existing, MirType::Void) {
                *existing = ty;
            }
        }
    }
}

fn merge_mir_type_lists(existing: &mut Vec<MirType>, incoming: Vec<MirType>) {
    if existing.len() < incoming.len() {
        existing.resize(incoming.len(), MirType::void());
    }
    for (index, ty) in incoming.into_iter().enumerate() {
        merge_mir_type(&mut existing[index], ty);
    }
}
