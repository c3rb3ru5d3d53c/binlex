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
use crate::controlflow::EntityKind;
use crate::controlflow::Function;
use crate::controlflow::Instruction;
use crate::controlflow::Reference;
use crate::controlflow::graph::Graph;
use crate::embeddings::{Embedding, EmbeddingBackend, EmbeddingsJson};
use crate::entropy;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::SSDeep;
use crate::hashing::TLSH;
use crate::hex;
use crate::ir::lir::{LirAbi, LirBlock, LirCpu};
use crate::ir::llvm::{Lifter as LlvmLifter, LiftersJson, LlvmJson};
use crate::ir::mir::MirBlock;
#[cfg(not(target_os = "windows"))]
use crate::ir::vex::{Lifter as VexLifter, VexJson};
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
    /// The kind of this entity, always `"block"`.
    pub kind: EntityKind,
    /// The architecture of the block.
    pub architecture: String,
    /// The starting address of the block.
    pub address: u64,
    /// The sequential fallthrough block address, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallthrough: Option<u64>,
    /// A set of explicit branch target block addresses.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub branches: BTreeSet<u64>,
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
    /// Direct outgoing call relationships from instructions in this block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub callee_references: Vec<Reference>,
    /// Direct outgoing control-flow relationships from this block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub successor_references: Vec<Reference>,
    /// Direct incoming control-flow relationships into this block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predecessor_references: Vec<Reference>,
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
    /// The ssdeep fuzzy hash of the block, if enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssdeep: Option<String>,
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
    /// Optional embeddings attached directly to this block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<EmbeddingsJson>,
    /// Attributes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Value>,
    /// Optional lifted representations attached to this block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifters: Option<LiftersJson>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct BlockJsonDeserializer {
    pub json: BlockJson,
    pub config: Configuration,
}

impl BlockJsonDeserializer {
    #[allow(dead_code)]
    pub fn new(string: String, config: Configuration) -> Result<Self, Error> {
        let json: BlockJson =
            serde_json::from_str(&string).map_err(|error| Error::other(format!("{}", error)))?;
        if json.kind != EntityKind::Block {
            return Err(Error::other("deserialized JSON is not a block kind"));
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
    pub fn successor_references(&self) -> Vec<Reference> {
        self.json.successor_references.clone()
    }

    #[allow(dead_code)]
    pub fn predecessor_references(&self) -> Vec<Reference> {
        self.json.predecessor_references.clone()
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
    pub fn ssdeep(&self) -> Option<String> {
        self.json.ssdeep.clone()
    }

    #[allow(dead_code)]
    pub fn callee_references(&self) -> Vec<Reference> {
        self.json.callee_references.clone()
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
    pub fn kind(&self) -> EntityKind {
        self.json.kind
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
    pub fn fallthrough(&self) -> Option<u64> {
        self.json.fallthrough
    }

    #[allow(dead_code)]
    pub fn branches(&self) -> BTreeSet<u64> {
        self.json.branches.clone()
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
    pub fn is_conditional(&self) -> bool {
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
    pub terminator: Instruction<'block>,
}

impl<'block> Block<'block> {
    fn payload_bytes_and_mask(&self) -> (Vec<u8>, Vec<u8>) {
        let mut raw_bytes = Vec::new();
        let mut wildcard_mask = Vec::new();
        for entry in self.cfg.listing.range(self.address..self.end()) {
            let instruction = entry.value();
            raw_bytes.extend_from_slice(&instruction.bytes);
            if instruction.chromosome_mask.len() == instruction.bytes.len() {
                wildcard_mask.extend_from_slice(&instruction.chromosome_mask);
            } else {
                wildcard_mask.extend(std::iter::repeat_n(0, instruction.bytes.len()));
            }
        }
        (raw_bytes, wildcard_mask)
    }

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
        let terminator_address = cfg.block_terminator_address(address).ok_or_else(|| {
            Error::other(format!("Block -> 0x{:x}: has no end instruction", address))
        })?;
        let terminator = Instruction::new(terminator_address, cfg).map_err(|_| {
            Error::other(format!("Block -> 0x{:x}: has no end instruction", address))
        })?;

        Ok(Self {
            address,
            cfg,
            terminator,
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

    pub fn lir(&self) -> Result<LirBlock, Error> {
        let instructions = self
            .instructions()
            .into_iter()
            .map(|instruction| {
                instruction
                    .semantics
                    .clone()
                    .or_else(|| instruction.build_semantics())
                    .ok_or_else(|| {
                        Error::other(format!(
                            "Block -> 0x{:x}: instruction 0x{:x} has no LIR",
                            self.address, instruction.address
                        ))
                    })
            })
            .collect::<Result<Vec<_>, Error>>()?;

        Ok(LirBlock {
            name: Some(format!("block_{:x}", self.address)),
            instructions,
        })
    }

    pub fn mir(&self) -> Result<MirBlock, Error> {
        let mut lir = self.lir()?;
        lir.optimize();
        MirBlock::from_lir(None, &lir).map_err(|error| Error::other(error.to_string()))
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
        self.process_base_with_references(
            self.successor_references(),
            self.predecessor_references(),
        )
    }

    pub fn process_base_with_references(
        &self,
        successor_references: Vec<Reference>,
        predecessor_references: Vec<Reference>,
    ) -> BlockJson {
        let (bytes, wildcard_mask) = self.payload_bytes_and_mask();
        let chromosome = Chromosome::new(bytes.clone(), wildcard_mask, self.cfg.config.clone())
            .expect("failed to build block chromosome");
        let size = bytes.len();
        let instructions = self.instruction_addresses();
        let callee_references = self.callee_references();
        let entropy = if self.cfg.config.blocks.entropy.enabled {
            entropy::shannon(&bytes)
        } else {
            None
        };
        let sha256 = if self.cfg.config.blocks.sha256.enabled {
            SHA256::new(&bytes).hexdigest()
        } else {
            None
        };
        let ssdeep = if self.cfg.config.blocks.ssdeep.enabled {
            SSDeep::new(&bytes).hexdigest()
        } else {
            None
        };
        let minhash = if self.cfg.config.blocks.minhash.enabled {
            if bytes.len() > self.cfg.config.blocks.minhash.maximum_byte_size
                && self.cfg.config.blocks.minhash.maximum_byte_size_enabled
            {
                None
            } else {
                MinHash32::new(
                    &bytes,
                    self.cfg.config.blocks.minhash.number_of_hashes,
                    self.cfg.config.blocks.minhash.shingle_size,
                    self.cfg.config.blocks.minhash.seed,
                )
                .hexdigest()
            }
        } else {
            None
        };
        let tlsh = if self.cfg.config.blocks.tlsh.enabled {
            TLSH::new(&bytes, self.cfg.config.blocks.tlsh.minimum_byte_size).hexdigest()
        } else {
            None
        };

        BlockJson {
            kind: EntityKind::Block,
            address: self.address,
            architecture: self.architecture().to_string(),
            fallthrough: self.fallthrough(),
            branches: self.branches(),
            edges: self.edges(),
            chromosome: chromosome.process(),
            conditional: self.terminator.is_conditional,
            size,
            bytes: hex::encode(&bytes),
            number_of_instructions: self.number_of_instructions(),
            instructions,
            callee_references,
            successor_references,
            predecessor_references,
            entropy,
            sha256,
            ssdeep,
            minhash,
            tlsh,
            contiguous: true,
            processors: None,
            embeddings: None,
            attributes: None,
            lifters: self.lifters_json(),
        }
    }

    pub fn process(&self) -> BlockJson {
        let mut json = self.process_base();
        self.apply_processors(&mut json);
        json
    }

    pub fn process_with_references(
        &self,
        successor_references: Vec<Reference>,
        predecessor_references: Vec<Reference>,
    ) -> BlockJson {
        let mut json =
            self.process_base_with_references(successor_references, predecessor_references);
        self.apply_processors(&mut json);
        json
    }

    fn apply_processors(&self, json: &mut BlockJson) {
        if crate::processor::enabled_processors_for_target(
            &self.cfg.config,
            crate::processor::ProcessorTarget::Graph,
        )
        .iter()
        .any(|processor| {
            self.cfg
                .processor_output(
                    crate::processor::ProcessorTarget::Block,
                    self.address,
                    processor.name(),
                )
                .is_none()
        }) {
            let _ = self.cfg.process_graph();
        }
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
        if self.cfg.config.blocks.embeddings.llvm.enabled {
            if let Some(vector) = self.embedding() {
                json.embeddings = Some(EmbeddingsJson::llvm(vector));
            }
        }
    }

    /// Return all processor outputs attached to this block.
    pub fn processors(&self) -> BTreeMap<String, Value> {
        self.process().processors.unwrap_or_default()
    }

    /// Return an embedding vector for this block using the default backend and dimensions.
    pub fn embedding(&self) -> Option<Vec<f32>> {
        self.embedding_with_options(None, None)
    }

    /// Return an embedding vector for this block using optional backend and dimension overrides.
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
        .embed_block(self)
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
        lifter.lift_block(self, abi)?;
        Ok(lifter)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn vex(&self, abi: Option<&LirAbi>) -> Result<VexLifter, Error> {
        let mut lifter = VexLifter::new(self.cfg.config.clone());
        lifter.lift_block(self, abi)?;
        Ok(lifter)
    }

    fn lifters_json(&self) -> Option<LiftersJson> {
        let llvm = if self.cfg.config.blocks.lifters.llvm.enabled {
            let mut lifter =
                LlvmLifter::from_architecture(self.architecture(), self.cfg.config.clone());
            lifter.lift_block(self, None).ok()?;
            Some(LlvmJson { text: lifter.ir() })
        } else {
            None
        };

        #[cfg(not(target_os = "windows"))]
        let vex =
            if self.cfg.config.lifters.vex.enabled && self.cfg.config.blocks.lifters.vex.enabled {
                let mut lifter = VexLifter::new(self.cfg.config.clone());
                lifter.lift_block(self, None).ok()?;
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

    /// Blocks are contiguous.
    pub fn contiguous(&self) -> bool {
        true
    }

    /// Retrives the instructions associated with the block.
    ///
    /// # Returns
    ///
    /// Returns a `Vec<Instruction>` representing the instructions associated with a block.
    pub fn instructions(&self) -> Vec<Instruction<'_>> {
        let mut result = Vec::<Instruction<'_>>::new();
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

    pub fn process_with_attributes_and_references(
        &self,
        attributes: Attributes,
        successor_references: Vec<Reference>,
        predecessor_references: Vec<Reference>,
    ) -> BlockJson {
        let mut result = self.process_with_references(successor_references, predecessor_references);
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
    pub fn fallthrough(&self) -> Option<u64> {
        if self.terminator.is_return {
            return None;
        }
        if self.terminator.is_trap {
            return None;
        }
        if self.terminator.is_jump && !self.terminator.is_conditional {
            return None;
        }
        if self.terminator.is_block_start && self.address != self.terminator.address {
            return Some(self.terminator.address);
        }
        self.terminator.fallthrough()
    }

    /// Retrieves the set of explicit branch target addresses for this block.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the target addresses.
    pub fn is_conditional(&self) -> bool {
        self.terminator.is_conditional
    }

    pub fn kind(&self) -> EntityKind {
        EntityKind::Block
    }

    pub fn branches(&self) -> BTreeSet<u64> {
        self.terminator.branches()
    }

    pub(crate) fn successor_addresses(&self) -> BTreeSet<u64> {
        self.cfg.block_successor_addresses(self.address)
    }

    /// Retrieves the direct outgoing control-flow references from this block.
    pub fn successor_references(&self) -> Vec<Reference> {
        self.successor_addresses()
            .into_iter()
            .map(|address| Reference::new(self.address, address))
            .collect()
    }

    /// Retrieves the direct incoming control-flow references into this block.
    pub fn predecessor_references(&self) -> Vec<Reference> {
        self.cfg
            .block_predecessor_addresses(self.address)
            .into_iter()
            .map(|address| Reference::new(address, self.address))
            .collect()
    }

    /// Retrieves the direct successor blocks.
    pub fn successors(&self) -> Vec<Block<'block>> {
        self.successor_addresses()
            .into_iter()
            .filter_map(|address| Block::new(address, self.cfg).ok())
            .collect()
    }

    /// Retrieves the direct predecessor blocks.
    pub fn predecessors(&self) -> Vec<Block<'block>> {
        self.predecessor_references()
            .into_iter()
            .filter_map(|reference| Block::new(reference.location, self.cfg).ok())
            .collect()
    }

    /// Retrieves a chromosome representing this block.
    ///
    /// # Returns
    ///
    /// Returns a `Chromosome` representing this block.
    pub fn chromosome(&self) -> Chromosome {
        let (raw_bytes, wildcard_mask) = self.payload_bytes_and_mask();
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

    /// Retrieves the direct outgoing call references from this block.
    pub fn callee_references(&self) -> Vec<Reference> {
        let mut result = Vec::<Reference>::new();
        for entry in self.cfg.listing.range(self.address..self.end()) {
            let instruction = entry.value();
            for function_address in instruction.functions.clone() {
                result.push(Reference::new(instruction.address, function_address));
            }
        }
        result.sort();
        result
    }

    /// Retrieves the directly called functions.
    pub fn callees(&self) -> Vec<Function<'block>> {
        let mut seen = BTreeSet::<u64>::new();
        let mut result = Vec::<Function<'block>>::new();
        for reference in self.callee_references() {
            if !seen.insert(reference.address) {
                continue;
            }
            if let Ok(function) = Function::new(reference.address, self.cfg) {
                result.push(function);
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

    /// Computes the ssdeep hash of the block's bytes.
    pub fn ssdeep(&self) -> Option<SSDeep<'static>> {
        Some(SSDeep::from_bytes(self.bytes()))
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
        self.payload_bytes_and_mask().0
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
        if let Some(next) = self.fallthrough() {
            return next;
        }
        self.terminator.address
    }
}
