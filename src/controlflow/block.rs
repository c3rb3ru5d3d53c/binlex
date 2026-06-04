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
use crate::controlflow::EntityKind;
use crate::controlflow::Function;
use crate::controlflow::Instruction;
use crate::controlflow::Reference;
use crate::controlflow::graph::Graph;
use crate::embeddings::{Embedding, EmbeddingBackend};
use crate::entropy;
use crate::genetics::Chromosome;
use crate::hashing::MinHash32;
use crate::hashing::SHA256;
use crate::hashing::SSDeep;
use crate::hashing::TLSH;
use crate::irs::lir::LirBlock;
use crate::irs::llvm::LlvmModule;
use crate::irs::mir::MirBlock;
#[cfg(not(target_os = "windows"))]
use crate::irs::vex::VexModule;
use std::collections::BTreeSet;
use std::io::Error;

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
                    .lir
                    .clone()
                    .or_else(|| instruction.build_lir())
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

    pub fn llvm(&self) -> Result<LlvmModule, Error> {
        if !self.cfg.config.blocks.lifters.llvm.enabled {
            return Err(Error::other("block llvm module is disabled"));
        }
        let mut lifter =
            LlvmModule::from_architecture_with_config(self.architecture(), self.cfg.config.clone());
        lifter.populate_block(self, None)?;
        Ok(lifter)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn vex(&self) -> Result<VexModule, Error> {
        let mut lifter = VexModule::with_config(None, self.cfg.config.clone());
        lifter.populate_block(self)?;
        Ok(lifter)
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
