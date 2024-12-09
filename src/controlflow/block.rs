use crate::Architecture;
use crate::controlflow::instruction::Instruction;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;
use std::io::ErrorKind;
use crate::binary::Binary;
use crate::controlflow::graph::Graph;
use crate::controlflow::Chromosome;
use crate::controlflow::ChromosomeJson;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use crate::hashing::MinHash32;
use crate::controlflow::Attributes;

/// Represents the JSON-serializable structure of a control flow block.
#[derive(Serialize, Deserialize)]
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
    /// The number of instructions in this block.
    pub number_of_instructions: usize,
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

/// Represents a control flow block within a graph.
#[derive(Clone)]
pub struct Block <'block>{
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
            return Err(Error::new(ErrorKind::Other, format!("Block -> 0x{:x}: is not valid", address)));
        }

        if !cfg.is_instruction_address(address) {
            return Err(Error::new(ErrorKind::Other, format!("Instruction -> 0x{:x}: is not valid", address)));
        }

        let mut terminator: Option<Instruction> = None;

        let previous_address: Option<u64> = None;
        for entry in cfg.listing.range(address..){
            let instruction = entry.value();
            if let Some(prev_addr) = previous_address{
                if instruction.address != prev_addr {
                    return Err(Error::new(ErrorKind::Other, format!("Block -> 0x{:x}: is not contiguous", address)));
                }
            }
            if instruction.is_jump
                || instruction.is_trap
                || instruction.is_return
                || (address != instruction.address && instruction.is_block_start) {
                terminator = Some(instruction.clone());
                break;
            }
        }

        if terminator.is_none() {
            return Err(Error::new(ErrorKind::Other, format!("Block -> 0x{:x}: has no end instruction", address)));
        }

        return Ok(Self {
            address: address,
            cfg: cfg,
            terminator: terminator.unwrap(),
        });
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
    pub fn process(&self) -> BlockJson {
        BlockJson {
            type_: "block".to_string(),
            address: self.address,
            architecture: self.architecture().to_string(),
            next: self.next(),
            to: self.terminator.to(),
            edges: self.edges(),
            chromosome: self.chromosome(),
            prologue: self.is_prologue(),
            conditional: self.terminator.is_conditional,
            size: self.size(),
            bytes: Binary::to_hex(&self.bytes()),
            number_of_instructions: self.number_of_instructions(),
            functions: self.functions(),
            entropy: self.entropy(),
            sha256: self.sha256(),
            minhash: self.minhash(),
            tlsh: self.tlsh(),
            contiguous: true,
            attributes: None,
        }
    }

    /// Processes the block into its JSON-serializable representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns a `BlockJson` instance containing the block's metadata and `Attributes`.
    pub fn process_with_attributes(&self, attributes: Attributes) -> BlockJson {
        let mut result = self.process();
        result.attributes = Some(attributes.process());
        return result;
    }

    /// Determines whether the block starts with a function prologue.
    ///
    /// # Returns
    ///
    /// Returns `true` if the block starts with a prologue; otherwise, `false`.
    pub fn is_prologue(&self) -> bool {
        if let Some(entry) =  self.cfg.listing.get(&self.address) {
            return entry.value().is_prologue;
        }
        return false;
    }

    /// Retrieves the number of edges (connections) this block has.
    ///
    /// # Returns
    ///
    /// Returns the number of edges as a `usize`.
    pub fn edges(&self) -> usize {
        return self.terminator.edges;
    }

    /// Retrieves the address of the next sequential block, if any.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the address of the next block if it is
    /// conditional or has specific ending conditions. Returns `None` otherwise.
    pub fn next(&self) -> Option<u64> {
        if !self.terminator.is_conditional { return None; }
        if self.terminator.address == self.address { return None; }
        if self.terminator.is_block_start { return Some(self.terminator.address); }
        if self.terminator.is_return { return None; }
        if self.terminator.is_trap { return None; }
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
        for item in self.to().iter().map(|ref_multi| *ref_multi).chain(self.next()) {
            result.insert(item);
        }
        result
    }

    /// Generates a signature for the block using its address range and control flow graph.
    ///
    /// # Returns
    ///
    /// Returns a `SignatureJson` representing the block's signature.
    pub fn chromosome(&self) -> ChromosomeJson {
        Chromosome::new(self.pattern(), self.cfg.config.clone()).unwrap().process()
    }

    /// Retrieves the pattern string representation of the chromosome.
    ///
    /// # Returns
    ///
    /// Returns a `Option<String>` containing the pattern representation of the chromosome.
    fn pattern(&self) -> String {
        let mut result = String::new();
        for entry in self.cfg.listing.range(self.address..self.address + self.size() as u64) {
            let instruction = entry.value();
            result += instruction.pattern.as_str();
        }
        return result;
    }

    /// Retrieves the function addresses associated with this block.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeMap<u64, u64>` where each key is an instruction address
    /// and each value is the address of the function containing that instruction.
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        for entry in self.cfg.listing.range(self.address..self.end()){
            let instruction = entry.value();
            for function_address in instruction.functions.clone() {
                result.insert(instruction.address, function_address);
            }
        }
        return result;
    }

    /// Computes the entropy of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if entropy calculation is disabled.
    pub fn entropy(&self) -> Option<f64> {
        if !self.cfg.config.blocks.heuristics.entropy.enabled { return None; }
        return Binary::entropy(&self.bytes());
    }

    /// Computes the TLSH of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the TLSH, or `None` if TLSH is disabled or the block size is too small.
    pub fn tlsh(&self) -> Option<String> {
        if !self.cfg.config.blocks.hashing.tlsh.enabled { return None; }
        return TLSH::new(&self.bytes(), self.cfg.config.blocks.hashing.tlsh.minimum_byte_size).hexdigest();
    }

    /// Computes the MinHash of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the MinHash, or `None` if MinHash is disabled or the block's size exceeds the configured maximum.
    pub fn minhash(&self) -> Option<String> {
        if !self.cfg.config.blocks.hashing.minhash.enabled { return None; }
        if self.bytes().len() > self.cfg.config.blocks.hashing.minhash.maximum_byte_size { return None; }
        return MinHash32::new(
            &self.bytes(),
            self.cfg.config.blocks.hashing.minhash.number_of_hashes,
            self.cfg.config.blocks.hashing.minhash.shingle_size,
            self.cfg.config.blocks.hashing.minhash.seed
        ).hexdigest();
    }

    /// Computes the SHA-256 hash of the block's bytes, if enabled.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hash, or `None` if SHA-256 is disabled.
    pub fn sha256(&self) -> Option<String> {
        if !self.cfg.config.blocks.hashing.sha256.enabled { return None; }
        return SHA256::new(&self.bytes()).hexdigest();
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
        for entry in self.cfg.listing.range(self.address..self.end()){
            let instruction = entry.value();
            result.extend(instruction.bytes.clone());
        }
        return result;
    }

    /// Counts the number of instructions in the block.
    ///
    /// # Returns
    ///
    /// Returns the number of instructions as a `usize`.
    pub fn number_of_instructions(&self) -> usize {
        let mut result: usize = 0;
        for _ in self.cfg.listing.range(self.address..=self.terminator.address){
            result += 1;
        }
        return result;
    }

    /// Retrieves the address of the block's last instruction.
    ///
    /// # Returns
    ///
    /// Returns the address as a `u64`.
    #[allow(dead_code)]
    pub fn end(&self) -> u64 {
        if self.address == self.terminator.address { return self.terminator.address + self.terminator.size() as u64; }
        if self.terminator.is_block_start {
            return self.terminator.address;
        }
        if self.terminator.is_return {
            return self.terminator.address + self.terminator.size() as u64;
        }
        if let Some(next)= self.next() {
            return next;
        }
        return self.terminator.address;
    }

}
