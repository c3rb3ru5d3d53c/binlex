
use crate::Architecture;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;
use std::io::ErrorKind;
use crate::binary::Binary;
use crate::controlflow::Graph;
use crate::controlflow::GraphQueue;
use crate::controlflow::Block;
use crate::controlflow::Chromosome;
use crate::controlflow::ChromosomeJson;
use crate::controlflow::Attributes;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use crate::hashing::MinHash32;
use serde_json::Value;

/// Represents a JSON-serializable structure containing metadata about a function.
#[derive(Serialize, Deserialize)]
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
    /// The size of the function in bytes, if available.
    pub size: usize,
    /// The raw bytes of the function in hexadecimal format, if available.
    pub bytes: Option<String>,
    /// A map of functions associated with the function.
    pub functions: BTreeMap<u64, u64>,
    /// The set of blocks contained within the function.
    pub blocks: BTreeSet<u64>,
    /// The number of instructions in the function.
    pub number_of_instructions: usize,
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

/// Represents a control flow function within a graph.
#[derive(Clone)]
pub struct Function <'function>{
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
            return Err(Error::new(ErrorKind::Other, format!("Function -> 0x{:x}: is not valid", address)));
        }

        if !cfg.is_instruction_address(address) {
            return Err(Error::new(ErrorKind::Other, format!("Instruction -> 0x{:x}: is not valid", address)));
        }

        let mut blocks = BTreeMap::<u64, Block>::new();

        let mut queue = GraphQueue::new();

        queue.enqueue(address);

        while let Some(block_address) = queue.dequeue() {
            queue.insert_processed(block_address);
            if cfg.blocks.is_invalid(block_address) {
                return Err(Error::new(ErrorKind::Other, format!("Function -> 0x{:x} -> Block -> 0x{:x}: is invalid", address, block_address)));
            }
            if let Ok(block) = Block::new(block_address, &cfg) {
                queue.enqueue_extend(block.blocks());
                blocks.insert(block_address, block);
            }
        }

        return Ok(Self {
            address: address,
            cfg: cfg,
            blocks: blocks,
        });
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
        let nodes = self.blocks().len();
        let edges = self.edges();
        let components = 1;
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
            prologue: self.is_prologue(),
            chromosome: self.chromosome(),
            bytes: self.bytes_to_hex(),
            size: self.size(),
            functions: self.functions(),
            blocks: self.blocks(),
            number_of_instructions: self.number_of_instructions(),
            cyclomatic_complexity: self.cyclomatic_complexity(),
            average_instructions_per_block: self.average_instructions_per_block(),
            entropy: self.entropy(),
            sha256: self.sha256(),
            minhash: self.minhash(),
            tlsh: self.tlsh(),
            contiguous: self.is_contiguous(),
            architecture: self.architecture().to_string(),
            attributes: None,
        }
    }

    /// Processes the function into its JSON-serializable representation including `Attributes`
    ///
    /// # Returns
    ///
    /// Returns a `FunctionJson` instance containing the function's metadata and `Attributes`.
    pub fn process_with_attributes(&self, attributes: Attributes) -> FunctionJson {
        let mut result = self.process();
        result.attributes = Some(attributes.process());
        return result;
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
    /// Returns `Some(ChromosomeJson)` if the function is contiguous; otherwise, `None`.
    pub fn chromosome(&self) -> Option<ChromosomeJson> {
        if !self.is_contiguous() { return None; }
        let bytes = self.bytes();
        if bytes.is_none() { return None; }
        let pattern = self.pattern()?;
        let chromosome = Chromosome::new(pattern, self.cfg.config.clone()).ok()?;
        return Some(chromosome.process());
    }

    /// Retrieves the pattern string representation of the chromosome.
    ///
    /// # Returns
    ///
    /// Returns a `Option<String>` containing the pattern representation of the chromosome.
    fn pattern(&self) -> Option<String> {
        if !self.is_contiguous() { return None; }
        let mut result = String::new();
        for entry in self.cfg.listing.range(self.address..self.address + self.size() as u64) {
            let instruction = entry.value();
            result += instruction.pattern.as_str();
        }
        return Some(result);
    }

    /// Retrieves the total number of instructions in the function.
    ///
    /// # Returns
    ///
    /// Returns the number of instructions as a `usize`.
    pub fn number_of_instructions(&self) -> usize {
        let mut result: usize = 0;
        for (_, block) in &self.blocks {
            result += block.number_of_instructions();
        }
        result
    }

    /// Indicates whether this function starts with a prologue.
    ///
    /// # Returns
    ///
    /// Returns `true` if the function starts with a prologue; otherwise, `false`.
    pub fn is_prologue(&self) -> bool {
        if let Some((_, block)) = self.blocks.iter().next() {
            return block.is_prologue();
        }
        return false;
    }

    /// Retrieves the set of block addresses in the function.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the addresses of all blocks in the function.
    pub fn blocks(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::<u64>::new();
        for (block_address, _) in &self.blocks {
            result.insert(*block_address);
        }
        result
    }

    /// Retrieves the number of edges (connections) in the function.
    ///
    /// # Returns
    ///
    /// Returns the number of edges as a `usize`.
    pub fn edges(&self) -> usize {
        let mut result: usize = 0;
        for (_, block) in &self.blocks {
            result += block.edges();
        }
        result
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
        return None;
    }

    /// Retrieves the size of the function in bytes, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(usize)` if the function is contiguous; otherwise, `None`.
    pub fn size(&self) -> usize {
        let mut result: usize = 0;
        for (_, block) in &self.blocks {
            result += block.size();
        }
        result
    }

    /// Retrieves the address of the function's last instruction, if contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the address, or `None` if the function is not contiguous.
    pub fn end(&self) -> Option<u64> {
        if !self.is_contiguous() { return None; }
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
        if !self.is_contiguous() { return None; }
        let mut bytes = Vec::<u8>::new();
        let mut block_previous_end: Option<u64> = None;
        for (block_start_address, block) in &self.blocks {
            bytes.extend(block.bytes());
            if block.terminator.is_return { break; }
            if let Some(previous_end) = block_previous_end {
                if previous_end != *block_start_address {
                    return None;
                }
            }
            block_previous_end = Some(block.address + block.size() as u64);
        }
        Some(bytes)
    }

    /// Computes the SHA-256 hash of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the hash, or `None` if SHA-256 is disabled or the function is not contiguous.
    pub fn sha256(&self) -> Option<String> {
        if !self.cfg.config.functions.hashing.sha256.enabled { return None; }
        if !self.is_contiguous() { return None; }
        if let Some(bytes) = self.bytes() {
            return SHA256::new(&bytes).hexdigest();
        }
        return None;
    }

    /// Computes the entropy of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(f64)` containing the entropy, or `None` if entropy calculation is disabled or the function is not contiguous.
    pub fn entropy(&self) -> Option<f64> {
        if !self.cfg.config.functions.heuristics.entropy.enabled { return None; }
        if self.is_contiguous() {
            if let Some(bytes) = self.bytes() {
                return Binary::entropy(&bytes);
            }
            return None;
        }
        let mut entropi = Vec::<f64>::new();
        for (_, block) in &self.blocks {
            if let Some(entropy) = block.entropy() {
                entropi.push(entropy);
            }
        }
        if entropi.is_empty() { return Some(0.0); }
        Some(entropi.iter().sum::<f64>() / entropi.len() as f64)
    }

    /// Computes the TLSH of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the TLSH, or `None` if TLSH is disabled or the function is not contiguous.
    pub fn tlsh(&self) -> Option<String> {
        if !self.cfg.config.functions.hashing.tlsh.enabled { return None; }
        if !self.is_contiguous() { return None; }
        if let Some(bytes) = self.bytes() {
            return TLSH::new(&bytes, self.cfg.config.functions.hashing.tlsh.minimum_byte_size).hexdigest();
        }
        return None;
    }

    /// Computes the MinHash of the function's bytes, if enabled and contiguous.
    ///
    /// # Returns
    ///
    /// Returns `Some(String)` containing the MinHash, or `None` if MinHash is disabled or the function is not contiguous.
    pub fn minhash(&self) -> Option<String> {
        if !self.cfg.config.functions.hashing.minhash.enabled { return None; }
        if !self.is_contiguous() { return None; }
        if let Some(bytes) = self.bytes() {
            if bytes.len() > self.cfg.config.functions.hashing.minhash.maximum_byte_size { return None; }
            return MinHash32::new(
                &bytes,
                self.cfg.config.functions.hashing.minhash.number_of_hashes,
                self.cfg.config.functions.hashing.minhash.shingle_size,
                self.cfg.config.functions.hashing.minhash.seed).hexdigest();
        }
        return None;
    }

    /// Retrieves the functions associated with this function.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeMap<u64, u64>` containing function addresses.
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        let mut result = BTreeMap::<u64, u64>::new();
        for (_, block) in &self.blocks {
            result.extend(block.functions());
        }
        result
    }

    /// Checks whether the function is contiguous in memory.
    ///
    /// # Returns
    ///
    /// Returns `true` if the function is contiguous; otherwise, `false`.
    pub fn is_contiguous(&self) -> bool {
        let mut block_previous_end: Option<u64> = None;
        for (block_start_address, block) in &self.blocks {
            if let Some(previous_end) = block_previous_end {
                if previous_end != *block_start_address {
                    return false;
                }
            }
            block_previous_end = Some(block.address + block.size() as u64);
        }
        return true;
    }
}
