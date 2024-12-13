//                    GNU LESSER GENERAL PUBLIC LICENSE
//                        Version 3, 29 June 2007
//
//  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
//  Everyone is permitted to copy and distribute verbatim copies
//  of this license document, but changing it is not allowed.
//
//
//   This version of the GNU Lesser General Public License incorporates
// the terms and conditions of version 3 of the GNU General Public
// License, supplemented by the additional permissions listed below.
//
//   0. Additional Definitions.
//
//   As used herein, "this License" refers to version 3 of the GNU Lesser
// General Public License, and the "GNU GPL" refers to version 3 of the GNU
// General Public License.
//
//   "The Library" refers to a covered work governed by this License,
// other than an Application or a Combined Work as defined below.
//
//   An "Application" is any work that makes use of an interface provided
// by the Library, but which is not otherwise based on the Library.
// Defining a subclass of a class defined by the Library is deemed a mode
// of using an interface provided by the Library.
//
//   A "Combined Work" is a work produced by combining or linking an
// Application with the Library.  The particular version of the Library
// with which the Combined Work was made is also called the "Linked
// Version".
//
//   The "Minimal Corresponding Source" for a Combined Work means the
// Corresponding Source for the Combined Work, excluding any source code
// for portions of the Combined Work that, considered in isolation, are
// based on the Application, and not on the Linked Version.
//
//   The "Corresponding Application Code" for a Combined Work means the
// object code and/or source code for the Application, including any data
// and utility programs needed for reproducing the Combined Work from the
// Application, but excluding the System Libraries of the Combined Work.
//
//   1. Exception to Section 3 of the GNU GPL.
//
//   You may convey a covered work under sections 3 and 4 of this License
// without being bound by section 3 of the GNU GPL.
//
//   2. Conveying Modified Versions.
//
//   If you modify a copy of the Library, and, in your modifications, a
// facility refers to a function or data to be supplied by an Application
// that uses the facility (other than as an argument passed when the
// facility is invoked), then you may convey a copy of the modified
// version:
//
//    a) under this License, provided that you make a good faith effort to
//    ensure that, in the event an Application does not supply the
//    function or data, the facility still operates, and performs
//    whatever part of its purpose remains meaningful, or
//
//    b) under the GNU GPL, with none of the additional permissions of
//    this License applicable to that copy.
//
//   3. Object Code Incorporating Material from Library Header Files.
//
//   The object code form of an Application may incorporate material from
// a header file that is part of the Library.  You may convey such object
// code under terms of your choice, provided that, if the incorporated
// material is not limited to numerical parameters, data structure
// layouts and accessors, or small macros, inline functions and templates
// (ten or fewer lines in length), you do both of the following:
//
//    a) Give prominent notice with each copy of the object code that the
//    Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the object code with a copy of the GNU GPL and this license
//    document.
//
//   4. Combined Works.
//
//   You may convey a Combined Work under terms of your choice that,
// taken together, effectively do not restrict modification of the
// portions of the Library contained in the Combined Work and reverse
// engineering for debugging such modifications, if you also do each of
// the following:
//
//    a) Give prominent notice with each copy of the Combined Work that
//    the Library is used in it and that the Library and its use are
//    covered by this License.
//
//    b) Accompany the Combined Work with a copy of the GNU GPL and this license
//    document.
//
//    c) For a Combined Work that displays copyright notices during
//    execution, include the copyright notice for the Library among
//    these notices, as well as a reference directing the user to the
//    copies of the GNU GPL and this license document.
//
//    d) Do one of the following:
//
//        0) Convey the Minimal Corresponding Source under the terms of this
//        License, and the Corresponding Application Code in a form
//        suitable for, and under terms that permit, the user to
//        recombine or relink the Application with a modified version of
//        the Linked Version to produce a modified Combined Work, in the
//        manner specified by section 6 of the GNU GPL for conveying
//        Corresponding Source.
//
//        1) Use a suitable shared library mechanism for linking with the
//        Library.  A suitable mechanism is one that (a) uses at run time
//        a copy of the Library already present on the user's computer
//        system, and (b) will operate properly with a modified version
//        of the Library that is interface-compatible with the Linked
//        Version.
//
//    e) Provide Installation Information, but only if you would otherwise
//    be required to provide such information under section 6 of the
//    GNU GPL, and only to the extent that such information is
//    necessary to install and execute a modified version of the
//    Combined Work produced by recombining or relinking the
//    Application with a modified version of the Linked Version. (If
//    you use option 4d0, the Installation Information must accompany
//    the Minimal Corresponding Source and Corresponding Application
//    Code. If you use option 4d1, you must provide the Installation
//    Information in the manner specified by section 6 of the GNU GPL
//    for conveying Corresponding Source.)
//
//   5. Combined Libraries.
//
//   You may place library facilities that are a work based on the
// Library side by side in a single library together with other library
// facilities that are not Applications and are not covered by this
// License, and convey such a combined library under terms of your
// choice, if you do both of the following:
//
//    a) Accompany the combined library with a copy of the same work based
//    on the Library, uncombined with any other library facilities,
//    conveyed under the terms of this License.
//
//    b) Give prominent notice with the combined library that part of it
//    is a work based on the Library, and explaining where to find the
//    accompanying uncombined form of the same work.
//
//   6. Revised Versions of the GNU Lesser General Public License.
//
//   The Free Software Foundation may publish revised and/or new versions
// of the GNU Lesser General Public License from time to time. Such new
// versions will be similar in spirit to the present version, but may
// differ in detail to address new problems or concerns.
//
//   Each version is given a distinguishing version number. If the
// Library as you received it specifies that a certain numbered version
// of the GNU Lesser General Public License "or any later version"
// applies to it, you have the option of following the terms and
// conditions either of that published version or of any later version
// published by the Free Software Foundation. If the Library as you
// received it does not specify a version number of the GNU Lesser
// General Public License, you may choose any version of the GNU Lesser
// General Public License ever published by the Free Software Foundation.
//
//   If the Library as you received it specifies that a proxy can decide
// whether future versions of the GNU Lesser General Public License shall
// apply, that proxy's public statement of acceptance of any version is
// permanent authorization for you to choose that version for the
// Library.

use crate::Architecture;
use crate::controlflow::Instruction;
use crate::controlflow::InstructionJson;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::Error;
use std::io::ErrorKind;
use crate::binary::Binary;
use crate::controlflow::graph::Graph;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::hashing::SHA256;
use crate::hashing::TLSH;
use crate::hashing::MinHash32;
use crate::controlflow::Attributes;
use crate::genetics::ChromosomeSimilarity;

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

    /// Compares this block to another for similarity.
    ///
    /// # Returns
    ///
    /// Returns `Option<ChromosomeSimilarity>` representing the similarity between this block to another.
    pub fn compare(&self, rhs: &Block) -> Option<ChromosomeSimilarity> {
        self.chromosome().compare(&rhs.chromosome())
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
            prologue: self.is_prologue(),
            conditional: self.terminator.is_conditional,
            size: self.size(),
            bytes: Binary::to_hex(&self.bytes()),
            number_of_instructions: self.number_of_instructions(),
            instructions: self.instructions_json(),
            functions: self.functions(),
            entropy: self.entropy(),
            sha256: self.sha256(),
            minhash: self.minhash(),
            tlsh: self.tlsh(),
            contiguous: true,
            attributes: None,
        }
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
            let instruction = Instruction::new(*entry.key(), self.cfg)
                .expect("failed to retrieve instruction");
            result.push(instruction);
            if address >= self.terminator.address { break; }
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
        if !self.cfg.config.blocks.instructions.enabled { return result; }
        for entry in self.cfg.listing.range(self.address..){
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
        Chromosome::new(self.pattern(), self.cfg.config.clone()).unwrap().process()
    }

    /// Retrieves the pattern string representation of the chromosome.
    ///
    /// # Returns
    ///
    /// Returns a `Option<String>` containing the pattern representation of the chromosome.
    pub fn pattern(&self) -> String {
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
        if self.terminator.is_jump { return self.terminator.address + self.terminator.size() as u64; }
        if self.address == self.terminator.address { return self.terminator.address + self.terminator.size() as u64; }
        if self.terminator.is_block_start {return self.terminator.address; }
        if self.terminator.is_return { return self.terminator.address + self.terminator.size() as u64; }
        if let Some(next)= self.next() { return next; }
        return self.terminator.address;
    }

}
