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

use std::{collections::BTreeSet, io::Error};
use crate::binary::Binary;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use std::io::ErrorKind;
use crate::controlflow::Graph;
use crate::controlflow::Attributes;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeJson;
use crate::genetics::ChromosomeSimilarity;
use crate::Config;
use crate::Architecture;

/// Represents a single instruction in disassembled binary code.
///
/// This struct encapsulates metadata and properties of an instruction,
/// such as its address, type, and relationships with other instructions.
#[derive(Clone)]
pub struct Instruction {
    // The instruction architecture
    pub architecture: Architecture,
    /// The configuration
    pub config: Config,
    /// The address of the instruction in memory.
    pub address: u64,
    /// Indicates whether this instruction is part of a function prologue.
    pub is_prologue: bool,
    /// Indicates whether this instruction is the start of a basic block.
    pub is_block_start: bool,
    /// Indicates whether this instruction is the start of a function.
    pub is_function_start: bool,
    /// The raw bytes of the instruction.
    pub bytes: Vec<u8>,
    /// The signature pattern of the instruction.
    pub pattern: String,
    /// Indicates whether this instruction is a return instruction.
    pub is_return: bool,
    /// Indicates whether this instruction is a call instruction.
    pub is_call: bool,
    /// A set of functions that this instruction may belong to.
    pub functions: BTreeSet<u64>,
    /// Indicates whether this instruction is a jump instruction.
    pub is_jump: bool,
    /// Indicates whether this instruction is a conditional instruction.
    pub is_conditional: bool,
    /// Indicates whether this instruction is a trap instruction.
    pub is_trap: bool,
    /// A set of addresses this instruction may jump or branch to.
    pub to: BTreeSet<u64>,
    /// The number of edges (connections) for this instruction.
    pub edges: usize,
}

/// Represents a JSON-serializable view of an `Instruction`.
#[derive(Serialize, Deserialize)]
pub struct InstructionJson {
    /// The type of this entity, always `"instruction"`.
    #[serde(rename = "type")]
    pub type_: String,
    // The architecture of the instruction.
    pub architecture: String,
    /// The address of the instruction in memory.
    pub address: u64,
    /// Indicates whether this instruction is part of a function prologue.
    pub is_prologue: bool,
    /// Indicates whether this instruction is the start of a basic block.
    pub is_block_start: bool,
    /// Indicates whether this instruction is the start of a function.
    pub is_function_start: bool,
    /// Indicates whether this instruction is a call instruction.
    pub is_call: bool,
    /// Indicates whether this instruction is a return instruction.
    pub is_return: bool,
    /// Indicates whether this instruction is a jump instruction.
    pub is_jump: bool,
    /// Indicates whether this instruction is a trap instruction.
    pub is_trap: bool,
    /// Indicates whether this instruction is conditional.
    pub is_conditional: bool,
    /// The number of edges (connections) for this instruction.
    pub edges: usize,
    /// The raw bytes of the instruction in hexadecimal format.
    pub bytes: String,
    /// The size of the instruction in bytes.
    pub size: usize,
    /// The chromosome
    pub chromosome: ChromosomeJson,
    /// A set of functions that this instruction may belong to.
    pub functions: BTreeSet<u64>,
    /// A set of addresses for the blocks this instruction may branch to.
    pub blocks: BTreeSet<u64>,
    /// A set of addresses this instruction may jump or branch to.
    pub to: BTreeSet<u64>,
    /// The address of the next sequential instruction, if any.
    pub next: Option<u64>,
    /// Attributes
    pub attributes: Option<Value>,
}

impl Instruction {
    /// Creates a new `Instruction` with the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address of the instruction.
    ///
    /// # Returns
    ///
    /// Returns a new `Instruction` with default values for its properties.
    #[allow(dead_code)]
    pub fn create(address: u64, architecture: Architecture, config: Config) -> Self {
        Self {
            address: address,
            is_prologue: false,
            is_block_start: false,
            is_function_start: false,
            bytes: Vec::<u8>::new(),
            pattern: String::new(),
            is_call: false,
            is_return: false,
            functions: BTreeSet::<u64>::new(),
            is_conditional: false,
            is_jump: false,
            to: BTreeSet::<u64>::new(),
            edges: 0,
            is_trap: false,
            architecture: architecture,
            config: config,
        }
    }

    /// Retrieves an `Instruction` from the control flow graph if available.
    ///
    /// # Returns
    ///
    /// Returns a `Result<Instruction, Error>` containing the `Instruction`.
    pub fn new(address: u64, cfg: &Graph) -> Result<Instruction, Error> {
        let instruction = cfg.get_instruction(address);
        if  instruction.is_none() { return Err(Error::new(ErrorKind::Other, format!("instruction does not exist"))); }
        Ok(instruction.unwrap())
    }

    /// Retrieves the set of addresses for the blocks this instruction may branch to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the block addresses.
    pub fn blocks(&self) -> BTreeSet<u64> {
        let mut result = BTreeSet::new();
        if !self.is_jump { return result; }
        for item in self.to.iter().map(|ref_multi| *ref_multi).chain(self.next()) {
            result.insert(item);
        }
        result
    }

    /// Compares this instruction to another for similarity.
    ///
    /// # Returns
    ///
    /// Returns `Option<ChromosomeSimilarity>` representing the similarity between this instruction to another.
    pub fn compare(&self, rhs: &Instruction) -> Option<ChromosomeSimilarity> {
        self.chromosome().compare(&rhs.chromosome())
    }

    /// Retrieves the address of the next sequential instruction.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the address of the next instruction, or `None`
    /// if the current instruction is a return or trap instruction.
    pub fn next(&self) -> Option<u64> {
        if self.is_jump && !self.is_conditional { return None; }
        if self.is_return { return None; }
        if self.is_trap { return None; }
        Some(self.address + self.size() as u64)
    }

    /// Computes the size of the instruction in bytes.
    ///
    /// # Returns
    ///
    /// Returns the size of the instruction as a `usize`.
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        return self.bytes.len();
    }

    /// Converts the `Instruction` into its JSON-serializable representation.
    ///
    /// # Returns
    ///
    /// Returns an `InstructionJson` struct containing the properties of the instruction.
    #[allow(dead_code)]
    pub fn process(&self) -> InstructionJson {
        InstructionJson {
            type_: "instruction".to_string(),
            architecture: self.architecture.to_string(),
            address: self.address,
            is_block_start: self.is_block_start,
            bytes: Binary::to_hex(&self.bytes),
            size: self.size(),
            chromosome: self.chromosome_json(),
            is_return: self.is_return,
            is_trap: self.is_trap,
            is_call: self.is_call,
            is_jump: self.is_jump,
            is_conditional: self.is_conditional,
            is_function_start: self.is_function_start,
            is_prologue: self.is_prologue,
            edges: self.edges,
            functions: self.functions(),
            blocks: self.blocks(),
            to: self.to(),
            next: self.next(),
            attributes: None,
        }
    }

    pub fn pattern(&self) -> String {
        self.pattern.clone()
    }

    /// Retrieves the chromosome representing the instruction.
    ///
    /// # Returns
    ///
    /// Returns a `Chromosome` represnting the instruction.
    pub fn chromosome(&self) -> Chromosome {
        Chromosome::new(self.pattern.clone(), self.config.clone())
            .expect("failed to parse instruction chromosome")
    }

    /// Retrieves the chromosome representing the instruction.
    ///
    /// # Returns
    ///
    /// Returns a `ChromosomeJson` representing the instruction.
    pub fn chromosome_json(&self) -> ChromosomeJson {
        Chromosome::new(self.pattern.clone(), self.config.clone())
        .expect("failed to parse instruction chromosome")
        .process()
    }

    /// Retrieves the set of addresses this instruction may jump or branch to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the target addresses.
    pub fn to(&self) -> BTreeSet<u64> {
       return self.to.clone();
    }

    /// Retrieves the set of functions this instruction may belong to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the function addresses.
    pub fn functions(&self) -> BTreeSet<u64> {
        return self.functions.clone();
    }

    /// Converts the instruction into a JSON string representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err` if serialization fails.
    pub fn json_with_attributes(&self, attributes: Attributes) -> Result<String, Error> {
        let raw = self.process_with_attributes(attributes);
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Processes the instruction into its JSON-serializable representation including `Attributes`.
    ///
    /// # Returns
    ///
    /// Returns a `BlockJson` instance containing the block's metadata and `Attributes`.
    pub fn process_with_attributes(&self, attributes: Attributes) -> InstructionJson {
        let mut result = self.process();
        result.attributes = Some(attributes.process());
        return result;
    }

    /// Converts the `Instruction` into a JSON string representation.
    ///
    /// # Returns
    ///
    /// Returns `Ok(String)` containing the JSON representation, or an `Err(Error)` if serialization fails.
    #[allow(dead_code)]
    pub fn json(&self) -> Result<String, Error> {
        let raw = self.process();
        let result = serde_json::to_string(&raw)?;
        Ok(result)
    }

    /// Prints the JSON representation of the `Instruction` to standard output.
    #[allow(dead_code)]
    pub fn print(&self) {
        if let Ok(json) = self.json() {
            println!("{}", json);
        }
    }
}
