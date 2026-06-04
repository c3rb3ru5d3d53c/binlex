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
use crate::controlflow::Function;
use crate::controlflow::Graph;
use crate::controlflow::Reference;
use crate::embeddings::{Embedding, EmbeddingBackend};
use crate::genetics::Chromosome;
use crate::io::Stderr;
use crate::irs::lir::LirInstruction;
use crate::irs::lir::arm64::InstructionDetailArm64;
use crate::irs::lir::cil::InstructionDetailCil;
use crate::irs::lir::x86::InstructionDetailX86;
use crate::irs::lir::{
    LirDiagnostic, LirDiagnosticKind, LirEffect, LirEncoding, LirStatus, LirTerminator,
};
use crate::irs::llvm::LlvmModule;
#[cfg(not(target_os = "windows"))]
use crate::irs::vex::VexModule;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::ops::{Deref, DerefMut};
use std::sync::OnceLock;
use std::{collections::BTreeMap, collections::BTreeSet, io::Error};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Operand {
    pub kind: OperandKind,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum OperandKind {
    Register(RegisterOperand),
    Immediate(ImmediateOperand),
    Memory(MemoryOperand),
    Float(FloatOperand),
    Special(SpecialOperand),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RegisterOperand {
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ImmediateOperand {
    pub value: i128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MemoryOperand {
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: Option<i32>,
    pub displacement: i64,
    pub space: Option<String>,
    pub segment: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FloatOperand {
    pub value: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SpecialOperand {
    pub kind: String,
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone)]
pub struct InstructionDetail {
    pub kind: InstructionDetailKind,
}

#[derive(Clone)]
pub enum InstructionDetailKind {
    X86(InstructionDetailX86),
    Arm64(InstructionDetailArm64),
    Cil(InstructionDetailCil),
}

impl InstructionDetail {
    pub fn x86(detail: InstructionDetailX86) -> Self {
        Self {
            kind: InstructionDetailKind::X86(detail),
        }
    }

    pub fn arm64(detail: InstructionDetailArm64) -> Self {
        Self {
            kind: InstructionDetailKind::Arm64(detail),
        }
    }

    pub fn cil(detail: InstructionDetailCil) -> Self {
        Self {
            kind: InstructionDetailKind::Cil(detail),
        }
    }

    pub fn build_lir(self) -> LirInstruction {
        match self.kind {
            InstructionDetailKind::X86(view) => {
                let mut semantics =
                    crate::irs::lir::x86::build(view.clone()).unwrap_or_else(|| {
                        unsupported_fallthrough(
                            view.machine.to_string(),
                            view.address,
                            view.mnemonic.clone(),
                            view.operand_text.clone(),
                            view.bytes.clone(),
                            "x86 mnemonic not implemented",
                        )
                    });
                if semantics.encoding.is_none() {
                    semantics.encoding = Some(LirEncoding {
                        architecture: view.machine.to_string(),
                        mnemonic: view.mnemonic.clone(),
                        disassembly: match view.operand_text.clone() {
                            Some(op_str) if !op_str.is_empty() => {
                                format!("{} {}", view.mnemonic, op_str)
                            }
                            _ => view.mnemonic.clone(),
                        },
                        address: view.address,
                        bytes: view.bytes.clone(),
                    });
                }
                semantics
            }
            InstructionDetailKind::Arm64(view) => {
                let mut semantics =
                    crate::irs::lir::arm64::build(view.clone()).unwrap_or_else(|| {
                        unsupported_fallthrough(
                            view.machine.to_string(),
                            view.address,
                            view.mnemonic.clone(),
                            view.operand_text.clone(),
                            view.bytes.clone(),
                            "arm64 mnemonic not implemented",
                        )
                    });
                if semantics.encoding.is_none() {
                    semantics.encoding = Some(LirEncoding {
                        architecture: view.machine.to_string(),
                        mnemonic: view.mnemonic.clone(),
                        disassembly: match view.operand_text.clone() {
                            Some(op_str) if !op_str.is_empty() => {
                                format!("{} {}", view.mnemonic, op_str)
                            }
                            _ => view.mnemonic.clone(),
                        },
                        address: view.address,
                        bytes: view.bytes.clone(),
                    });
                }
                semantics
            }
            InstructionDetailKind::Cil(view) => {
                let mut semantics = crate::irs::lir::cil::build(view.clone());
                if semantics.encoding.is_none() {
                    semantics.encoding = Some(LirEncoding {
                        architecture: "cil".to_string(),
                        mnemonic: view.mnemonic.clone(),
                        disassembly: view.mnemonic.clone(),
                        address: view.address,
                        bytes: view.operand_bytes().to_vec(),
                    });
                }
                semantics
            }
        }
    }
}

pub struct InstructionRecord {
    // The instruction architecture
    pub architecture: Architecture,
    /// The configuration
    pub config: Configuration,
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
    /// Bit-level wildcard mask for the instruction chromosome, one byte per instruction byte.
    pub chromosome_mask: Vec<u8>,
    /// The signature pattern of the instruction.
    pub pattern: String,
    /// Indicates whether this instruction is a return instruction.
    pub is_return: bool,
    /// Indicates whether this instruction is a call instruction.
    pub is_call: bool,
    /// A set of callee function addresses for this instruction.
    pub functions: BTreeSet<u64>,
    /// Indicates whether this instruction is a jump instruction.
    pub is_jump: bool,
    /// Indicates whether this instruction is a conditional instruction.
    pub is_conditional: bool,
    /// Indicates whether this instruction is a trap instruction.
    pub is_trap: bool,
    /// Indicates whether this instruction uses an indirect control-flow target.
    pub has_indirect_target: bool,
    /// A set of addresses this instruction may jump or branch to.
    pub to: BTreeSet<u64>,
    /// The number of edges (connections) for this instruction.
    pub edges: usize,
    /// Stable decoded mnemonic for scripting and inspection.
    pub mnemonic: String,
    /// Canonical decoded disassembly text.
    pub disassembly: String,
    /// Normalized decoded operands.
    pub operands: Vec<Operand>,
    /// Decoded instruction detail captured for semantic lowering.
    pub instruction_detail: Option<InstructionDetail>,
    /// Optional canonical LIR bindings for later lifting.
    pub semantics: Option<LirInstruction>,
    prepared_semantics_cache: OnceLock<Result<LirInstruction, String>>,
}

impl Clone for InstructionRecord {
    fn clone(&self) -> Self {
        Self {
            architecture: self.architecture,
            config: self.config.clone(),
            address: self.address,
            is_prologue: self.is_prologue,
            is_block_start: self.is_block_start,
            is_function_start: self.is_function_start,
            bytes: self.bytes.clone(),
            chromosome_mask: self.chromosome_mask.clone(),
            pattern: self.pattern.clone(),
            is_return: self.is_return,
            is_call: self.is_call,
            functions: self.functions.clone(),
            is_jump: self.is_jump,
            is_conditional: self.is_conditional,
            is_trap: self.is_trap,
            has_indirect_target: self.has_indirect_target,
            to: self.to.clone(),
            edges: self.edges,
            mnemonic: self.mnemonic.clone(),
            disassembly: self.disassembly.clone(),
            operands: self.operands.clone(),
            instruction_detail: self.instruction_detail.clone(),
            semantics: self.semantics.clone(),
            prepared_semantics_cache: OnceLock::new(),
        }
    }
}

impl InstructionRecord {
    /// Creates a new instruction record with the specified address.
    ///
    /// # Arguments
    ///
    /// * `address` - The memory address of the instruction.
    ///
    /// # Returns
    ///
    /// Returns a new instruction record with default values for its properties.
    #[allow(dead_code)]
    pub fn create(address: u64, architecture: Architecture, config: Configuration) -> Self {
        Self {
            address,
            is_prologue: false,
            is_block_start: false,
            is_function_start: false,
            bytes: Vec::<u8>::new(),
            chromosome_mask: Vec::<u8>::new(),
            pattern: String::new(),
            is_call: false,
            is_return: false,
            functions: BTreeSet::<u64>::new(),
            is_conditional: false,
            is_jump: false,
            has_indirect_target: false,
            to: BTreeSet::<u64>::new(),
            edges: 0,
            is_trap: false,
            mnemonic: String::new(),
            disassembly: String::new(),
            operands: Vec::new(),
            instruction_detail: None,
            semantics: None,
            prepared_semantics_cache: OnceLock::new(),
            architecture,
            config,
        }
    }

    /// Retrieves the address of the instruction.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Retrieves the mnemonic of the instruction.
    pub fn mnemonic(&self) -> String {
        self.mnemonic.clone()
    }

    /// Retrieves the raw bytes of the instruction.
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Retrieves the disassembly text of the instruction.
    pub fn disassembly(&self) -> String {
        self.disassembly.clone()
    }

    /// Retrieves the normalized decoded operands of the instruction.
    pub fn operands(&self) -> Vec<Operand> {
        self.operands.clone()
    }

    /// Replaces the canonical LIR attached to this instruction.
    pub fn set_lir(&mut self, lir: LirInstruction) {
        let _ = self.prepared_semantics_cache.take();
        self.semantics = Some(lir);
    }

    pub fn prepared_semantics(&self) -> Result<Option<&LirInstruction>, Error> {
        let Some(semantics) = self.semantics.clone().or_else(|| self.build_semantics()) else {
            return Ok(None);
        };
        match self.prepared_semantics_cache.get_or_init(|| {
            crate::irs::llvm::prepare::prepare_instruction_semantics(&semantics)
                .map_err(|error| error.to_string())
        }) {
            Ok(prepared) => Ok(Some(prepared)),
            Err(message) => Err(Error::other(message.clone())),
        }
    }

    pub(crate) fn reset_prepared_semantics_cache(&mut self) {
        let _ = self.prepared_semantics_cache.take();
    }

    pub fn set_instruction_detail(&mut self, detail: InstructionDetail) {
        self.instruction_detail = Some(detail);
    }

    pub fn build_semantics(&self) -> Option<LirInstruction> {
        if let Some(detail) = self.instruction_detail.clone() {
            return Some(detail.build_lir());
        }
        self.fallthrough()
            .map(|_| self.unsupported_fallthrough_semantics("instruction detail unavailable"))
    }

    pub fn build_and_log_semantics(&self) -> Option<LirInstruction> {
        let semantics = self.build_semantics()?;
        log_semantics_debug(
            &self.config,
            self.address,
            &self.mnemonic,
            &self.disassembly,
            &self.bytes,
            &semantics,
        );
        Some(semantics)
    }

    fn unsupported_fallthrough_semantics(&self, message: &str) -> LirInstruction {
        LirInstruction {
            version: 1,
            status: LirStatus::Partial,
            metadata: Default::default(),
            abi: None,
            encoding: Some(LirEncoding {
                architecture: self.architecture.to_string(),
                mnemonic: self.mnemonic.clone(),
                disassembly: if self.disassembly.is_empty() {
                    self.mnemonic.clone()
                } else {
                    self.disassembly.clone()
                },
                address: self.address,
                bytes: self.bytes.clone(),
            }),
            temporaries: Vec::new(),
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
            diagnostics: vec![diagnostic(
                LirDiagnosticKind::UnsupportedInstruction,
                format!("0x{:x}: {} ({})", self.address, message, self.mnemonic),
            )],
        }
    }

    /// Retrieves the address of the next sequential instruction.
    ///
    /// # Returns
    ///
    /// Returns `Some(u64)` containing the address of the next instruction, or `None`
    /// if the current instruction is a return or trap instruction.
    pub fn fallthrough(&self) -> Option<u64> {
        if self.is_jump && !self.is_conditional {
            return None;
        }
        if self.is_return {
            return None;
        }
        if self.is_trap {
            return None;
        }
        Some(self.address + self.size() as u64)
    }

    /// Retrieves the set of explicit branch target addresses for this instruction.
    pub fn branches(&self) -> BTreeSet<u64> {
        self.to.clone()
    }

    /// Retrieves the full set of outgoing CFG successor addresses for this instruction.
    pub fn successors(&self) -> BTreeSet<u64> {
        let mut result = self.branches();
        if let Some(fallthrough) = self.fallthrough() {
            result.insert(fallthrough);
        }
        result
    }

    /// Retrieves the outgoing successor block references from this instruction.
    pub fn successor_block_references(&self) -> Vec<Reference> {
        let mut result = Vec::<Reference>::new();
        for block_address in self.successors() {
            result.push(Reference::new(self.address, block_address));
        }
        result.sort();
        result
    }

    /// Computes the size of the instruction in bytes.
    ///
    /// # Returns
    ///
    /// Returns the size of the instruction as a `usize`.
    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.bytes.len()
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
        let mask = if self.chromosome_mask.len() == self.bytes.len() {
            self.chromosome_mask.clone()
        } else {
            vec![0; self.bytes.len()]
        };
        Chromosome::new(self.bytes.clone(), mask, self.config.clone())
            .expect("failed to build instruction chromosome")
    }

    /// Retrieves the set of addresses this instruction may jump or branch to.
    ///
    /// # Returns
    ///
    /// Returns a `BTreeSet<u64>` containing the target addresses.
    /// Indicates whether this instruction uses an indirect control-flow target.
    pub fn has_indirect_target(&self) -> bool {
        self.has_indirect_target
    }

    /// Indicates whether this instruction is conditional.
    pub fn is_conditional(&self) -> bool {
        self.is_conditional
    }

    /// Retrieves the direct outgoing call references from this instruction.
    pub fn callee_references(&self) -> Vec<Reference> {
        let mut result = Vec::<Reference>::new();
        for function_address in &self.functions {
            result.push(Reference::new(self.address, *function_address));
        }
        result.sort();
        result
    }

    /// Retrieves the direct callee function addresses from this instruction.
    pub fn callees(&self) -> BTreeSet<u64> {
        self.functions.clone()
    }
}

#[derive(Clone)]
pub struct Instruction<'instruction> {
    pub cfg: &'instruction Graph,
    pub inner: InstructionRecord,
}

impl<'instruction> Deref for Instruction<'instruction> {
    type Target = InstructionRecord;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Instruction<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'instruction> From<Instruction<'instruction>> for InstructionRecord {
    fn from(value: Instruction<'instruction>) -> Self {
        value.inner
    }
}

impl<'instruction> Instruction<'instruction> {
    pub fn create(
        address: u64,
        architecture: Architecture,
        config: Configuration,
    ) -> InstructionRecord {
        InstructionRecord::create(address, architecture, config)
    }

    pub fn new(address: u64, cfg: &'instruction Graph) -> Result<Self, Error> {
        let inner = cfg
            .get_instruction_record(address)
            .ok_or_else(|| Error::other("instruction does not exist"))?;
        Ok(Self { cfg, inner })
    }

    pub fn into_record(self) -> InstructionRecord {
        self.inner
    }

    pub fn callees(&self) -> Vec<Function<'instruction>> {
        let mut result = Vec::<Function<'instruction>>::new();
        for reference in self.callee_references() {
            if let Ok(function) = Function::new(reference.address, self.cfg) {
                result.push(function);
            }
        }
        result
    }

    pub fn successor_blocks(&self) -> Vec<Block<'instruction>> {
        let mut result = Vec::<Block<'instruction>>::new();
        for reference in self.successor_block_references() {
            if let Ok(block) = Block::new(reference.address, self.cfg) {
                result.push(block);
            }
        }
        result
    }

    /// Return an embedding vector for this instruction using the default backend and dimensions.
    pub fn embedding(&self) -> Option<Vec<f32>> {
        self.embedding_with_options(None, None)
    }

    /// Return an embedding vector for this instruction using optional backend and dimension overrides.
    pub fn embedding_with_options(
        &self,
        backend: Option<EmbeddingBackend>,
        dimensions: Option<usize>,
    ) -> Option<Vec<f32>> {
        Embedding::new(self.architecture, self.config.clone(), backend, dimensions)
            .embed_instruction(self)
    }

    pub fn llvm(&self) -> Result<LlvmModule, Error> {
        if !self.config.instructions.lifters.llvm.enabled {
            return Err(Error::other("instruction llvm module is disabled"));
        }
        let mut lifter =
            LlvmModule::from_architecture_with_config(self.architecture, self.config.clone());
        lifter.populate_instruction(self)?;
        Ok(lifter)
    }

    #[cfg(not(target_os = "windows"))]
    pub fn vex(&self) -> Result<VexModule, Error> {
        let mut lifter = VexModule::with_config(None, self.config.clone());
        lifter.populate_instruction(self)?;
        Ok(lifter)
    }

    pub fn kind(&self) -> EntityKind {
        EntityKind::Instruction
    }
}

fn log_semantics_debug(
    config: &Configuration,
    address: u64,
    mnemonic: &str,
    disassembly: &str,
    bytes: &[u8],
    semantics: &LirInstruction,
) {
    let has_intrinsic_effect = semantics
        .effects
        .iter()
        .any(|effect| matches!(effect, LirEffect::Intrinsic { .. }));
    let intrinsic_effects = semantics
        .effects
        .iter()
        .filter_map(|effect| match effect {
            LirEffect::Intrinsic { name, .. } => Some(name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if semantics.status == LirStatus::Complete
        && semantics.diagnostics.is_empty()
        && !has_intrinsic_effect
    {
        return;
    }

    let bytes = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("");

    let summary = if semantics.diagnostics.is_empty() {
        format!(
            "no diagnostics; mnemonic={}; disassembly={}; bytes={}; effects={}; intrinsic_effects={}; terminator={:?}",
            mnemonic,
            disassembly,
            bytes,
            semantics.effects.len(),
            if intrinsic_effects.is_empty() {
                "none".to_string()
            } else {
                intrinsic_effects.join(",")
            },
            semantics.terminator.kind()
        )
    } else {
        format!(
            "mnemonic={}; disassembly={}; bytes={}; intrinsic_effects={}; {}",
            mnemonic,
            disassembly,
            bytes,
            if intrinsic_effects.is_empty() {
                "none".to_string()
            } else {
                intrinsic_effects.join(",")
            },
            semantics
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        )
    };

    Stderr::print_debug(
        config,
        format!(
            "0x{:x}: semantics status={:?}, diagnostics={}",
            address, semantics.status, summary
        ),
    );
}

fn diagnostic(kind: LirDiagnosticKind, message: impl Into<String>) -> LirDiagnostic {
    LirDiagnostic {
        kind,
        message: message.into(),
    }
}

fn unsupported_fallthrough(
    architecture: String,
    address: u64,
    mnemonic: String,
    operand_text: Option<String>,
    bytes: Vec<u8>,
    message: &str,
) -> LirInstruction {
    LirInstruction {
        version: 1,
        status: LirStatus::Partial,
        metadata: Default::default(),
        abi: None,
        encoding: Some(LirEncoding {
            architecture,
            mnemonic: mnemonic.clone(),
            disassembly: match operand_text {
                Some(op_str) if !op_str.is_empty() => format!("{} {}", mnemonic, op_str),
                _ => mnemonic.clone(),
            },
            address,
            bytes,
        }),
        temporaries: Vec::new(),
        effects: Vec::new(),
        terminator: LirTerminator::FallThrough,
        diagnostics: vec![diagnostic(
            LirDiagnosticKind::UnsupportedInstruction,
            format!("0x{:x}: {} ({})", address, message, mnemonic),
        )],
    }
}
