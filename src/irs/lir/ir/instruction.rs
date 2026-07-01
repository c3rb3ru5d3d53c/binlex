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

use serde::{Deserialize, Serialize};

mod lir_const_value_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            String(String),
            Unsigned(u64),
            Signed(i64),
        }

        match Repr::deserialize(deserializer)? {
            Repr::String(value) => value.parse::<u128>().map_err(serde::de::Error::custom),
            Repr::Unsigned(value) => Ok(value as u128),
            Repr::Signed(value) => u128::try_from(value).map_err(serde::de::Error::custom),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirInstruction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    pub status: LirStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects: Vec<LirEffect>,
    pub terminator: LirTerminator,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirData {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirBlock {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub instructions: Vec<LirInstruction>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirFunction {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocks: Vec<LirBlock>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirModule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<LirFunction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<LirData>,
}

impl LirBlock {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            instructions: Vec::new(),
        }
    }

    pub fn address(&self) -> Option<u64> {
        self.instructions
            .iter()
            .find_map(|instruction| instruction.address())
    }

    pub fn instructions(&self) -> &[LirInstruction] {
        &self.instructions
    }

    pub fn instructions_mut(&mut self) -> &mut Vec<LirInstruction> {
        &mut self.instructions
    }

    pub fn append_instruction(&mut self, instruction: LirInstruction) {
        self.instructions.push(instruction);
    }

    pub fn text(&self) -> String {
        crate::irs::lir::format_lir_block(self)
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn ssa(&self) -> Self {
        crate::irs::lir::ssa_block_lir(self)
    }

    pub fn bytecode(&self) -> mlir::Result<Vec<u8>> {
        let mut module = LirModule::new(None);
        let mut function = LirFunction::new(None);
        function.append_block(self.clone());
        module.append_function(function);
        module.bytecode()
    }
}

impl LirFunction {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            blocks: Vec::new(),
        }
    }

    pub fn from_instructions(name: Option<String>, instructions: Vec<LirInstruction>) -> Self {
        let mut block = LirBlock::new(Some("block_0".to_string()));
        block.instructions = instructions;
        Self {
            name,
            blocks: vec![block],
        }
    }

    pub fn address(&self) -> Option<u64> {
        self.blocks.iter().find_map(|block| block.address())
    }

    pub fn blocks(&self) -> &[LirBlock] {
        &self.blocks
    }

    pub fn blocks_mut(&mut self) -> &mut Vec<LirBlock> {
        &mut self.blocks
    }

    pub fn instructions(&self) -> Vec<&LirInstruction> {
        self.blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .collect()
    }

    pub fn append_block(&mut self, block: LirBlock) {
        self.blocks.push(block);
    }

    pub fn text(&self) -> String {
        crate::irs::lir::format_lir_function(self)
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn ssa(&self) -> Self {
        crate::irs::lir::ssa_function_lir(self)
    }

    pub fn bytecode(&self) -> mlir::Result<Vec<u8>> {
        let mut module = LirModule::new(self.name.clone());
        module.append_function(self.clone());
        module.bytecode()
    }
}

impl LirModule {
    pub fn new(name: Option<String>) -> Self {
        Self {
            name,
            functions: Vec::new(),
            data: Vec::new(),
        }
    }

    pub fn from_instructions(instructions: Vec<LirInstruction>) -> Self {
        Self::from_instructions_with_data(instructions, Vec::new())
    }

    pub fn from_instructions_with_data(
        instructions: Vec<LirInstruction>,
        data: Vec<LirData>,
    ) -> Self {
        Self {
            name: None,
            functions: vec![LirFunction {
                name: None,
                blocks: vec![LirBlock {
                    name: None,
                    instructions,
                }],
            }],
            data,
        }
    }

    pub fn functions(&self) -> &[LirFunction] {
        &self.functions
    }

    pub fn functions_mut(&mut self) -> &mut Vec<LirFunction> {
        &mut self.functions
    }

    pub fn append_function(&mut self, function: LirFunction) {
        self.functions.push(function);
    }

    pub fn instructions(&self) -> Vec<&LirInstruction> {
        self.functions
            .iter()
            .flat_map(|function| function.instructions())
            .collect()
    }

    pub fn primary_function(&self) -> Option<&LirFunction> {
        self.functions.first()
    }

    pub fn data(&self) -> &[LirData] {
        &self.data
    }

    pub fn append_data(&mut self, data: LirData) {
        self.data.push(data);
    }

    pub fn text(&self) -> String {
        crate::irs::lir::format_lir_module(self)
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn ssa(&self) -> Self {
        crate::irs::lir::ssa_module_lir(self)
    }

    pub fn mlir(&self) -> mlir::Result<crate::irs::lir::LirMlirModule> {
        crate::irs::lir::LirMlirModule::from_lir(self)
    }

    pub fn from_text(text: &str) -> mlir::Result<crate::irs::lir::LirMlirModule> {
        crate::irs::lir::LirMlirModule::from_text(text)
    }

    pub fn from_bytecode(bytecode: &[u8]) -> mlir::Result<crate::irs::lir::LirMlirModule> {
        crate::irs::lir::LirMlirModule::from_bytecode(bytecode)
    }

    pub fn bytecode(&self) -> mlir::Result<Vec<u8>> {
        Ok(self.mlir()?.bytecode())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirStatus {
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirLocationKind {
    Register,
    Flag,
    ProgramCounter,
    Temporary,
    Memory,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirLocation {
    Register {
        name: String,
        bits: u16,
    },
    Flag {
        name: String,
        bits: u16,
    },
    ProgramCounter {
        bits: u16,
    },
    Temporary {
        id: u32,
        bits: u16,
    },
    Memory {
        space: LirAddressSpace,
        addr: Box<LirExpression>,
        bits: u16,
    },
    IndexedMemory {
        name: String,
        index: Box<LirExpression>,
        bits: u16,
    },
    StackMemory {
        name: String,
        offset: u32,
        bits: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirLocationRegister {
    pub name: String,
    pub bits: u16,
}

impl LirLocationRegister {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

impl From<LirLocationRegister> for LirLocation {
    fn from(value: LirLocationRegister) -> Self {
        Self::Register {
            name: value.name,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirLocationFlag {
    pub name: String,
    pub bits: u16,
}

impl LirLocationFlag {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

impl From<LirLocationFlag> for LirLocation {
    fn from(value: LirLocationFlag) -> Self {
        Self::Flag {
            name: value.name,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirLocationProgramCounter {
    pub bits: u16,
}

impl LirLocationProgramCounter {
    pub fn new(bits: u16) -> Self {
        Self { bits }
    }
}

impl From<LirLocationProgramCounter> for LirLocation {
    fn from(value: LirLocationProgramCounter) -> Self {
        Self::ProgramCounter { bits: value.bits }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirLocationTemporary {
    pub id: u32,
    pub bits: u16,
}

impl LirLocationTemporary {
    pub fn new(id: u32, bits: u16) -> Self {
        Self { id, bits }
    }
}

impl From<LirLocationTemporary> for LirLocation {
    fn from(value: LirLocationTemporary) -> Self {
        Self::Temporary {
            id: value.id,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirLocationMemory {
    pub space: LirAddressSpace,
    pub addr: LirExpression,
    pub bits: u16,
}

impl LirLocationMemory {
    pub fn new(space: LirAddressSpace, addr: LirExpression, bits: u16) -> Self {
        Self { space, addr, bits }
    }
}

impl From<LirLocationMemory> for LirLocation {
    fn from(value: LirLocationMemory) -> Self {
        Self::Memory {
            space: value.space,
            addr: Box::new(value.addr),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirLocationIndexedMemory {
    pub name: String,
    pub index: LirExpression,
    pub bits: u16,
}

impl LirLocationIndexedMemory {
    pub fn new(name: impl Into<String>, index: LirExpression, bits: u16) -> Self {
        Self {
            name: name.into(),
            index,
            bits,
        }
    }
}

impl From<LirLocationIndexedMemory> for LirLocation {
    fn from(value: LirLocationIndexedMemory) -> Self {
        Self::IndexedMemory {
            name: value.name,
            index: Box::new(value.index),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirLocationStackMemory {
    pub name: String,
    pub offset: u32,
    pub bits: u16,
}

impl LirLocationStackMemory {
    pub fn new(name: impl Into<String>, offset: u32, bits: u16) -> Self {
        Self {
            name: name.into(),
            offset,
            bits,
        }
    }
}

impl From<LirLocationStackMemory> for LirLocation {
    fn from(value: LirLocationStackMemory) -> Self {
        Self::StackMemory {
            name: value.name,
            offset: value.offset,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirAddressSpace {
    Default,
    State,
    Stack,
    Heap,
    Global,
    Io,
    CpuMemory { name: String },
    Segment { name: String },
    Named { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirEffect {
    Phi {
        dst: LirLocation,
        sources: Vec<LirPhiSource>,
    },
    Set {
        dst: LirLocation,
        expression: LirExpression,
    },
    Store {
        space: LirAddressSpace,
        addr: LirExpression,
        expression: LirExpression,
        bits: u16,
    },
    MemorySet {
        space: LirAddressSpace,
        addr: LirExpression,
        value: LirExpression,
        count: LirExpression,
        element_bits: u16,
        decrement: LirExpression,
    },
    MemoryCopy {
        src_space: LirAddressSpace,
        src_addr: LirExpression,
        dst_space: LirAddressSpace,
        dst_addr: LirExpression,
        count: LirExpression,
        element_bits: u16,
        decrement: LirExpression,
    },
    AtomicCmpXchg {
        space: LirAddressSpace,
        addr: LirExpression,
        expected: LirExpression,
        desired: LirExpression,
        bits: u16,
        observed: LirLocation,
    },
    WriteProperty {
        reference: LirExpression,
        name: String,
        expression: LirExpression,
        bits: u16,
    },
    WriteElement {
        reference: LirExpression,
        index: LirExpression,
        expression: LirExpression,
        bits: u16,
    },
    Push {
        stack: String,
        expression: LirExpression,
    },
    Pop {
        stack: String,
        dst: LirLocation,
    },
    Fence {
        kind: LirFenceKind,
    },
    Trap {
        kind: LirTrapKind,
    },
    Intrinsic {
        name: String,
        args: Vec<LirExpression>,
        outputs: Vec<LirLocation>,
    },
    Nop,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirPhiSource {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor: Option<u64>,
    pub value: LirExpression,
}

impl LirPhiSource {
    pub fn new(predecessor: Option<u64>, value: LirExpression) -> Self {
        Self { predecessor, value }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectPhi {
    pub dst: LirLocation,
    pub sources: Vec<LirPhiSource>,
}

impl LirEffectPhi {
    pub fn new(dst: LirLocation, sources: Vec<LirPhiSource>) -> Self {
        Self { dst, sources }
    }
}

impl From<LirEffectPhi> for LirEffect {
    fn from(value: LirEffectPhi) -> Self {
        Self::Phi {
            dst: value.dst,
            sources: value.sources,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectSet {
    pub dst: LirLocation,
    pub expression: LirExpression,
}

impl LirEffectSet {
    pub fn new(dst: LirLocation, expression: LirExpression) -> Self {
        Self { dst, expression }
    }
}

impl From<LirEffectSet> for LirEffect {
    fn from(value: LirEffectSet) -> Self {
        Self::Set {
            dst: value.dst,
            expression: value.expression,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectStore {
    pub space: LirAddressSpace,
    pub addr: LirExpression,
    pub expression: LirExpression,
    pub bits: u16,
}

impl LirEffectStore {
    pub fn new(
        space: LirAddressSpace,
        addr: LirExpression,
        expression: LirExpression,
        bits: u16,
    ) -> Self {
        Self {
            space,
            addr,
            expression,
            bits,
        }
    }
}

impl From<LirEffectStore> for LirEffect {
    fn from(value: LirEffectStore) -> Self {
        Self::Store {
            space: value.space,
            addr: value.addr,
            expression: value.expression,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectMemorySet {
    pub space: LirAddressSpace,
    pub addr: LirExpression,
    pub value: LirExpression,
    pub count: LirExpression,
    pub element_bits: u16,
    pub decrement: LirExpression,
}

impl LirEffectMemorySet {
    pub fn new(
        space: LirAddressSpace,
        addr: LirExpression,
        value: LirExpression,
        count: LirExpression,
        element_bits: u16,
        decrement: LirExpression,
    ) -> Self {
        Self {
            space,
            addr,
            value,
            count,
            element_bits,
            decrement,
        }
    }
}

impl From<LirEffectMemorySet> for LirEffect {
    fn from(value: LirEffectMemorySet) -> Self {
        Self::MemorySet {
            space: value.space,
            addr: value.addr,
            value: value.value,
            count: value.count,
            element_bits: value.element_bits,
            decrement: value.decrement,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectMemoryCopy {
    pub src_space: LirAddressSpace,
    pub src_addr: LirExpression,
    pub dst_space: LirAddressSpace,
    pub dst_addr: LirExpression,
    pub count: LirExpression,
    pub element_bits: u16,
    pub decrement: LirExpression,
}

impl LirEffectMemoryCopy {
    pub fn new(
        src_space: LirAddressSpace,
        src_addr: LirExpression,
        dst_space: LirAddressSpace,
        dst_addr: LirExpression,
        count: LirExpression,
        element_bits: u16,
        decrement: LirExpression,
    ) -> Self {
        Self {
            src_space,
            src_addr,
            dst_space,
            dst_addr,
            count,
            element_bits,
            decrement,
        }
    }
}

impl From<LirEffectMemoryCopy> for LirEffect {
    fn from(value: LirEffectMemoryCopy) -> Self {
        Self::MemoryCopy {
            src_space: value.src_space,
            src_addr: value.src_addr,
            dst_space: value.dst_space,
            dst_addr: value.dst_addr,
            count: value.count,
            element_bits: value.element_bits,
            decrement: value.decrement,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectAtomicCmpXchg {
    pub space: LirAddressSpace,
    pub addr: LirExpression,
    pub expected: LirExpression,
    pub desired: LirExpression,
    pub bits: u16,
    pub observed: LirLocation,
}

impl LirEffectAtomicCmpXchg {
    pub fn new(
        space: LirAddressSpace,
        addr: LirExpression,
        expected: LirExpression,
        desired: LirExpression,
        bits: u16,
        observed: LirLocation,
    ) -> Self {
        Self {
            space,
            addr,
            expected,
            desired,
            bits,
            observed,
        }
    }
}

impl From<LirEffectAtomicCmpXchg> for LirEffect {
    fn from(value: LirEffectAtomicCmpXchg) -> Self {
        Self::AtomicCmpXchg {
            space: value.space,
            addr: value.addr,
            expected: value.expected,
            desired: value.desired,
            bits: value.bits,
            observed: value.observed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectWriteProperty {
    pub reference: LirExpression,
    pub name: String,
    pub expression: LirExpression,
    pub bits: u16,
}

impl LirEffectWriteProperty {
    pub fn new(
        reference: LirExpression,
        name: impl Into<String>,
        expression: LirExpression,
        bits: u16,
    ) -> Self {
        Self {
            reference,
            name: name.into(),
            expression,
            bits,
        }
    }
}

impl From<LirEffectWriteProperty> for LirEffect {
    fn from(value: LirEffectWriteProperty) -> Self {
        Self::WriteProperty {
            reference: value.reference,
            name: value.name,
            expression: value.expression,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectWriteElement {
    pub reference: LirExpression,
    pub index: LirExpression,
    pub expression: LirExpression,
    pub bits: u16,
}

impl LirEffectWriteElement {
    pub fn new(
        reference: LirExpression,
        index: LirExpression,
        expression: LirExpression,
        bits: u16,
    ) -> Self {
        Self {
            reference,
            index,
            expression,
            bits,
        }
    }
}

impl From<LirEffectWriteElement> for LirEffect {
    fn from(value: LirEffectWriteElement) -> Self {
        Self::WriteElement {
            reference: value.reference,
            index: value.index,
            expression: value.expression,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectPush {
    pub stack: String,
    pub expression: LirExpression,
}

impl LirEffectPush {
    pub fn new(stack: impl Into<String>, expression: LirExpression) -> Self {
        Self {
            stack: stack.into(),
            expression,
        }
    }
}

impl From<LirEffectPush> for LirEffect {
    fn from(value: LirEffectPush) -> Self {
        Self::Push {
            stack: value.stack,
            expression: value.expression,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectPop {
    pub stack: String,
    pub dst: LirLocation,
}

impl LirEffectPop {
    pub fn new(stack: impl Into<String>, dst: LirLocation) -> Self {
        Self {
            stack: stack.into(),
            dst,
        }
    }
}

impl From<LirEffectPop> for LirEffect {
    fn from(value: LirEffectPop) -> Self {
        Self::Pop {
            stack: value.stack,
            dst: value.dst,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectFence {
    pub kind: LirFenceKind,
}

impl LirEffectFence {
    pub fn new(kind: LirFenceKind) -> Self {
        Self { kind }
    }
}

impl From<LirEffectFence> for LirEffect {
    fn from(value: LirEffectFence) -> Self {
        Self::Fence { kind: value.kind }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectTrap {
    pub kind: LirTrapKind,
}

impl LirEffectTrap {
    pub fn new(kind: LirTrapKind) -> Self {
        Self { kind }
    }
}

impl From<LirEffectTrap> for LirEffect {
    fn from(value: LirEffectTrap) -> Self {
        Self::Trap { kind: value.kind }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectIntrinsic {
    pub name: String,
    pub args: Vec<LirExpression>,
    pub outputs: Vec<LirLocation>,
}

impl LirEffectIntrinsic {
    pub fn new(
        name: impl Into<String>,
        args: Vec<LirExpression>,
        outputs: Vec<LirLocation>,
    ) -> Self {
        Self {
            name: name.into(),
            args,
            outputs,
        }
    }
}

impl From<LirEffectIntrinsic> for LirEffect {
    fn from(value: LirEffectIntrinsic) -> Self {
        Self::Intrinsic {
            name: value.name,
            args: value.args,
            outputs: value.outputs,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirEffectNop;

impl LirEffectNop {
    pub fn new() -> Self {
        Self
    }
}

impl From<LirEffectNop> for LirEffect {
    fn from(_: LirEffectNop) -> Self {
        Self::Nop
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirEffectKind {
    Phi,
    Set,
    Store,
    MemorySet,
    MemoryCopy,
    AtomicCmpXchg,
    WriteProperty,
    WriteElement,
    Push,
    Pop,
    Fence,
    Trap,
    Intrinsic,
    Nop,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirFenceKind {
    Acquire,
    Release,
    AcquireRelease,
    SequentiallyConsistent,
    Named { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirTrapKind {
    Breakpoint,
    DivideError,
    Overflow,
    InvalidOpcode,
    GeneralProtection,
    PageFault,
    AlignmentFault,
    Syscall,
    Interrupt,
    Named { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirTerminator {
    FallThrough,
    Jump {
        target: LirExpression,
    },
    Branch {
        condition: LirExpression,
        true_target: LirExpression,
        false_target: LirExpression,
    },
    Call {
        target: LirExpression,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        return_target: Option<LirExpression>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        does_return: Option<bool>,
    },
    Return {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expression: Option<LirExpression>,
    },
    Unreachable,
    Trap,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirTerminatorFallThrough;

impl LirTerminatorFallThrough {
    pub fn new() -> Self {
        Self
    }
}

impl From<LirTerminatorFallThrough> for LirTerminator {
    fn from(_: LirTerminatorFallThrough) -> Self {
        Self::FallThrough
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirTerminatorJump {
    pub target: LirExpression,
}

impl LirTerminatorJump {
    pub fn new(target: LirExpression) -> Self {
        Self { target }
    }
}

impl From<LirTerminatorJump> for LirTerminator {
    fn from(value: LirTerminatorJump) -> Self {
        Self::Jump {
            target: value.target,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirTerminatorBranch {
    pub condition: LirExpression,
    pub true_target: LirExpression,
    pub false_target: LirExpression,
}

impl LirTerminatorBranch {
    pub fn new(
        condition: LirExpression,
        true_target: LirExpression,
        false_target: LirExpression,
    ) -> Self {
        Self {
            condition,
            true_target,
            false_target,
        }
    }
}

impl From<LirTerminatorBranch> for LirTerminator {
    fn from(value: LirTerminatorBranch) -> Self {
        Self::Branch {
            condition: value.condition,
            true_target: value.true_target,
            false_target: value.false_target,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirTerminatorCall {
    pub target: LirExpression,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_target: Option<LirExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub does_return: Option<bool>,
}

impl LirTerminatorCall {
    pub fn new(
        target: LirExpression,
        return_target: Option<LirExpression>,
        does_return: Option<bool>,
    ) -> Self {
        Self {
            target,
            return_target,
            does_return,
        }
    }
}

impl From<LirTerminatorCall> for LirTerminator {
    fn from(value: LirTerminatorCall) -> Self {
        Self::Call {
            target: value.target,
            return_target: value.return_target,
            does_return: value.does_return,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirTerminatorReturn {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<LirExpression>,
}

impl LirTerminatorReturn {
    pub fn new(expression: Option<LirExpression>) -> Self {
        Self { expression }
    }
}

impl From<LirTerminatorReturn> for LirTerminator {
    fn from(value: LirTerminatorReturn) -> Self {
        Self::Return {
            expression: value.expression,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirTerminatorUnreachable;

impl LirTerminatorUnreachable {
    pub fn new() -> Self {
        Self
    }
}

impl From<LirTerminatorUnreachable> for LirTerminator {
    fn from(_: LirTerminatorUnreachable) -> Self {
        Self::Unreachable
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirTerminatorTrap;

impl LirTerminatorTrap {
    pub fn new() -> Self {
        Self
    }
}

impl From<LirTerminatorTrap> for LirTerminator {
    fn from(_: LirTerminatorTrap) -> Self {
        Self::Trap
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirTerminatorKind {
    FallThrough,
    Jump,
    Branch,
    Call,
    Return,
    Unreachable,
    Trap,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LirExpression {
    Const {
        #[serde(with = "lir_const_value_serde")]
        value: u128,
        bits: u16,
    },
    Function {
        name: String,
        bits: u16,
    },
    DataAddress {
        name: String,
        bits: u16,
    },
    AddressOf {
        location: Box<LirLocation>,
        bits: u16,
    },
    Read(Box<LirLocation>),
    Load {
        space: LirAddressSpace,
        addr: Box<LirExpression>,
        bits: u16,
    },
    Unary {
        op: LirOperationUnary,
        arg: Box<LirExpression>,
        bits: u16,
    },
    Binary {
        op: LirOperationBinary,
        left: Box<LirExpression>,
        right: Box<LirExpression>,
        bits: u16,
    },
    Cast {
        op: LirOperationCast,
        arg: Box<LirExpression>,
        bits: u16,
    },
    Compare {
        op: LirOperationCompare,
        left: Box<LirExpression>,
        right: Box<LirExpression>,
        bits: u16,
    },
    Select {
        condition: Box<LirExpression>,
        when_true: Box<LirExpression>,
        when_false: Box<LirExpression>,
        bits: u16,
    },
    Extract {
        arg: Box<LirExpression>,
        lsb: u16,
        bits: u16,
    },
    Concat {
        parts: Vec<LirExpression>,
        bits: u16,
    },
    Undefined {
        bits: u16,
    },
    Poison {
        bits: u16,
    },
    Intrinsic {
        name: String,
        args: Vec<LirExpression>,
        bits: u16,
    },
    Null {
        bits: u16,
    },
    Allocate {
        kind: String,
        bits: u16,
    },
    ReadProperty {
        reference: Box<LirExpression>,
        name: String,
        bits: u16,
    },
    ReadElement {
        reference: Box<LirExpression>,
        index: Box<LirExpression>,
        bits: u16,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionConst {
    #[serde(with = "lir_const_value_serde")]
    pub value: u128,
    pub bits: u16,
}

impl LirExpressionConst {
    pub fn new(value: u128, bits: u16) -> Self {
        Self { value, bits }
    }
}

impl From<LirExpressionConst> for LirExpression {
    fn from(value: LirExpressionConst) -> Self {
        Self::Const {
            value: value.value,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionFunction {
    pub name: String,
    pub bits: u16,
}

impl LirExpressionFunction {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

impl From<LirExpressionFunction> for LirExpression {
    fn from(value: LirExpressionFunction) -> Self {
        Self::Function {
            name: value.name,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionDataAddress {
    pub name: String,
    pub bits: u16,
}

impl LirExpressionDataAddress {
    pub fn new(name: impl Into<String>, bits: u16) -> Self {
        Self {
            name: name.into(),
            bits,
        }
    }
}

impl From<LirExpressionDataAddress> for LirExpression {
    fn from(value: LirExpressionDataAddress) -> Self {
        Self::DataAddress {
            name: value.name,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionAddressOf {
    pub location: LirLocation,
    pub bits: u16,
}

impl LirExpressionAddressOf {
    pub fn new(location: LirLocation, bits: u16) -> Self {
        Self { location, bits }
    }
}

impl From<LirExpressionAddressOf> for LirExpression {
    fn from(value: LirExpressionAddressOf) -> Self {
        Self::AddressOf {
            location: Box::new(value.location),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionRead {
    pub location: LirLocation,
}

impl LirExpressionRead {
    pub fn new(location: LirLocation) -> Self {
        Self { location }
    }
}

impl From<LirExpressionRead> for LirExpression {
    fn from(value: LirExpressionRead) -> Self {
        Self::Read(Box::new(value.location))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionLoad {
    pub space: LirAddressSpace,
    pub addr: LirExpression,
    pub bits: u16,
}

impl LirExpressionLoad {
    pub fn new(space: LirAddressSpace, addr: LirExpression, bits: u16) -> Self {
        Self { space, addr, bits }
    }
}

impl From<LirExpressionLoad> for LirExpression {
    fn from(value: LirExpressionLoad) -> Self {
        Self::Load {
            space: value.space,
            addr: Box::new(value.addr),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionUnary {
    pub op: LirOperationUnary,
    pub arg: LirExpression,
    pub bits: u16,
}

impl LirExpressionUnary {
    pub fn new(op: LirOperationUnary, arg: LirExpression, bits: u16) -> Self {
        Self { op, arg, bits }
    }
}

impl From<LirExpressionUnary> for LirExpression {
    fn from(value: LirExpressionUnary) -> Self {
        Self::Unary {
            op: value.op,
            arg: Box::new(value.arg),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionBinary {
    pub op: LirOperationBinary,
    pub left: LirExpression,
    pub right: LirExpression,
    pub bits: u16,
}

impl LirExpressionBinary {
    pub fn new(
        op: LirOperationBinary,
        left: LirExpression,
        right: LirExpression,
        bits: u16,
    ) -> Self {
        Self {
            op,
            left,
            right,
            bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionCast {
    pub op: LirOperationCast,
    pub arg: LirExpression,
    pub bits: u16,
}

impl LirExpressionCast {
    pub fn new(op: LirOperationCast, arg: LirExpression, bits: u16) -> Self {
        Self { op, arg, bits }
    }
}

impl From<LirExpressionCast> for LirExpression {
    fn from(value: LirExpressionCast) -> Self {
        Self::Cast {
            op: value.op,
            arg: Box::new(value.arg),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionCompare {
    pub op: LirOperationCompare,
    pub left: LirExpression,
    pub right: LirExpression,
    pub bits: u16,
}

impl LirExpressionCompare {
    pub fn new(
        op: LirOperationCompare,
        left: LirExpression,
        right: LirExpression,
        bits: u16,
    ) -> Self {
        Self {
            op,
            left,
            right,
            bits,
        }
    }
}

impl From<LirExpressionCompare> for LirExpression {
    fn from(value: LirExpressionCompare) -> Self {
        Self::Compare {
            op: value.op,
            left: Box::new(value.left),
            right: Box::new(value.right),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionSelect {
    pub condition: LirExpression,
    pub when_true: LirExpression,
    pub when_false: LirExpression,
    pub bits: u16,
}

impl LirExpressionSelect {
    pub fn new(
        condition: LirExpression,
        when_true: LirExpression,
        when_false: LirExpression,
        bits: u16,
    ) -> Self {
        Self {
            condition,
            when_true,
            when_false,
            bits,
        }
    }
}

impl From<LirExpressionSelect> for LirExpression {
    fn from(value: LirExpressionSelect) -> Self {
        Self::Select {
            condition: Box::new(value.condition),
            when_true: Box::new(value.when_true),
            when_false: Box::new(value.when_false),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionExtract {
    pub arg: LirExpression,
    pub lsb: u16,
    pub bits: u16,
}

impl LirExpressionExtract {
    pub fn new(arg: LirExpression, lsb: u16, bits: u16) -> Self {
        Self { arg, lsb, bits }
    }
}

impl From<LirExpressionExtract> for LirExpression {
    fn from(value: LirExpressionExtract) -> Self {
        Self::Extract {
            arg: Box::new(value.arg),
            lsb: value.lsb,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionConcat {
    pub parts: Vec<LirExpression>,
    pub bits: u16,
}

impl LirExpressionConcat {
    pub fn new(parts: Vec<LirExpression>, bits: u16) -> Self {
        Self { parts, bits }
    }
}

impl From<LirExpressionConcat> for LirExpression {
    fn from(value: LirExpressionConcat) -> Self {
        Self::Concat {
            parts: value.parts,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionUndefined {
    pub bits: u16,
}

impl LirExpressionUndefined {
    pub fn new(bits: u16) -> Self {
        Self { bits }
    }
}

impl From<LirExpressionUndefined> for LirExpression {
    fn from(value: LirExpressionUndefined) -> Self {
        Self::Undefined { bits: value.bits }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionPoison {
    pub bits: u16,
}

impl LirExpressionPoison {
    pub fn new(bits: u16) -> Self {
        Self { bits }
    }
}

impl From<LirExpressionPoison> for LirExpression {
    fn from(value: LirExpressionPoison) -> Self {
        Self::Poison { bits: value.bits }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionIntrinsic {
    pub name: String,
    pub args: Vec<LirExpression>,
    pub bits: u16,
}

impl LirExpressionIntrinsic {
    pub fn new(name: impl Into<String>, args: Vec<LirExpression>, bits: u16) -> Self {
        Self {
            name: name.into(),
            args,
            bits,
        }
    }
}

impl From<LirExpressionIntrinsic> for LirExpression {
    fn from(value: LirExpressionIntrinsic) -> Self {
        Self::Intrinsic {
            name: value.name,
            args: value.args,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionNull {
    pub bits: u16,
}

impl LirExpressionNull {
    pub fn new(bits: u16) -> Self {
        Self { bits }
    }
}

impl From<LirExpressionNull> for LirExpression {
    fn from(value: LirExpressionNull) -> Self {
        Self::Null { bits: value.bits }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionAllocate {
    pub kind: String,
    pub bits: u16,
}

impl LirExpressionAllocate {
    pub fn new(kind: impl Into<String>, bits: u16) -> Self {
        Self {
            kind: kind.into(),
            bits,
        }
    }
}

impl From<LirExpressionAllocate> for LirExpression {
    fn from(value: LirExpressionAllocate) -> Self {
        Self::Allocate {
            kind: value.kind,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionReadProperty {
    pub reference: LirExpression,
    pub name: String,
    pub bits: u16,
}

impl LirExpressionReadProperty {
    pub fn new(reference: LirExpression, name: impl Into<String>, bits: u16) -> Self {
        Self {
            reference,
            name: name.into(),
            bits,
        }
    }
}

impl From<LirExpressionReadProperty> for LirExpression {
    fn from(value: LirExpressionReadProperty) -> Self {
        Self::ReadProperty {
            reference: Box::new(value.reference),
            name: value.name,
            bits: value.bits,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LirExpressionReadElement {
    pub reference: LirExpression,
    pub index: LirExpression,
    pub bits: u16,
}

impl LirExpressionReadElement {
    pub fn new(reference: LirExpression, index: LirExpression, bits: u16) -> Self {
        Self {
            reference,
            index,
            bits,
        }
    }
}

impl From<LirExpressionReadElement> for LirExpression {
    fn from(value: LirExpressionReadElement) -> Self {
        Self::ReadElement {
            reference: Box::new(value.reference),
            index: Box::new(value.index),
            bits: value.bits,
        }
    }
}

impl From<LirExpressionBinary> for LirExpression {
    fn from(value: LirExpressionBinary) -> Self {
        Self::Binary {
            op: value.op,
            left: Box::new(value.left),
            right: Box::new(value.right),
            bits: value.bits,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirExpressionKind {
    Const,
    Function,
    DataAddress,
    AddressOf,
    Read,
    Load,
    Unary,
    Binary,
    Cast,
    Compare,
    Select,
    Extract,
    Concat,
    Undefined,
    Poison,
    Intrinsic,
    Null,
    Allocate,
    ReadProperty,
    ReadElement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirOperationUnary {
    Not,
    Neg,
    BitReverse,
    ByteSwap,
    CountLeadingZeros,
    CountTrailingZeros,
    PopCount,
    Sqrt,
    Abs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirOperationBinary {
    Add,
    AddWithCarry,
    Sub,
    SubWithBorrow,
    Mul,
    FAdd,
    FSub,
    FMul,
    FDiv,
    UMulHigh,
    SMulHigh,
    UDiv,
    SDiv,
    URem,
    SRem,
    And,
    Or,
    Xor,
    Shl,
    LShr,
    AShr,
    RotateLeft,
    RotateRight,
    MinUnsigned,
    MinSigned,
    MaxUnsigned,
    MaxSigned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirOperationCast {
    ZeroExtend,
    SignExtend,
    Truncate,
    Bitcast,
    IntToFloat,
    UIntToFloat,
    FloatToInt,
    FloatToUInt,
    FloatExtend,
    FloatTruncate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirOperationCompare {
    Eq,
    Ne,
    Ult,
    Ule,
    Ugt,
    Uge,
    Slt,
    Sle,
    Sgt,
    Sge,
    Ordered,
    Unordered,
    Oeq,
    One,
    Olt,
    Ole,
    Ogt,
    Oge,
    Ueq,
    Une,
    UltFp,
    UleFp,
    UgtFp,
    UgeFp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LirOperation {
    Binary(LirOperationBinary),
    Unary(LirOperationUnary),
    Cast(LirOperationCast),
    Compare(LirOperationCompare),
}

impl LirInstruction {
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    pub fn set_address(&mut self, address: Option<u64>) {
        self.address = address;
    }

    pub fn set_status(&mut self, status: LirStatus) {
        self.status = status;
    }

    pub fn set_effects(&mut self, effects: Vec<LirEffect>) {
        self.effects = effects;
    }

    pub fn set_terminator(&mut self, terminator: LirTerminator) {
        self.terminator = terminator;
    }

    pub fn text(&self) -> String {
        crate::irs::lir::format_lir_instruction(self)
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn ssa(&self) -> Self {
        crate::irs::lir::ssa_instruction_lir(self)
    }

    pub fn bytecode(&self) -> mlir::Result<Vec<u8>> {
        LirModule::from_instructions(vec![self.clone()]).bytecode()
    }
}

impl LirLocation {
    pub fn kind(&self) -> LirLocationKind {
        match self {
            Self::Register { .. } => LirLocationKind::Register,
            Self::Flag { .. } => LirLocationKind::Flag,
            Self::ProgramCounter { .. } => LirLocationKind::ProgramCounter,
            Self::Temporary { .. } => LirLocationKind::Temporary,
            Self::Memory { .. } | Self::IndexedMemory { .. } | Self::StackMemory { .. } => {
                LirLocationKind::Memory
            }
        }
    }

    pub fn bits(&self) -> u16 {
        match self {
            Self::Register { bits, .. } => *bits,
            Self::Flag { bits, .. } => *bits,
            Self::ProgramCounter { bits } => *bits,
            Self::Temporary { bits, .. } => *bits,
            Self::Memory { bits, .. }
            | Self::IndexedMemory { bits, .. }
            | Self::StackMemory { bits, .. } => *bits,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Register { name, .. }
            | Self::Flag { name, .. }
            | Self::IndexedMemory { name, .. }
            | Self::StackMemory { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: LirLocationKind) {
        let bits = self.bits();
        *self = default_location_for_kind(kind, bits);
    }

    pub fn set_bits(&mut self, bits: u16) {
        match self {
            Self::Register { bits: current, .. }
            | Self::Flag { bits: current, .. }
            | Self::ProgramCounter { bits: current }
            | Self::Temporary { bits: current, .. }
            | Self::Memory { bits: current, .. }
            | Self::IndexedMemory { bits: current, .. }
            | Self::StackMemory { bits: current, .. } => *current = bits,
        }
    }

    pub fn set_name(&mut self, name: impl Into<String>) -> Result<(), &'static str> {
        match self {
            Self::Register { name: current, .. }
            | Self::Flag { name: current, .. }
            | Self::IndexedMemory { name: current, .. }
            | Self::StackMemory { name: current, .. } => {
                *current = name.into();
                Ok(())
            }
            _ => Err("location name is not valid for this location kind"),
        }
    }
}

impl LirEffect {
    pub fn text(&self) -> String {
        crate::irs::lir::format_lir_effect(self)
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }

    pub fn kind(&self) -> LirEffectKind {
        match self {
            Self::Phi { .. } => LirEffectKind::Phi,
            Self::Set { .. } => LirEffectKind::Set,
            Self::Store { .. } => LirEffectKind::Store,
            Self::MemorySet { .. } => LirEffectKind::MemorySet,
            Self::MemoryCopy { .. } => LirEffectKind::MemoryCopy,
            Self::AtomicCmpXchg { .. } => LirEffectKind::AtomicCmpXchg,
            Self::WriteProperty { .. } => LirEffectKind::WriteProperty,
            Self::WriteElement { .. } => LirEffectKind::WriteElement,
            Self::Push { .. } => LirEffectKind::Push,
            Self::Pop { .. } => LirEffectKind::Pop,
            Self::Fence { .. } => LirEffectKind::Fence,
            Self::Trap { .. } => LirEffectKind::Trap,
            Self::Intrinsic { .. } => LirEffectKind::Intrinsic,
            Self::Nop => LirEffectKind::Nop,
        }
    }

    pub fn expression(&self) -> Option<&LirExpression> {
        match self {
            Self::Phi { sources, .. } => sources.first().map(|source| &source.value),
            Self::Set { expression, .. } => Some(expression),
            Self::Store { expression, .. } => Some(expression),
            Self::MemorySet { value, .. } => Some(value),
            Self::AtomicCmpXchg { desired, .. } => Some(desired),
            Self::WriteProperty { expression, .. } | Self::WriteElement { expression, .. } => {
                Some(expression)
            }
            Self::Push { expression, .. } => Some(expression),
            _ => None,
        }
    }

    pub fn location(&self) -> Option<&LirLocation> {
        match self {
            Self::Phi { dst, .. } => Some(dst),
            Self::Set { dst, .. } => Some(dst),
            Self::AtomicCmpXchg { observed, .. } => Some(observed),
            Self::Pop { dst, .. } => Some(dst),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: LirEffectKind) {
        *self = default_effect_for_kind(kind);
    }

    pub fn set_expression(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Phi { sources, .. } => {
                if let Some(source) = sources.first_mut() {
                    source.value = expression;
                    Ok(())
                } else {
                    Err("phi effect has no source expression")
                }
            }
            Self::Set {
                expression: current,
                ..
            }
            | Self::Store {
                expression: current,
                ..
            }
            | Self::MemorySet { value: current, .. }
            | Self::AtomicCmpXchg {
                desired: current, ..
            }
            | Self::WriteProperty {
                expression: current,
                ..
            }
            | Self::WriteElement {
                expression: current,
                ..
            }
            | Self::Push {
                expression: current,
                ..
            } => {
                *current = expression;
                Ok(())
            }
            _ => Err("effect expression is not valid for this effect kind"),
        }
    }

    pub fn set_location(&mut self, location: LirLocation) -> Result<(), &'static str> {
        match self {
            Self::Phi { dst, .. } => {
                *dst = location;
                Ok(())
            }
            Self::Set { dst, .. } => {
                *dst = location;
                Ok(())
            }
            Self::AtomicCmpXchg { observed, .. } => {
                *observed = location;
                Ok(())
            }
            Self::Pop { dst, .. } => {
                *dst = location;
                Ok(())
            }
            _ => Err("effect location is not valid for this effect kind"),
        }
    }
}

impl LirTerminator {
    pub fn kind(&self) -> LirTerminatorKind {
        match self {
            Self::FallThrough => LirTerminatorKind::FallThrough,
            Self::Jump { .. } => LirTerminatorKind::Jump,
            Self::Branch { .. } => LirTerminatorKind::Branch,
            Self::Call { .. } => LirTerminatorKind::Call,
            Self::Return { .. } => LirTerminatorKind::Return,
            Self::Unreachable => LirTerminatorKind::Unreachable,
            Self::Trap => LirTerminatorKind::Trap,
        }
    }

    pub fn condition(&self) -> Option<&LirExpression> {
        match self {
            Self::Branch { condition, .. } => Some(condition),
            _ => None,
        }
    }

    pub fn true_target(&self) -> Option<&LirExpression> {
        match self {
            Self::Branch { true_target, .. } => Some(true_target),
            _ => None,
        }
    }

    pub fn false_target(&self) -> Option<&LirExpression> {
        match self {
            Self::Branch { false_target, .. } => Some(false_target),
            _ => None,
        }
    }

    pub fn target(&self) -> Option<&LirExpression> {
        match self {
            Self::Jump { target } | Self::Call { target, .. } => Some(target),
            _ => None,
        }
    }

    pub fn return_target(&self) -> Option<&LirExpression> {
        match self {
            Self::Call { return_target, .. } => return_target.as_ref(),
            _ => None,
        }
    }

    pub fn does_return(&self) -> Option<bool> {
        match self {
            Self::Call { does_return, .. } => *does_return,
            _ => None,
        }
    }

    pub fn return_expression(&self) -> Option<&LirExpression> {
        match self {
            Self::Return { expression } => expression.as_ref(),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: LirTerminatorKind) {
        *self = default_terminator_for_kind(kind);
    }

    pub fn set_condition(&mut self, condition: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Branch {
                condition: current, ..
            } => {
                *current = condition;
                Ok(())
            }
            _ => Err("terminator condition is only valid for branch terminators"),
        }
    }

    pub fn set_true_target(&mut self, target: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Branch {
                true_target: current,
                ..
            } => {
                *current = target;
                Ok(())
            }
            _ => Err("terminator true_target is only valid for branch terminators"),
        }
    }

    pub fn set_false_target(&mut self, target: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Branch {
                false_target: current,
                ..
            } => {
                *current = target;
                Ok(())
            }
            _ => Err("terminator false_target is only valid for branch terminators"),
        }
    }

    pub fn set_target(&mut self, target: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Jump { target: current }
            | Self::Call {
                target: current, ..
            } => {
                *current = target;
                Ok(())
            }
            _ => Err("terminator target is only valid for jump and call terminators"),
        }
    }

    pub fn set_return_target(
        &mut self,
        return_target: Option<LirExpression>,
    ) -> Result<(), &'static str> {
        match self {
            Self::Call {
                return_target: current,
                ..
            } => {
                *current = return_target;
                Ok(())
            }
            _ => Err("terminator return_target is only valid for call terminators"),
        }
    }

    pub fn set_does_return(&mut self, does_return: Option<bool>) -> Result<(), &'static str> {
        match self {
            Self::Call {
                does_return: current,
                ..
            } => {
                *current = does_return;
                Ok(())
            }
            _ => Err("terminator does_return is only valid for call terminators"),
        }
    }

    pub fn set_return_expression(
        &mut self,
        expression: Option<LirExpression>,
    ) -> Result<(), &'static str> {
        match self {
            Self::Return {
                expression: current,
            } => {
                *current = expression;
                Ok(())
            }
            _ => Err("terminator expression is only valid for return terminators"),
        }
    }
}

impl LirExpression {
    pub fn kind(&self) -> LirExpressionKind {
        match self {
            Self::Const { .. } => LirExpressionKind::Const,
            Self::Function { .. } => LirExpressionKind::Function,
            Self::DataAddress { .. } => LirExpressionKind::DataAddress,
            Self::AddressOf { .. } => LirExpressionKind::AddressOf,
            Self::Read(_) => LirExpressionKind::Read,
            Self::Load { .. } => LirExpressionKind::Load,
            Self::Unary { .. } => LirExpressionKind::Unary,
            Self::Binary { .. } => LirExpressionKind::Binary,
            Self::Cast { .. } => LirExpressionKind::Cast,
            Self::Compare { .. } => LirExpressionKind::Compare,
            Self::Select { .. } => LirExpressionKind::Select,
            Self::Extract { .. } => LirExpressionKind::Extract,
            Self::Concat { .. } => LirExpressionKind::Concat,
            Self::Undefined { .. } => LirExpressionKind::Undefined,
            Self::Poison { .. } => LirExpressionKind::Poison,
            Self::Intrinsic { .. } => LirExpressionKind::Intrinsic,
            Self::Null { .. } => LirExpressionKind::Null,
            Self::Allocate { .. } => LirExpressionKind::Allocate,
            Self::ReadProperty { .. } => LirExpressionKind::ReadProperty,
            Self::ReadElement { .. } => LirExpressionKind::ReadElement,
        }
    }

    pub fn operation(&self) -> Option<LirOperation> {
        match self {
            Self::Binary { op, .. } => Some(LirOperation::Binary(*op)),
            Self::Unary { op, .. } => Some(LirOperation::Unary(*op)),
            Self::Cast { op, .. } => Some(LirOperation::Cast(*op)),
            Self::Compare { op, .. } => Some(LirOperation::Compare(*op)),
            _ => None,
        }
    }

    pub fn bits(&self) -> u16 {
        match self {
            Self::Const { bits, .. } => *bits,
            Self::Function { bits, .. } => *bits,
            Self::DataAddress { bits, .. } => *bits,
            Self::AddressOf { bits, .. } => *bits,
            Self::Read(location) => location.bits(),
            Self::Load { bits, .. } => *bits,
            Self::Unary { bits, .. } => *bits,
            Self::Binary { bits, .. } => *bits,
            Self::Cast { bits, .. } => *bits,
            Self::Compare { bits, .. } => *bits,
            Self::Select { bits, .. } => *bits,
            Self::Extract { bits, .. } => *bits,
            Self::Concat { bits, .. } => *bits,
            Self::Undefined { bits } => *bits,
            Self::Poison { bits } => *bits,
            Self::Intrinsic { bits, .. } => *bits,
            Self::Null { bits } => *bits,
            Self::Allocate { bits, .. } => *bits,
            Self::ReadProperty { bits, .. } => *bits,
            Self::ReadElement { bits, .. } => *bits,
        }
    }

    pub fn left(&self) -> Option<&LirExpression> {
        match self {
            Self::Binary { left, .. } | Self::Compare { left, .. } => Some(left),
            _ => None,
        }
    }

    pub fn right(&self) -> Option<&LirExpression> {
        match self {
            Self::Binary { right, .. } | Self::Compare { right, .. } => Some(right),
            _ => None,
        }
    }

    pub fn argument(&self) -> Option<&LirExpression> {
        match self {
            Self::Unary { arg, .. }
            | Self::Cast { arg, .. }
            | Self::Extract { arg, .. }
            | Self::ReadProperty { reference: arg, .. } => Some(arg),
            _ => None,
        }
    }

    pub fn condition(&self) -> Option<&LirExpression> {
        match self {
            Self::Select { condition, .. } => Some(condition),
            _ => None,
        }
    }

    pub fn when_true(&self) -> Option<&LirExpression> {
        match self {
            Self::Select { when_true, .. } => Some(when_true),
            _ => None,
        }
    }

    pub fn when_false(&self) -> Option<&LirExpression> {
        match self {
            Self::Select { when_false, .. } => Some(when_false),
            _ => None,
        }
    }

    pub fn address(&self) -> Option<&LirExpression> {
        match self {
            Self::Load { addr, .. } => Some(addr),
            _ => None,
        }
    }

    pub fn address_space(&self) -> Option<&LirAddressSpace> {
        match self {
            Self::Load { space, .. } => Some(space),
            _ => None,
        }
    }

    pub fn location(&self) -> Option<&LirLocation> {
        match self {
            Self::Read(location) | Self::AddressOf { location, .. } => Some(location),
            _ => None,
        }
    }

    pub fn offset(&self) -> Option<u16> {
        match self {
            Self::Extract { lsb, .. } => Some(*lsb),
            _ => None,
        }
    }

    pub fn parts(&self) -> Option<&[LirExpression]> {
        match self {
            Self::Concat { parts, .. } => Some(parts),
            _ => None,
        }
    }

    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Function { name, .. }
            | Self::DataAddress { name, .. }
            | Self::Intrinsic { name, .. }
            | Self::Allocate { kind: name, .. }
            | Self::ReadProperty { name, .. } => Some(name.as_str()),
            _ => None,
        }
    }

    pub fn arguments(&self) -> Option<&[LirExpression]> {
        match self {
            Self::Intrinsic { args, .. } => Some(args),
            _ => None,
        }
    }

    pub fn value(&self) -> Option<u128> {
        match self {
            Self::Const { value, .. } => Some(*value),
            _ => None,
        }
    }

    pub fn set_kind(&mut self, kind: LirExpressionKind) {
        *self = default_expression_for_kind(kind, self.bits());
    }

    pub fn set_operation(&mut self, operation: LirOperation) -> Result<(), &'static str> {
        match (self, operation) {
            (Self::Binary { op, .. }, LirOperation::Binary(value)) => *op = value,
            (Self::Unary { op, .. }, LirOperation::Unary(value)) => *op = value,
            (Self::Cast { op, .. }, LirOperation::Cast(value)) => *op = value,
            (Self::Compare { op, .. }, LirOperation::Compare(value)) => *op = value,
            _ => return Err("expression operation does not match expression kind"),
        }
        Ok(())
    }

    pub fn set_bits(&mut self, bits: u16) {
        match self {
            Self::Const { bits: current, .. }
            | Self::Function { bits: current, .. }
            | Self::DataAddress { bits: current, .. }
            | Self::AddressOf { bits: current, .. }
            | Self::Load { bits: current, .. }
            | Self::Unary { bits: current, .. }
            | Self::Binary { bits: current, .. }
            | Self::Cast { bits: current, .. }
            | Self::Compare { bits: current, .. }
            | Self::Select { bits: current, .. }
            | Self::Extract { bits: current, .. }
            | Self::Concat { bits: current, .. }
            | Self::Undefined { bits: current }
            | Self::Poison { bits: current }
            | Self::Intrinsic { bits: current, .. }
            | Self::Null { bits: current }
            | Self::Allocate { bits: current, .. }
            | Self::ReadProperty { bits: current, .. }
            | Self::ReadElement { bits: current, .. } => *current = bits,
            Self::Read(location) => location.set_bits(bits),
        }
    }

    pub fn set_left(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Binary { left, .. } | Self::Compare { left, .. } => {
                *left = Box::new(expression);
                Ok(())
            }
            _ => Err("expression left operand is not valid for this expression kind"),
        }
    }

    pub fn set_right(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Binary { right, .. } | Self::Compare { right, .. } => {
                *right = Box::new(expression);
                Ok(())
            }
            _ => Err("expression right operand is not valid for this expression kind"),
        }
    }

    pub fn set_argument(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Unary { arg, .. }
            | Self::Cast { arg, .. }
            | Self::Extract { arg, .. }
            | Self::ReadProperty { reference: arg, .. } => {
                *arg = Box::new(expression);
                Ok(())
            }
            _ => Err("expression argument is not valid for this expression kind"),
        }
    }

    pub fn set_condition(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Select {
                condition: current, ..
            } => {
                *current = Box::new(expression);
                Ok(())
            }
            _ => Err("expression condition is not valid for this expression kind"),
        }
    }

    pub fn set_when_true(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Select {
                when_true: current, ..
            } => {
                *current = Box::new(expression);
                Ok(())
            }
            _ => Err("expression when_true is not valid for this expression kind"),
        }
    }

    pub fn set_when_false(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Select {
                when_false: current,
                ..
            } => {
                *current = Box::new(expression);
                Ok(())
            }
            _ => Err("expression when_false is not valid for this expression kind"),
        }
    }

    pub fn set_address(&mut self, expression: LirExpression) -> Result<(), &'static str> {
        match self {
            Self::Load { addr, .. } => {
                *addr = Box::new(expression);
                Ok(())
            }
            _ => Err("expression address is only valid for load expressions"),
        }
    }

    pub fn set_address_space(&mut self, space: LirAddressSpace) -> Result<(), &'static str> {
        match self {
            Self::Load { space: current, .. } => {
                *current = space;
                Ok(())
            }
            _ => Err("expression address_space is only valid for load expressions"),
        }
    }

    pub fn set_location(&mut self, location: LirLocation) -> Result<(), &'static str> {
        match self {
            Self::Read(current)
            | Self::AddressOf {
                location: current, ..
            } => {
                *current = Box::new(location);
                Ok(())
            }
            _ => Err("expression location is only valid for read and address_of expressions"),
        }
    }

    pub fn set_offset(&mut self, offset: u16) -> Result<(), &'static str> {
        match self {
            Self::Extract { lsb, .. } => {
                *lsb = offset;
                Ok(())
            }
            _ => Err("expression offset is only valid for extract expressions"),
        }
    }

    pub fn set_parts(&mut self, parts: Vec<LirExpression>) -> Result<(), &'static str> {
        match self {
            Self::Concat { parts: current, .. } => {
                *current = parts;
                Ok(())
            }
            _ => Err("expression parts are only valid for concat expressions"),
        }
    }

    pub fn set_name(&mut self, name: impl Into<String>) -> Result<(), &'static str> {
        match self {
            Self::Function { name: current, .. }
            | Self::DataAddress { name: current, .. }
            | Self::Intrinsic { name: current, .. } => {
                *current = name.into();
                Ok(())
            }
            _ => Err(
                "expression name is only valid for function, data_address, and intrinsic expressions",
            ),
        }
    }

    pub fn set_arguments(&mut self, arguments: Vec<LirExpression>) -> Result<(), &'static str> {
        match self {
            Self::Intrinsic { args, .. } => {
                *args = arguments;
                Ok(())
            }
            _ => Err("expression arguments are only valid for intrinsic expressions"),
        }
    }

    pub fn set_value(&mut self, value: u128) -> Result<(), &'static str> {
        match self {
            Self::Const { value: current, .. } => {
                *current = value;
                Ok(())
            }
            _ => Err("expression value is only valid for const expressions"),
        }
    }
}

fn default_const(bits: u16) -> LirExpression {
    LirExpression::Const { value: 0, bits }
}

fn default_location_for_kind(kind: LirLocationKind, bits: u16) -> LirLocation {
    match kind {
        LirLocationKind::Register => LirLocation::Register {
            name: "reg".to_string(),
            bits,
        },
        LirLocationKind::Flag => LirLocation::Flag {
            name: "flag".to_string(),
            bits,
        },
        LirLocationKind::ProgramCounter => LirLocation::ProgramCounter { bits },
        LirLocationKind::Temporary => LirLocation::Temporary { id: 0, bits },
        LirLocationKind::Memory => LirLocation::Memory {
            space: LirAddressSpace::Default,
            addr: Box::new(default_const(64)),
            bits,
        },
    }
}

fn default_expression_for_kind(kind: LirExpressionKind, bits: u16) -> LirExpression {
    match kind {
        LirExpressionKind::Const => LirExpression::Const { value: 0, bits },
        LirExpressionKind::Function => LirExpression::Function {
            name: String::new(),
            bits,
        },
        LirExpressionKind::DataAddress => LirExpression::DataAddress {
            name: String::new(),
            bits,
        },
        LirExpressionKind::AddressOf => LirExpression::AddressOf {
            location: Box::new(default_location_for_kind(LirLocationKind::Memory, 8)),
            bits,
        },
        LirExpressionKind::Read => LirExpression::Read(Box::new(default_location_for_kind(
            LirLocationKind::Temporary,
            bits,
        ))),
        LirExpressionKind::Load => LirExpression::Load {
            space: LirAddressSpace::Default,
            addr: Box::new(default_const(64)),
            bits,
        },
        LirExpressionKind::Unary => LirExpression::Unary {
            op: LirOperationUnary::Not,
            arg: Box::new(default_const(bits)),
            bits,
        },
        LirExpressionKind::Binary => LirExpression::Binary {
            op: LirOperationBinary::Add,
            left: Box::new(default_const(bits)),
            right: Box::new(default_const(bits)),
            bits,
        },
        LirExpressionKind::Cast => LirExpression::Cast {
            op: LirOperationCast::Bitcast,
            arg: Box::new(default_const(bits)),
            bits,
        },
        LirExpressionKind::Compare => LirExpression::Compare {
            op: LirOperationCompare::Eq,
            left: Box::new(default_const(bits)),
            right: Box::new(default_const(bits)),
            bits,
        },
        LirExpressionKind::Select => LirExpression::Select {
            condition: Box::new(default_const(1)),
            when_true: Box::new(default_const(bits)),
            when_false: Box::new(default_const(bits)),
            bits,
        },
        LirExpressionKind::Extract => LirExpression::Extract {
            arg: Box::new(default_const(bits)),
            lsb: 0,
            bits,
        },
        LirExpressionKind::Concat => LirExpression::Concat {
            parts: vec![default_const(bits)],
            bits,
        },
        LirExpressionKind::Undefined => LirExpression::Undefined { bits },
        LirExpressionKind::Poison => LirExpression::Poison { bits },
        LirExpressionKind::Intrinsic => LirExpression::Intrinsic {
            name: String::new(),
            args: Vec::new(),
            bits,
        },
        LirExpressionKind::Null => LirExpression::Null { bits },
        LirExpressionKind::Allocate => LirExpression::Allocate {
            kind: "object".to_string(),
            bits,
        },
        LirExpressionKind::ReadProperty => LirExpression::ReadProperty {
            reference: Box::new(LirExpression::Null { bits }),
            name: "property".to_string(),
            bits,
        },
        LirExpressionKind::ReadElement => LirExpression::ReadElement {
            reference: Box::new(LirExpression::Null { bits }),
            index: Box::new(default_const(bits)),
            bits,
        },
    }
}

fn default_effect_for_kind(kind: LirEffectKind) -> LirEffect {
    match kind {
        LirEffectKind::Phi => LirEffect::Phi {
            dst: default_location_for_kind(LirLocationKind::Temporary, 64),
            sources: vec![LirPhiSource::new(None, default_const(64))],
        },
        LirEffectKind::Set => LirEffect::Set {
            dst: default_location_for_kind(LirLocationKind::Temporary, 64),
            expression: default_const(64),
        },
        LirEffectKind::Store => LirEffect::Store {
            space: LirAddressSpace::Default,
            addr: default_const(64),
            expression: default_const(8),
            bits: 8,
        },
        LirEffectKind::MemorySet => LirEffect::MemorySet {
            space: LirAddressSpace::Default,
            addr: default_const(64),
            value: default_const(8),
            count: default_const(64),
            element_bits: 8,
            decrement: default_const(1),
        },
        LirEffectKind::MemoryCopy => LirEffect::MemoryCopy {
            src_space: LirAddressSpace::Default,
            src_addr: default_const(64),
            dst_space: LirAddressSpace::Default,
            dst_addr: default_const(64),
            count: default_const(64),
            element_bits: 8,
            decrement: default_const(1),
        },
        LirEffectKind::AtomicCmpXchg => LirEffect::AtomicCmpXchg {
            space: LirAddressSpace::Default,
            addr: default_const(64),
            expected: default_const(8),
            desired: default_const(8),
            bits: 8,
            observed: default_location_for_kind(LirLocationKind::Temporary, 8),
        },
        LirEffectKind::WriteProperty => LirEffect::WriteProperty {
            reference: LirExpression::Null { bits: 64 },
            name: "property".to_string(),
            expression: default_const(64),
            bits: 64,
        },
        LirEffectKind::WriteElement => LirEffect::WriteElement {
            reference: LirExpression::Null { bits: 64 },
            index: default_const(64),
            expression: default_const(64),
            bits: 64,
        },
        LirEffectKind::Push => LirEffect::Push {
            stack: "stack".to_string(),
            expression: default_const(64),
        },
        LirEffectKind::Pop => LirEffect::Pop {
            stack: "stack".to_string(),
            dst: default_location_for_kind(LirLocationKind::Temporary, 64),
        },
        LirEffectKind::Fence => LirEffect::Fence {
            kind: LirFenceKind::SequentiallyConsistent,
        },
        LirEffectKind::Trap => LirEffect::Trap {
            kind: LirTrapKind::Breakpoint,
        },
        LirEffectKind::Intrinsic => LirEffect::Intrinsic {
            name: String::new(),
            args: Vec::new(),
            outputs: Vec::new(),
        },
        LirEffectKind::Nop => LirEffect::Nop,
    }
}

fn default_terminator_for_kind(kind: LirTerminatorKind) -> LirTerminator {
    match kind {
        LirTerminatorKind::FallThrough => LirTerminator::FallThrough,
        LirTerminatorKind::Jump => LirTerminator::Jump {
            target: default_const(64),
        },
        LirTerminatorKind::Branch => LirTerminator::Branch {
            condition: default_const(1),
            true_target: default_const(64),
            false_target: default_const(64),
        },
        LirTerminatorKind::Call => LirTerminator::Call {
            target: default_const(64),
            return_target: None,
            does_return: None,
        },
        LirTerminatorKind::Return => LirTerminator::Return { expression: None },
        LirTerminatorKind::Unreachable => LirTerminator::Unreachable,
        LirTerminatorKind::Trap => LirTerminator::Trap,
    }
}

#[cfg(test)]
mod tests {
    use super::{LirBlock, LirExpression, LirFunction, LirInstruction, LirStatus, LirTerminator};

    fn instruction(address: Option<u64>) -> LirInstruction {
        LirInstruction {
            address,
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::FallThrough,
        }
    }

    #[test]
    fn lir_instruction_address_returns_stored_address() {
        assert_eq!(instruction(Some(0x401000)).address(), Some(0x401000));
        assert_eq!(instruction(None).address(), None);
    }

    #[test]
    fn lir_block_address_returns_first_addressed_instruction() {
        let mut block = LirBlock::new(None);
        block.append_instruction(instruction(None));
        block.append_instruction(instruction(Some(0x401004)));
        block.append_instruction(instruction(Some(0x401008)));

        assert_eq!(block.address(), Some(0x401004));
    }

    #[test]
    fn lir_block_address_returns_none_when_addressless() {
        let mut block = LirBlock::new(None);
        block.append_instruction(instruction(None));

        assert_eq!(block.address(), None);
    }

    #[test]
    fn lir_function_address_returns_first_addressed_block() {
        let mut first = LirBlock::new(None);
        first.append_instruction(instruction(None));
        let mut second = LirBlock::new(None);
        second.append_instruction(instruction(Some(0x401010)));

        let mut function = LirFunction::new(None);
        function.append_block(first);
        function.append_block(second);

        assert_eq!(function.address(), Some(0x401010));
    }

    #[test]
    fn lir_function_address_returns_none_when_addressless() {
        let mut block = LirBlock::new(None);
        block.append_instruction(instruction(None));
        let mut function = LirFunction::new(None);
        function.append_block(block);

        assert_eq!(function.address(), None);
    }

    #[test]
    fn lir_const_serde_serializes_u128_as_string() {
        let lir = LirInstruction {
            address: Some(0x4010),
            status: LirStatus::Complete,
            effects: Vec::new(),
            terminator: LirTerminator::Return {
                expression: Some(LirExpression::Const {
                    value: u128::MAX,
                    bits: 128,
                }),
            },
        };

        let value = serde_json::to_value(lir).expect("serialize lir");
        let serialized = value
            .get("terminator")
            .and_then(|value| value.get("Return"))
            .and_then(|value| value.get("expression"))
            .and_then(|value| value.get("Const"))
            .and_then(|value| value.get("value"))
            .and_then(|value| value.as_str())
            .expect("const value should serialize as string");

        assert_eq!(serialized, u128::MAX.to_string());
    }

    #[test]
    fn lir_const_serde_deserializes_string_back_to_u128() {
        let value = u128::MAX.to_string();
        let payload = serde_json::json!({
            "address": 16400,
            "status": "Complete",
            "terminator": {
                "Return": {
                    "expression": {
                        "Const": {
                            "value": value,
                            "bits": 128
                        }
                    }
                }
            },
            "temporaries": [],
            "effects": []
        });

        let lir: LirInstruction = serde_json::from_value(payload).expect("deserialize lir");

        match lir.terminator {
            LirTerminator::Return {
                expression: Some(LirExpression::Const { value, bits }),
            } => {
                assert_eq!(value, u128::MAX);
                assert_eq!(bits, 128);
            }
            other => panic!("unexpected terminator: {:?}", other),
        }
        assert_eq!(lir.address, Some(16400));
    }
}
