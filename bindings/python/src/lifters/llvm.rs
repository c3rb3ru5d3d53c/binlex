use crate::controlflow::{Block as PyBlock, Function as PyFunction, Instruction as PyInstruction};
use crate::semantics::abis::extract_abi;
use crate::semantics::{SemanticCpu as PySemanticCpu, Semantics as PySemantics};
use crate::Configuration;
use binlex::controlflow::{Block, Function, Graph, Instruction, InstructionRecord};
use binlex::core::Architecture;
use binlex::io::Stderr;
use binlex::lifters::llvm::{JittedFunction as InnerJittedFunction, Lifter as InnerLifter};
use binlex::semantics::{Semantic, SemanticAbi, SemanticCpuKind, SemanticTerminator, Semantics};
use pyo3::prelude::*;
use pyo3::types::PyAny;
use std::collections::BTreeMap;
use std::io::Error;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
enum ModuleItemDef {
    Instruction {
        record: InstructionRecord,
    },
    Block {
        address: u64,
        records: Vec<InstructionRecord>,
        abi: Option<SemanticAbi>,
    },
    Function {
        address: u64,
        blocks: Vec<(u64, Vec<InstructionRecord>)>,
        abi: Option<SemanticAbi>,
        name: Option<String>,
    },
    BlockSemantics {
        semantics: Semantics,
        abi: Option<SemanticAbi>,
    },
    FunctionSemantics {
        semantics: Semantics,
        abi: Option<SemanticAbi>,
        name: Option<String>,
    },
    CreatedFunction {
        function: CreatedFunctionDef,
    },
}

#[derive(Clone)]
enum ModuleOverrideDef {
    Ir(String),
    Bitcode(Vec<u8>),
}

#[derive(Clone)]
struct CreatedFunctionDef {
    name: String,
    abi: Option<SemanticAbi>,
    body_semantics: Option<Semantics>,
    blocks: Vec<CreatedBlockDef>,
    raw_ir: Option<String>,
    raw_bitcode: Option<Vec<u8>>,
}

#[derive(Clone)]
enum CreatedBlockDef {
    Cfg {
        name: Option<String>,
        address: u64,
        records: Vec<InstructionRecord>,
    },
    Semantics {
        name: Option<String>,
        semantics: Semantics,
    },
}

struct BuildState {
    config: binlex::Configuration,
    cpu: binlex::semantics::SemanticCpu,
    triple: Option<String>,
    inner: InnerLifter,
    module_override: Option<ModuleOverrideDef>,
    items: Vec<ModuleItemDef>,
    dirty: bool,
}

impl BuildState {
    fn new(
        cpu: binlex::semantics::SemanticCpu,
        config: binlex::Configuration,
        triple: Option<String>,
    ) -> Result<Self, Error> {
        let inner = InnerLifter::new(cpu.clone(), config.clone(), triple.clone())?;
        Ok(Self {
            config,
            cpu,
            triple,
            inner,
            module_override: None,
            items: Vec::new(),
            dirty: false,
        })
    }

    fn rebuild(&mut self) -> Result<(), Error> {
        let mut inner = InnerLifter::new(
            self.cpu.clone(),
            self.config.clone(),
            self.triple.clone(),
        )?;
        if let Some(override_def) = self.module_override.clone() {
            match override_def {
                ModuleOverrideDef::Ir(ir) => inner.set_ir(&ir)?,
                ModuleOverrideDef::Bitcode(bitcode) => inner.set_bitcode(&bitcode)?,
            }
        }
        for item in self.items.clone() {
            match item {
                ModuleItemDef::Instruction { record } => {
                    let graph = graph_from_instruction_record(
                        architecture_from_cpu(&self.cpu)?,
                        &self.config,
                        record,
                    );
                    let instruction =
                        Instruction::new(*graph.instruction_addresses().iter().next().unwrap(), &graph)?;
                    inner.lift_instruction(&instruction)?;
                }
                ModuleItemDef::Block {
                    address,
                    records,
                    abi,
                } => {
                    let mut graph = Graph::new(architecture_from_cpu(&self.cpu)?, self.config.clone());
                    for record in records {
                        graph.insert_instruction(record);
                    }
                    graph.set_block(address);
                    let block = Block::new(address, &graph)?;
                    inner.lift_block(&block, abi.as_ref())?;
                }
                ModuleItemDef::Function {
                    address,
                    blocks,
                    abi,
                    name,
                } => {
                    let mut graph = Graph::new(architecture_from_cpu(&self.cpu)?, self.config.clone());
                    for (block_address, records) in blocks {
                        for record in records {
                            graph.insert_instruction(record);
                        }
                        graph.set_block(block_address);
                    }
                    graph.set_function(address);
                    let function = Function::new(address, &graph)?;
                    if let Some(name) = name {
                        inner.lift_function_named(&function, abi.as_ref(), &name, None)?;
                    } else {
                        inner.lift_function(&function, abi.as_ref())?;
                    }
                }
                ModuleItemDef::BlockSemantics { semantics, abi } => {
                    inner.lift_block_semantics(&semantics, abi.as_ref())?;
                }
                ModuleItemDef::FunctionSemantics {
                    semantics,
                    abi,
                    name,
                } => {
                    if let Some(name) = name {
                        inner.lift_function_semantics_named(&semantics, abi.as_ref(), &name)?;
                    } else {
                        inner.lift_function_semantics(&semantics, abi.as_ref())?;
                    }
                }
                ModuleItemDef::CreatedFunction { function } => {
                    compile_created_function(&mut inner, &self.config, &self.cpu, &function)?;
                }
            }
        }
        self.inner = inner;
        self.dirty = false;
        Ok(())
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn ensure_built(&mut self) -> Result<(), Error> {
        if self.dirty {
            self.rebuild()?;
        }
        Ok(())
    }
}

fn architecture_from_cpu(cpu: &binlex::semantics::SemanticCpu) -> Result<Architecture, Error> {
    match cpu.kind() {
        Some(SemanticCpuKind::I386) => Ok(Architecture::I386),
        Some(SemanticCpuKind::Amd64) => Ok(Architecture::AMD64),
        Some(SemanticCpuKind::Arm64) => Ok(Architecture::ARM64),
        Some(SemanticCpuKind::Cil) => Ok(Architecture::CIL),
        None => Err(Error::other(
            "llvm builder requires a built-in semantic CPU kind",
        )),
    }
}

fn graph_from_instruction_record(
    architecture: Architecture,
    config: &binlex::Configuration,
    record: InstructionRecord,
) -> Graph {
    let mut graph = Graph::new(architecture, config.clone());
    let address = record.address;
    graph.insert_instruction(record);
    graph.instructions.insert_processed(address);
    graph.instructions.insert_valid(address);
    graph
}

fn instruction_records_for_block(graph: &Graph, address: u64) -> Result<Vec<InstructionRecord>, Error> {
    let block = Block::new(address, graph)?;
    Ok(block
        .instructions()
        .into_iter()
        .map(Instruction::into_record)
        .collect())
}

fn compile_created_function(
    inner: &mut InnerLifter,
    config: &binlex::Configuration,
    cpu: &binlex::semantics::SemanticCpu,
    function: &CreatedFunctionDef,
) -> Result<(), Error> {
    if let Some(ir) = &function.raw_ir {
        return inner.link_ir_module(ir, Some(&function.name));
    }
    if let Some(bitcode) = &function.raw_bitcode {
        return inner.link_bitcode_module(bitcode, Some(&function.name));
    }
    if let Some(semantics) = &function.body_semantics {
        return inner.lift_function_semantics_named(semantics, function.abi.as_ref(), &function.name);
    }

    let architecture = architecture_from_cpu(cpu)?;
    let mut graph = Graph::new(architecture, config.clone());
    let mut block_labels = BTreeMap::<u64, String>::new();
    let mut next_block_base = 0x1000u64;
    let mut entry_address = None;

    for (index, block) in function.blocks.iter().enumerate() {
        match block {
            CreatedBlockDef::Cfg {
                name,
                address: _,
                records,
            } => {
                let block_address = records
                    .first()
                    .map(|record| record.address)
                    .ok_or_else(|| Error::other("cfg block contains no instructions"))?;
                if entry_address.is_none() {
                    entry_address = Some(block_address);
                }
                for record in records.iter().cloned() {
                    graph.insert_instruction(record);
                }
                graph.set_block(block_address);
                if let Some(name) = name {
                    block_labels.insert(block_address, name.clone());
                }
            }
            CreatedBlockDef::Semantics { name, semantics } => {
                let block_address = next_block_base;
                if entry_address.is_none() {
                    entry_address = Some(block_address);
                }
                if let Some(name) = name {
                    block_labels.insert(block_address, name.clone());
                }
                let next_block_address = function
                    .blocks
                    .get(index + 1)
                    .map(|_| next_block_base + 0x1000);
                insert_semantics_block(
                    &mut graph,
                    architecture,
                    block_address,
                    &semantics.semantics,
                    next_block_address,
                    config,
                );
                graph.set_block(block_address);
                next_block_base += 0x1000;
            }
        }
    }

    let entry_address = entry_address.ok_or_else(|| Error::other("function contains no blocks"))?;
    graph.set_function(entry_address);
    let function_graph = Function::new(entry_address, &graph)?;
    inner.lift_function_named(
        &function_graph,
        function.abi.as_ref(),
        &function.name,
        Some(&block_labels),
    )
}

fn insert_semantics_block(
    graph: &mut Graph,
    architecture: Architecture,
    block_address: u64,
    semantics: &[Semantic],
    next_block_address: Option<u64>,
    config: &binlex::Configuration,
) {
    for (index, semantic) in semantics.iter().enumerate() {
        let address = block_address + index as u64;
        let mut record = Instruction::create(address, architecture, config.clone());
        record.bytes = vec![0x90];
        record.mnemonic = "semantic".to_string();
        record.disassembly = "semantic".to_string();
        record.pattern = "90".to_string();
        record.semantics = Some(semantic.clone());
        if index == 0 {
            record.is_block_start = true;
        }
        if index == semantics.len() - 1 {
            match &semantic.terminator {
                SemanticTerminator::Return { .. } => {
                    record.is_return = true;
                }
                SemanticTerminator::Jump { target } => {
                    record.is_jump = true;
                    if let Some(address) = semantic_expression_u64(target) {
                        record.to.insert(address);
                    } else if let Some(next) = next_block_address {
                        record.to.insert(next);
                    }
                }
                SemanticTerminator::Branch {
                    true_target,
                    false_target,
                    ..
                } => {
                    record.is_jump = true;
                    record.is_conditional = true;
                    if let Some(address) = semantic_expression_u64(true_target) {
                        record.to.insert(address);
                    }
                    if let Some(address) = semantic_expression_u64(false_target) {
                        record.to.insert(address);
                    }
                }
                SemanticTerminator::Trap => {
                    record.is_trap = true;
                }
                SemanticTerminator::Call { does_return, .. } => {
                    record.is_call = true;
                    if does_return.unwrap_or(true) {
                        if let Some(next) = next_block_address {
                            record.to.insert(next);
                        }
                    }
                }
                SemanticTerminator::FallThrough => {
                    if let Some(next) = next_block_address {
                        record.is_jump = true;
                        record.to.insert(next);
                    }
                }
                SemanticTerminator::Unreachable => {}
            }
        }
        record.edges = record.successors().len();
        graph.insert_instruction(record);
    }
}

fn semantic_expression_u64(expression: &binlex::semantics::SemanticExpression) -> Option<u64> {
    match expression {
        binlex::semantics::SemanticExpression::Const { value, .. } => (*value).try_into().ok(),
        _ => None,
    }
}

#[pyclass(unsendable)]
pub struct Lifter {
    pub config: binlex::Configuration,
    pub cpu: binlex::semantics::SemanticCpu,
    state: Arc<Mutex<BuildState>>,
}

#[pyclass(unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct LiftedFunction {
    state: Arc<Mutex<BuildState>>,
    index: usize,
}

#[pyclass(unsendable, skip_from_py_object)]
#[derive(Clone)]
pub struct LiftedBlock {
    state: Arc<Mutex<BuildState>>,
    function_index: usize,
    block_index: usize,
}

#[pyclass(unsendable, skip_from_py_object)]
pub struct JittedFunction {
    inner: InnerJittedFunction,
}

#[pymethods]
impl Lifter {
    #[new]
    #[pyo3(signature = (cpu, config, triple=None), text_signature = "(cpu, config, triple=None)")]
    pub fn new(
        py: Python<'_>,
        cpu: Py<PySemanticCpu>,
        config: Py<Configuration>,
        triple: Option<String>,
    ) -> PyResult<Self> {
        let inner_cpu = cpu.borrow(py).inner.clone();
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let state = BuildState::new(inner_cpu.clone(), inner_config.clone(), triple)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self {
            config: inner_config,
            cpu: inner_cpu,
            state: Arc::new(Mutex::new(state)),
        })
    }

    #[pyo3(text_signature = "($self, instruction)")]
    pub fn lift_instruction(&self, py: Python<'_>, instruction: &PyInstruction) -> bool {
        let record = match instruction.with_inner_instruction(py, |inner| Ok(inner.inner.clone())) {
            Ok(record) => record,
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm lift instruction failed: {}", err));
                return false;
            }
        };
        let mut state = self.state.lock().unwrap();
        state.items.push(ModuleItemDef::Instruction { record });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (block, abi=None), text_signature = "($self, block, abi=None)")]
    pub fn lift_block(&self, py: Python<'_>, block: &PyBlock, abi: Option<Py<PyAny>>) -> bool {
        let abi = match abi {
            Some(value) => match extract_abi(value.bind(py)) {
                Ok(abi) => Some(abi),
                Err(err) => {
                    Stderr::print_debug(&self.config, format!("llvm lift block failed: {}", err));
                    return false;
                }
            },
            None => None,
        };
        let (records, address) = match block.with_inner_block(py, |inner| {
            Ok((instruction_records_for_block(inner.cfg, inner.address())?, inner.address()))
        }) {
            Ok(values) => values,
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm lift block failed: {}", err));
                return false;
            }
        };
        let mut state = self.state.lock().unwrap();
        state.items.push(ModuleItemDef::Block {
            address,
            records,
            abi,
        });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (function, abi=None), text_signature = "($self, function, abi=None)")]
    pub fn lift_function(
        &self,
        py: Python<'_>,
        function: &PyFunction,
        abi: Option<Py<PyAny>>,
    ) -> bool {
        let abi = match abi {
            Some(value) => match extract_abi(value.bind(py)) {
                Ok(abi) => Some(abi),
                Err(err) => {
                    Stderr::print_debug(&self.config, format!("llvm lift function failed: {}", err));
                    return false;
                }
            },
            None => None,
        };
        let (blocks, address) = match function.with_inner_function(py, |inner| {
            let mut blocks = Vec::with_capacity(inner.blocks.len());
            for block in inner.blocks.values() {
                blocks.push((block.address(), instruction_records_for_block(inner.cfg, block.address())?));
            }
            Ok((blocks, inner.address()))
        }) {
            Ok(values) => values,
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm lift function failed: {}", err));
                return false;
            }
        };
        let mut state = self.state.lock().unwrap();
        state.items.push(ModuleItemDef::Function {
            address,
            blocks,
            abi,
            name: None,
        });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (semantics, abi=None), text_signature = "($self, semantics, abi=None)")]
    pub fn lift_block_semantics(
        &self,
        py: Python<'_>,
        semantics: Py<PySemantics>,
        abi: Option<Py<PyAny>>,
    ) -> bool {
        let semantics = semantics.borrow(py).inner.lock().unwrap().clone();
        let abi = match abi {
            Some(value) => match extract_abi(value.bind(py)) {
                Ok(abi) => Some(abi),
                Err(err) => {
                    Stderr::print_debug(&self.config, format!("llvm lift block semantics failed: {}", err));
                    return false;
                }
            },
            None => None,
        };
        let mut state = self.state.lock().unwrap();
        state.items.push(ModuleItemDef::BlockSemantics { semantics, abi });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (semantics, abi=None, name=None), text_signature = "($self, semantics, abi=None, name=None)")]
    pub fn lift_function_semantics(
        &self,
        py: Python<'_>,
        semantics: Py<PySemantics>,
        abi: Option<Py<PyAny>>,
        name: Option<String>,
    ) -> bool {
        let semantics = semantics.borrow(py).inner.lock().unwrap().clone();
        let abi = match abi {
            Some(value) => match extract_abi(value.bind(py)) {
                Ok(abi) => Some(abi),
                Err(err) => {
                    Stderr::print_debug(&self.config, format!("llvm lift function semantics failed: {}", err));
                    return false;
                }
            },
            None => None,
        };
        let mut state = self.state.lock().unwrap();
        state.items.push(ModuleItemDef::FunctionSemantics { semantics, abi, name });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (name, abi=None), text_signature = "($self, name, abi=None)")]
    pub fn create_function(
        &self,
        py: Python<'_>,
        name: String,
        abi: Option<Py<PyAny>>,
    ) -> PyResult<LiftedFunction> {
        let abi = match abi {
            Some(value) => Some(extract_abi(value.bind(py))?),
            None => None,
        };
        let mut state = self.state.lock().unwrap();
        let index = state.items.len();
        state.items.push(ModuleItemDef::CreatedFunction {
            function: CreatedFunctionDef {
                name,
                abi,
                body_semantics: None,
                blocks: Vec::new(),
                raw_ir: None,
                raw_bitcode: None,
            },
        });
        state.mark_dirty();
        Ok(LiftedFunction {
            state: self.state.clone(),
            index,
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn functions(&self) -> Vec<LiftedFunction> {
        let state = self.state.lock().unwrap();
        state
            .items
            .iter()
            .enumerate()
            .filter_map(|(index, item)| match item {
                ModuleItemDef::CreatedFunction { .. } => Some(LiftedFunction {
                    state: self.state.clone(),
                    index,
                }),
                _ => None,
            })
            .collect()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn clear(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        state.module_override = None;
        state.items.clear();
        rebuild_state(&mut state, &self.config, "llvm clear failed")
    }

    #[pyo3(text_signature = "($self)")]
    pub fn ir(&self) -> String {
        let mut state = self.state.lock().unwrap();
        let _ = state.ensure_built();
        state.inner.ir()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        println!("{}", self.ir());
    }

    #[pyo3(text_signature = "($self, ir)")]
    pub fn set_ir(&self, ir: String) -> bool {
        let mut state = self.state.lock().unwrap();
        state.module_override = Some(ModuleOverrideDef::Ir(ir));
        state.items.clear();
        rebuild_state(&mut state, &self.config, "llvm set ir failed")
    }

    #[pyo3(text_signature = "($self, bitcode)")]
    pub fn set_bitcode(&self, bitcode: Vec<u8>) -> bool {
        let mut state = self.state.lock().unwrap();
        state.module_override = Some(ModuleOverrideDef::Bitcode(bitcode));
        state.items.clear();
        rebuild_state(&mut state, &self.config, "llvm set bitcode failed")
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bitcode(&self) -> Vec<u8> {
        let mut state = self.state.lock().unwrap();
        let _ = state.ensure_built();
        state.inner.bitcode()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn object(&self) -> Option<Vec<u8>> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm object failed: {}", err));
            return None;
        }
        match state.inner.object() {
            Ok(bytes) => Some(bytes),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm object failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn optimize_mem2reg(&self) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm mem2reg failed: {}", err));
            return None;
        }
        match state.inner.mem2reg() {
            Ok(inner) => {
                state.inner = inner;
                Some(true)
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm mem2reg failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn optimize_instcombine(&self) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm instcombine failed: {}", err));
            return None;
        }
        match state.inner.instcombine() {
            Ok(inner) => {
                state.inner = inner;
                Some(true)
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm instcombine failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn optimize_cfg(&self) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm cfg failed: {}", err));
            return None;
        }
        match state.inner.cfg() {
            Ok(inner) => {
                state.inner = inner;
                Some(true)
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm cfg failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn optimize_gvn(&self) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm gvn failed: {}", err));
            return None;
        }
        match state.inner.gvn() {
            Ok(inner) => {
                state.inner = inner;
                Some(true)
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm gvn failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn optimize_sroa(&self) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm sroa failed: {}", err));
            return None;
        }
        match state.inner.sroa() {
            Ok(inner) => {
                state.inner = inner;
                Some(true)
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm sroa failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn optimize_dce(&self) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm dce failed: {}", err));
            return None;
        }
        match state.inner.dce() {
            Ok(inner) => {
                state.inner = inner;
                Some(true)
            }
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm dce failed: {}", err));
                None
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn verify(&self) -> Option<bool> {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&self.config, format!("llvm verify failed: {}", err));
            return None;
        }
        match state.inner.verify() {
            Ok(()) => Some(true),
            Err(err) => {
                Stderr::print_debug(&self.config, format!("llvm verify failed: {}", err));
                None
            }
        }
    }

    pub fn __str__(&self) -> String {
        self.ir()
    }
}

#[pymethods]
impl LiftedFunction {
    pub fn name(&self) -> String {
        let state = self.state.lock().unwrap();
        match &state.items[self.index] {
            ModuleItemDef::CreatedFunction { function } => function.name.clone(),
            _ => String::new(),
        }
    }

    #[pyo3(text_signature = "($self, name)")]
    pub fn set_name(&self, name: String) -> bool {
        if name.trim().is_empty() {
            Stderr::print_debug(
                &self.state.lock().unwrap().config,
                "llvm set function name failed: name cannot be empty".to_string(),
            );
            return false;
        }
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        function.name = name;
        state.mark_dirty();
        true
    }

    pub fn blocks(&self) -> Vec<LiftedBlock> {
        let state = self.state.lock().unwrap();
        let count = match &state.items[self.index] {
            ModuleItemDef::CreatedFunction { function } => function.blocks.len(),
            _ => 0,
        };
        (0..count)
            .map(|block_index| LiftedBlock {
                state: self.state.clone(),
                function_index: self.index,
                block_index,
            })
            .collect()
    }

    #[pyo3(signature = (block, name=None), text_signature = "($self, block, name=None)")]
    pub fn lift_block(&self, py: Python<'_>, block: &PyBlock, name: Option<String>) -> bool {
        let (records, address) = match block.with_inner_block(py, |inner| {
            Ok((instruction_records_for_block(inner.cfg, inner.address())?, inner.address()))
        }) {
            Ok(values) => values,
            Err(err) => {
                Stderr::print_debug(
                    &self.state.lock().unwrap().config,
                    format!("llvm function block append failed: {}", err),
                );
                return false;
            }
        };
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        if function.body_semantics.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm function block append failed: function already has semantic body".to_string(),
            );
            return false;
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm function block append failed: function already has raw llvm body".to_string(),
            );
            return false;
        }
        function.blocks.push(CreatedBlockDef::Cfg {
            name,
            address,
            records,
        });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (semantics, name=None), text_signature = "($self, semantics, name=None)")]
    pub fn lift_block_semantics(
        &self,
        py: Python<'_>,
        semantics: Py<PySemantics>,
        name: Option<String>,
    ) -> bool {
        let semantics = semantics.borrow(py).inner.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        if function.body_semantics.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm semantic block append failed: function already has semantic body".to_string(),
            );
            return false;
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm semantic block append failed: function already has raw llvm body".to_string(),
            );
            return false;
        }
        function
            .blocks
            .push(CreatedBlockDef::Semantics { name, semantics });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (semantics), text_signature = "($self, semantics)")]
    pub fn lift_function_semantics(&self, py: Python<'_>, semantics: Py<PySemantics>) -> bool {
        let semantics = semantics.borrow(py).inner.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        if !function.blocks.is_empty() {
            Stderr::print_debug(
                &state.config,
                "llvm function semantics append failed: function already has blocks".to_string(),
            );
            return false;
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm function semantics append failed: function already has raw llvm body".to_string(),
            );
            return false;
        }
        function.body_semantics = Some(semantics);
        state.mark_dirty();
        true
    }

    pub fn set_ir(&self, ir: String) -> bool {
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        function.body_semantics = None;
        function.blocks.clear();
        function.raw_bitcode = None;
        function.raw_ir = Some(ir);
        state.mark_dirty();
        true
    }

    pub fn set_bitcode(&self, bitcode: Vec<u8>) -> bool {
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        function.body_semantics = None;
        function.blocks.clear();
        function.raw_ir = None;
        function.raw_bitcode = Some(bitcode);
        state.mark_dirty();
        true
    }

    pub fn optimize_mem2reg(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&state.config, format!("llvm function mem2reg failed: {}", err));
            return false;
        }
        let Some(ModuleItemDef::CreatedFunction { function }) = state.items.get(self.index) else {
            return false;
        };
        match state.inner.mem2reg_function(&function.name) {
            Ok(inner) => {
                state.inner = inner;
                true
            }
            Err(err) => {
                Stderr::print_debug(&state.config, format!("llvm function mem2reg failed: {}", err));
                false
            }
        }
    }

    pub fn optimize_instcombine(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&state.config, format!("llvm function instcombine failed: {}", err));
            return false;
        }
        let Some(ModuleItemDef::CreatedFunction { function }) = state.items.get(self.index) else {
            return false;
        };
        match state.inner.instcombine_function(&function.name) {
            Ok(inner) => {
                state.inner = inner;
                true
            }
            Err(err) => {
                Stderr::print_debug(&state.config, format!("llvm function instcombine failed: {}", err));
                false
            }
        }
    }

    pub fn optimize_cfg(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&state.config, format!("llvm function cfg failed: {}", err));
            return false;
        }
        let Some(ModuleItemDef::CreatedFunction { function }) = state.items.get(self.index) else {
            return false;
        };
        match state.inner.cfg_function(&function.name) {
            Ok(inner) => {
                state.inner = inner;
                true
            }
            Err(err) => {
                Stderr::print_debug(&state.config, format!("llvm function cfg failed: {}", err));
                false
            }
        }
    }

    pub fn optimize_gvn(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&state.config, format!("llvm function gvn failed: {}", err));
            return false;
        }
        let Some(ModuleItemDef::CreatedFunction { function }) = state.items.get(self.index) else {
            return false;
        };
        match state.inner.gvn_function(&function.name) {
            Ok(inner) => {
                state.inner = inner;
                true
            }
            Err(err) => {
                Stderr::print_debug(&state.config, format!("llvm function gvn failed: {}", err));
                false
            }
        }
    }

    pub fn optimize_sroa(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&state.config, format!("llvm function sroa failed: {}", err));
            return false;
        }
        let Some(ModuleItemDef::CreatedFunction { function }) = state.items.get(self.index) else {
            return false;
        };
        match state.inner.sroa_function(&function.name) {
            Ok(inner) => {
                state.inner = inner;
                true
            }
            Err(err) => {
                Stderr::print_debug(&state.config, format!("llvm function sroa failed: {}", err));
                false
            }
        }
    }

    pub fn optimize_dce(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(&state.config, format!("llvm function dce failed: {}", err));
            return false;
        }
        let Some(ModuleItemDef::CreatedFunction { function }) = state.items.get(self.index) else {
            return false;
        };
        match state.inner.dce_function(&function.name) {
            Ok(inner) => {
                state.inner = inner;
                true
            }
            Err(err) => {
                Stderr::print_debug(&state.config, format!("llvm function dce failed: {}", err));
                false
            }
        }
    }

    pub fn ir(&self) -> Option<String> {
        match function_preview_lifter(&self.state, self.index, false) {
            Ok(lifter) => Some(lifter.ir()),
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(&state.config, format!("llvm function ir failed: {}", err));
                None
            }
        }
    }

    pub fn print(&self) -> bool {
        match self.ir() {
            Some(text) => {
                println!("{text}");
                true
            }
            None => false,
        }
    }

    pub fn bitcode(&self) -> Option<Vec<u8>> {
        match function_preview_lifter(&self.state, self.index, false) {
            Ok(lifter) => Some(lifter.bitcode()),
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(&state.config, format!("llvm function bitcode failed: {}", err));
                None
            }
        }
    }

    pub fn object(&self) -> Option<Vec<u8>> {
        match function_preview_lifter(&self.state, self.index, false) {
            Ok(lifter) => match lifter.object() {
                Ok(bytes) => Some(bytes),
                Err(err) => {
                    let state = self.state.lock().unwrap();
                    Stderr::print_debug(&state.config, format!("llvm function object failed: {}", err));
                    None
                }
            },
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(&state.config, format!("llvm function object failed: {}", err));
                None
            }
        }
    }

    #[pyo3(signature = (links=None), text_signature = "($self, links=None)")]
    pub fn jit(&self, links: Option<BTreeMap<String, u64>>) -> Option<JittedFunction> {
        let state = self.state.lock().unwrap();
        let name = match state.items.get(self.index) {
            Some(ModuleItemDef::CreatedFunction { function }) => function.name.clone(),
            _ => return None,
        };
        let preserve_links = links.as_ref().is_some_and(|links| !links.is_empty());
        drop(state);
        match function_preview_lifter(&self.state, self.index, preserve_links) {
            Ok(lifter) => {
                let links = links
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(name, address)| (name, address as usize))
                    .collect::<BTreeMap<_, _>>();
                match lifter.jit_function(&name, &links) {
                Ok(inner) => Some(JittedFunction { inner }),
                Err(err) => {
                    let state = self.state.lock().unwrap();
                    Stderr::print_debug(&state.config, format!("llvm function jit failed: {}", err));
                    None
                }
            }
            }
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(&state.config, format!("llvm function jit failed: {}", err));
                None
            }
        }
    }
}

#[pymethods]
impl LiftedBlock {
    pub fn name(&self) -> String {
        let state = self.state.lock().unwrap();
        let Some(ModuleItemDef::CreatedFunction { function }) = state.items.get(self.function_index) else {
            return String::new();
        };
        match &function.blocks[self.block_index] {
            CreatedBlockDef::Cfg { name, address, .. } => {
                name.clone().unwrap_or_else(|| format!("block_{address:x}"))
            }
            CreatedBlockDef::Semantics { name, .. } => name
                .clone()
                .unwrap_or_else(|| format!("block_{}", self.block_index)),
        }
    }

    pub fn ir(&self) -> Option<String> {
        match block_preview_lifter(&self.state, self.function_index, self.block_index) {
            Ok(lifter) => Some(lifter.ir()),
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(&state.config, format!("llvm block ir failed: {}", err));
                None
            }
        }
    }

    pub fn print(&self) -> bool {
        match self.ir() {
            Some(text) => {
                println!("{text}");
                true
            }
            None => false,
        }
    }
}

#[pymethods]
impl JittedFunction {
    pub fn name(&self) -> String {
        self.inner.name().to_string()
    }

    pub fn address(&self) -> u64 {
        self.inner.address() as u64
    }
}

fn function_preview_lifter(
    state: &Arc<Mutex<BuildState>>,
    index: usize,
    preserve_module: bool,
) -> Result<InnerLifter, Error> {
    let state = state.lock().unwrap();
    let item = state
        .items
        .get(index)
        .ok_or_else(|| Error::other("lifted function is invalid"))?;
    let ModuleItemDef::CreatedFunction { function } = item else {
        return Err(Error::other("lifted function is invalid"));
    };
    if !state.dirty {
        if preserve_module {
            let mut lifter = InnerLifter::new(
                state.cpu.clone(),
                state.config.clone(),
                state.triple.clone(),
            )?;
            lifter.set_bitcode(&state.inner.bitcode())?;
            return Ok(lifter);
        }
        return state.inner.duplicate_function_view(&function.name);
    }
    let function = function.clone();
    let mut lifter = InnerLifter::new(
        state.cpu.clone(),
        state.config.clone(),
        state.triple.clone(),
    )?;
    compile_created_function(&mut lifter, &state.config, &state.cpu, &function)?;
    Ok(lifter)
}

fn block_preview_lifter(
    state: &Arc<Mutex<BuildState>>,
    function_index: usize,
    block_index: usize,
) -> Result<InnerLifter, Error> {
    let state = state.lock().unwrap();
    let item = state
        .items
        .get(function_index)
        .cloned()
        .ok_or_else(|| Error::other("lifted block is invalid"))?;
    let ModuleItemDef::CreatedFunction { function } = item else {
        return Err(Error::other("lifted block is invalid"));
    };
    let block = function
        .blocks
        .get(block_index)
        .cloned()
        .ok_or_else(|| Error::other("lifted block is invalid"))?;
    let preview = CreatedFunctionDef {
        name: block_preview_function_name(&function.name, &block, block_index),
        abi: function.abi.clone(),
        body_semantics: None,
        blocks: vec![block],
        raw_ir: None,
        raw_bitcode: None,
    };
    let mut lifter = InnerLifter::new(
        state.cpu.clone(),
        state.config.clone(),
        state.triple.clone(),
    )?;
    compile_created_function(&mut lifter, &state.config, &state.cpu, &preview)?;
    Ok(lifter)
}

fn block_preview_function_name(
    function_name: &str,
    block: &CreatedBlockDef,
    block_index: usize,
) -> String {
    match block {
        CreatedBlockDef::Cfg { name, address, .. } => name
            .clone()
            .unwrap_or_else(|| format!("{function_name}_block_{address:x}")),
        CreatedBlockDef::Semantics { name, .. } => name
            .clone()
            .unwrap_or_else(|| format!("{function_name}_block_{block_index}")),
    }
}

fn rebuild_state(state: &mut BuildState, config: &binlex::Configuration, context: &str) -> bool {
    match state.rebuild() {
        Ok(()) => true,
        Err(err) => {
            Stderr::print_debug(config, format!("{context}: {err}"));
            false
        }
    }
}

#[pymodule]
#[pyo3(name = "llvm")]
pub fn llvm_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Lifter>()?;
    m.add_class::<LiftedFunction>()?;
    m.add_class::<LiftedBlock>()?;
    m.add_class::<JittedFunction>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.lifters.llvm", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.lifters.llvm")?;
    Ok(())
}
