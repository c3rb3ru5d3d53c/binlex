use crate::controlflow::Block as PyBlock;
use crate::irs::lir::{LirCpu as PyLirCpu, LirFunction as PyLirFunction, LirModule as PyLirModule};
use crate::Configuration;
use binlex::controlflow::{Block, Function, Graph, Instruction, InstructionRecord};
use binlex::core::Architecture;
use binlex::io::Stderr;
use binlex::irs::lir::{LirCpuKind, LirInstruction, LirModule, LirTerminator};
use binlex::irs::llvm::LlvmModule as InnerLlvmModule;
use pyo3::prelude::*;
use std::collections::BTreeMap;
use std::io::Error;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
enum ModuleItemDef {
    BlockLir {
        lir: LirModule,
    },
    FunctionLir {
        lir: LirModule,
        name: Option<String>,
    },
    CreatedFunction {
        function: CreatedFunctionDef,
    },
}

#[derive(Clone)]
enum ModuleOverrideDef {
    Text(String),
    Bitcode(Vec<u8>),
}

#[derive(Clone)]
struct CreatedFunctionDef {
    name: String,
    body_lir: Option<LirModule>,
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
    LirModule {
        name: Option<String>,
        lir: LirModule,
    },
}

struct BuildState {
    name: Option<String>,
    config: binlex::Configuration,
    cpu: binlex::irs::lir::LirCpu,
    triple: Option<String>,
    inner: InnerLlvmModule,
    module_override: Option<ModuleOverrideDef>,
    items: Vec<ModuleItemDef>,
    dirty: bool,
}

impl BuildState {
    fn new(
        name: Option<String>,
        cpu: binlex::irs::lir::LirCpu,
        config: binlex::Configuration,
        triple: Option<String>,
    ) -> Result<Self, Error> {
        let inner = InnerLlvmModule::with_config(
            name.clone(),
            cpu.clone(),
            config.clone(),
            triple.clone(),
        )?;
        Ok(Self {
            name,
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
        let mut inner = InnerLlvmModule::with_config(
            self.name.clone(),
            self.cpu.clone(),
            self.config.clone(),
            self.triple.clone(),
        )?;
        if let Some(override_def) = self.module_override.clone() {
            match override_def {
                ModuleOverrideDef::Text(text) => inner.set_text(&text)?,
                ModuleOverrideDef::Bitcode(bitcode) => inner.set_bitcode(&bitcode)?,
            }
        }
        for item in self.items.clone() {
            match item {
                ModuleItemDef::BlockLir { lir } => {
                    inner.populate_block_lir(&lir)?;
                }
                ModuleItemDef::FunctionLir { lir, name } => {
                    if let Some(name) = name {
                        inner.populate_function_lir_named(&lir, &name)?;
                    } else {
                        inner.populate_function_lir(&lir)?;
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

fn architecture_from_cpu(cpu: &binlex::irs::lir::LirCpu) -> Result<Architecture, Error> {
    match cpu.kind() {
        Some(LirCpuKind::I386) => Ok(Architecture::I386),
        Some(LirCpuKind::Amd64) => Ok(Architecture::AMD64),
        Some(LirCpuKind::Arm64) => Ok(Architecture::ARM64),
        Some(LirCpuKind::Cil) => Ok(Architecture::CIL),
        None => Err(Error::other(
            "llvm builder requires a built-in lir CPU kind",
        )),
    }
}

fn instruction_records_for_block(
    graph: &Graph,
    address: u64,
) -> Result<Vec<InstructionRecord>, Error> {
    let block = Block::new(address, graph)?;
    Ok(block
        .instructions()
        .into_iter()
        .map(Instruction::into_record)
        .collect())
}

fn compile_created_function(
    inner: &mut InnerLlvmModule,
    config: &binlex::Configuration,
    cpu: &binlex::irs::lir::LirCpu,
    function: &CreatedFunctionDef,
) -> Result<(), Error> {
    if let Some(ir) = &function.raw_ir {
        return inner.link_ir_module(ir, Some(&function.name));
    }
    if let Some(bitcode) = &function.raw_bitcode {
        return inner.link_bitcode_module(bitcode, Some(&function.name));
    }
    if let Some(lir) = &function.body_lir {
        return inner.populate_function_lir_named(lir, &function.name);
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
            CreatedBlockDef::LirModule { name, lir } => {
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
                let instructions = lir.instructions().into_iter().cloned().collect::<Vec<_>>();
                insert_lir_block(
                    &mut graph,
                    architecture,
                    block_address,
                    &instructions,
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
    inner.populate_function_named(&function_graph, &function.name, Some(&block_labels))
}

fn insert_lir_block(
    graph: &mut Graph,
    architecture: Architecture,
    block_address: u64,
    lirs: &[LirInstruction],
    next_block_address: Option<u64>,
    config: &binlex::Configuration,
) {
    for (index, lir) in lirs.iter().enumerate() {
        let address = block_address + index as u64;
        let mut record = Instruction::create(address, architecture, config.clone());
        record.bytes = vec![0x90];
        record.mnemonic = "lir".to_string();
        record.disassembly = "lir".to_string();
        record.pattern = "90".to_string();
        record.ir.lir = Some(lir.clone());
        if index == 0 {
            record.is_block_start = true;
        }
        if index == lirs.len() - 1 {
            match &lir.terminator {
                LirTerminator::Return { .. } => {
                    record.is_return = true;
                }
                LirTerminator::Jump { target } => {
                    record.is_jump = true;
                    if let Some(address) = lir_expression_u64(&target) {
                        record.to.insert(address);
                    } else if let Some(next) = next_block_address {
                        record.to.insert(next);
                    }
                }
                LirTerminator::Branch {
                    true_target,
                    false_target,
                    ..
                } => {
                    record.is_jump = true;
                    record.is_conditional = true;
                    if let Some(address) = lir_expression_u64(&true_target) {
                        record.to.insert(address);
                    }
                    if let Some(address) = lir_expression_u64(&false_target) {
                        record.to.insert(address);
                    }
                }
                LirTerminator::Trap => {
                    record.is_trap = true;
                }
                LirTerminator::Call { does_return, .. } => {
                    record.is_call = true;
                    if does_return.unwrap_or(true) {
                        if let Some(next) = next_block_address {
                            record.to.insert(next);
                        }
                    }
                }
                LirTerminator::FallThrough => {
                    if let Some(next) = next_block_address {
                        record.is_jump = true;
                        record.to.insert(next);
                    }
                }
                LirTerminator::Unreachable => {}
            }
        }
        record.edges = record.successors().len();
        graph.insert_instruction(record);
    }
}

fn lir_expression_u64(expression: &binlex::irs::lir::LirExpression) -> Option<u64> {
    match expression {
        binlex::irs::lir::LirExpression::Const { value, .. } => (*value).try_into().ok(),
        _ => None,
    }
}

#[pyclass(unsendable)]
pub struct LlvmModule {
    pub config: binlex::Configuration,
    pub cpu: binlex::irs::lir::LirCpu,
    state: Arc<Mutex<BuildState>>,
}

impl LlvmModule {
    pub(crate) fn from_inner(
        inner: InnerLlvmModule,
        config: binlex::Configuration,
        cpu: binlex::irs::lir::LirCpu,
        name: Option<String>,
        triple: Option<String>,
    ) -> Self {
        Self {
            config: config.clone(),
            cpu: cpu.clone(),
            state: Arc::new(Mutex::new(BuildState {
                name,
                config,
                cpu,
                triple,
                inner,
                module_override: None,
                items: Vec::new(),
                dirty: false,
            })),
        }
    }
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

#[pymethods]
impl LlvmModule {
    #[new]
    #[pyo3(signature = (name, cpu, triple=None), text_signature = "(name, cpu, triple=None)")]
    pub fn new(
        py: Python<'_>,
        name: Option<String>,
        cpu: Py<PyLirCpu>,
        triple: Option<String>,
    ) -> PyResult<Self> {
        let inner_cpu = cpu.borrow(py).inner.clone();
        let inner_config = binlex::Configuration::default();
        let state = BuildState::new(name, inner_cpu.clone(), inner_config.clone(), triple)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self {
            config: inner_config,
            cpu: inner_cpu,
            state: Arc::new(Mutex::new(state)),
        })
    }

    #[classmethod]
    #[pyo3(signature = (name, cpu, config, triple=None), text_signature = "(name, cpu, config, triple=None)")]
    pub fn with_config(
        _cls: &Bound<'_, pyo3::types::PyType>,
        py: Python<'_>,
        name: Option<String>,
        cpu: Py<PyLirCpu>,
        config: Py<Configuration>,
        triple: Option<String>,
    ) -> PyResult<Self> {
        let inner_cpu = cpu.borrow(py).inner.clone();
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let state = BuildState::new(name, inner_cpu.clone(), inner_config.clone(), triple)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self {
            config: inner_config,
            cpu: inner_cpu,
            state: Arc::new(Mutex::new(state)),
        })
    }

    #[pyo3(signature = (lir, config), text_signature = "($self, lir, config)")]
    pub fn from_lir(
        &mut self,
        py: Python<'_>,
        lir: Py<PyLirModule>,
        config: Py<Configuration>,
    ) -> PyResult<bool> {
        let lir = lir.borrow(py).inner.lock().unwrap().clone();
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        state.name = lir.name.clone();
        state.config = inner_config.clone();
        state
            .inner
            .from_lir(&lir, inner_config.clone())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        state.module_override = None;
        state.items.clear();
        state.dirty = false;
        self.config = inner_config;
        Ok(true)
    }

    #[pyo3(signature = (lir), text_signature = "($self, lir)")]
    pub fn append_block_lir(&self, py: Python<'_>, lir: Py<PyLirModule>) -> bool {
        let lir = lir.borrow(py).inner.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        state.items.push(ModuleItemDef::BlockLir { lir });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (lir, name=None), text_signature = "($self, lir, name=None)")]
    pub fn append_function_lir(
        &self,
        py: Python<'_>,
        lir: Py<PyLirModule>,
        name: Option<String>,
    ) -> bool {
        let lir = lir.borrow(py).inner.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        state.items.push(ModuleItemDef::FunctionLir { lir, name });
        state.mark_dirty();
        true
    }

    #[pyo3(name = "_create_function", signature = (name), text_signature = "($self, name)")]
    pub fn create_function(&self, name: String) -> PyResult<LiftedFunction> {
        let mut state = self.state.lock().unwrap();
        let index = state.items.len();
        state.items.push(ModuleItemDef::CreatedFunction {
            function: CreatedFunctionDef {
                name,
                body_lir: None,
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
    pub fn text(&self) -> String {
        let mut state = self.state.lock().unwrap();
        let _ = state.ensure_built();
        state.inner.text()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        println!("{}", self.text());
    }

    #[pyo3(text_signature = "($self, text)")]
    pub fn set_text(&self, text: String) -> bool {
        let mut state = self.state.lock().unwrap();
        state.module_override = Some(ModuleOverrideDef::Text(text));
        state.items.clear();
        rebuild_state(&mut state, &self.config, "llvm set text failed")
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
        self.text()
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
    pub fn append_block(&self, py: Python<'_>, block: &PyBlock, name: Option<String>) -> bool {
        let (records, address) = match block.with_inner_block(py, |inner| {
            Ok((
                instruction_records_for_block(inner.cfg, inner.address())?,
                inner.address(),
            ))
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
        if function.body_lir.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm function block append failed: function already has lir body".to_string(),
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

    #[pyo3(signature = (lir, name=None), text_signature = "($self, lir, name=None)")]
    pub fn append_block_lir(
        &self,
        py: Python<'_>,
        lir: Py<PyLirModule>,
        name: Option<String>,
    ) -> bool {
        let lir = lir.borrow(py).inner.lock().unwrap().clone();
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        if function.body_lir.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm lir block append failed: function already has lir body".to_string(),
            );
            return false;
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm lir block append failed: function already has raw llvm body".to_string(),
            );
            return false;
        }
        function
            .blocks
            .push(CreatedBlockDef::LirModule { name, lir });
        state.mark_dirty();
        true
    }

    #[pyo3(signature = (lir), text_signature = "($self, lir)")]
    pub fn set_lir(&self, py: Python<'_>, lir: Py<PyLirFunction>) -> bool {
        let lir_function = lir.borrow(py).inner.lock().unwrap().clone();
        let mut lir = LirModule::new(lir_function.name.clone());
        lir.append_function(lir_function);
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        if !function.blocks.is_empty() {
            Stderr::print_debug(
                &state.config,
                "llvm function lir append failed: function already has blocks".to_string(),
            );
            return false;
        }
        if function.raw_ir.is_some() || function.raw_bitcode.is_some() {
            Stderr::print_debug(
                &state.config,
                "llvm function lir append failed: function already has raw llvm body".to_string(),
            );
            return false;
        }
        function.body_lir = Some(lir);
        state.mark_dirty();
        true
    }

    pub fn set_text(&self, text: String) -> bool {
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        function.body_lir = None;
        function.blocks.clear();
        function.raw_bitcode = None;
        function.raw_ir = Some(text);
        state.mark_dirty();
        true
    }

    pub fn set_bitcode(&self, bitcode: Vec<u8>) -> bool {
        let mut state = self.state.lock().unwrap();
        let item = state.items.get_mut(self.index);
        let Some(ModuleItemDef::CreatedFunction { function }) = item else {
            return false;
        };
        function.body_lir = None;
        function.blocks.clear();
        function.raw_ir = None;
        function.raw_bitcode = Some(bitcode);
        state.mark_dirty();
        true
    }

    pub fn optimize_mem2reg(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(
                &state.config,
                format!("llvm function mem2reg failed: {}", err),
            );
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
                Stderr::print_debug(
                    &state.config,
                    format!("llvm function mem2reg failed: {}", err),
                );
                false
            }
        }
    }

    pub fn optimize_instcombine(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Err(err) = state.ensure_built() {
            Stderr::print_debug(
                &state.config,
                format!("llvm function instcombine failed: {}", err),
            );
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
                Stderr::print_debug(
                    &state.config,
                    format!("llvm function instcombine failed: {}", err),
                );
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

    pub fn text(&self) -> Option<String> {
        match function_preview_lifter(&self.state, self.index) {
            Ok(lifter) => Some(lifter.text()),
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(&state.config, format!("llvm function text failed: {}", err));
                None
            }
        }
    }

    pub fn print(&self) -> bool {
        match self.text() {
            Some(text) => {
                println!("{text}");
                true
            }
            None => false,
        }
    }

    pub fn bitcode(&self) -> Option<Vec<u8>> {
        match function_preview_lifter(&self.state, self.index) {
            Ok(lifter) => Some(lifter.bitcode()),
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(
                    &state.config,
                    format!("llvm function bitcode failed: {}", err),
                );
                None
            }
        }
    }

    pub fn object(&self) -> Option<Vec<u8>> {
        match function_preview_lifter(&self.state, self.index) {
            Ok(lifter) => match lifter.object() {
                Ok(bytes) => Some(bytes),
                Err(err) => {
                    let state = self.state.lock().unwrap();
                    Stderr::print_debug(
                        &state.config,
                        format!("llvm function object failed: {}", err),
                    );
                    None
                }
            },
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(
                    &state.config,
                    format!("llvm function object failed: {}", err),
                );
                None
            }
        }
    }
}

#[pymethods]
impl LiftedBlock {
    pub fn name(&self) -> String {
        let state = self.state.lock().unwrap();
        let Some(ModuleItemDef::CreatedFunction { function }) =
            state.items.get(self.function_index)
        else {
            return String::new();
        };
        match &function.blocks[self.block_index] {
            CreatedBlockDef::Cfg { name, address, .. } => {
                name.clone().unwrap_or_else(|| format!("block_{address:x}"))
            }
            CreatedBlockDef::LirModule { name, .. } => name
                .clone()
                .unwrap_or_else(|| format!("block_{}", self.block_index)),
        }
    }

    pub fn text(&self) -> Option<String> {
        match block_preview_lifter(&self.state, self.function_index, self.block_index) {
            Ok(lifter) => Some(lifter.text()),
            Err(err) => {
                let state = self.state.lock().unwrap();
                Stderr::print_debug(&state.config, format!("llvm block text failed: {}", err));
                None
            }
        }
    }

    pub fn print(&self) -> bool {
        match self.text() {
            Some(text) => {
                println!("{text}");
                true
            }
            None => false,
        }
    }
}

fn function_preview_lifter(
    state: &Arc<Mutex<BuildState>>,
    index: usize,
) -> Result<InnerLlvmModule, Error> {
    let state = state.lock().unwrap();
    let item = state
        .items
        .get(index)
        .ok_or_else(|| Error::other("lifted function is invalid"))?;
    let ModuleItemDef::CreatedFunction { function } = item else {
        return Err(Error::other("lifted function is invalid"));
    };
    let function = function.clone();
    let mut lifter = InnerLlvmModule::with_config(
        state.name.clone(),
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
) -> Result<InnerLlvmModule, Error> {
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
        body_lir: None,
        blocks: vec![block],
        raw_ir: None,
        raw_bitcode: None,
    };
    let mut lifter = InnerLlvmModule::with_config(
        state.name.clone(),
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
        CreatedBlockDef::LirModule { name, .. } => name
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
    m.add_class::<LlvmModule>()?;
    m.add_class::<LiftedFunction>()?;
    m.add_class::<LiftedBlock>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.irs.llvm", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.irs.llvm")?;
    Ok(())
}
