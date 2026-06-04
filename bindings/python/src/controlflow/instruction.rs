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

use crate::controlflow::json_value_to_py;
use crate::controlflow::Block;
use crate::controlflow::EntityKind;
use crate::controlflow::Function;
use crate::controlflow::Graph;
use crate::controlflow::Reference;
use crate::genetics::Chromosome;
use crate::irs::lir::Lir as PyLir;
use crate::irs::llvm::LlvmModule as PyLlvmModule;
#[cfg(not(target_os = "windows"))]
use crate::irs::vex::VexModule as PyVexModule;
use binlex::controlflow::EntityKind as InnerEntityKind;
use binlex::controlflow::Instruction as RawInnerInstruction;
use binlex::controlflow::Operand as InnerOperand;
use binlex::controlflow::OperandKind as InnerOperandKind;
use pyo3::class::basic::CompareOp;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::Mutex;

type InnerInstruction = RawInnerInstruction<'static>;

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum OperandKindValue {
    Register,
    Immediate,
    Memory,
    Float,
    Special,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone, Copy)]
pub struct OperandKind {
    inner: OperandKindValue,
}

impl OperandKind {
    fn from_operand_kind(inner: &InnerOperandKind) -> Self {
        let inner = match inner {
            InnerOperandKind::Register(_) => OperandKindValue::Register,
            InnerOperandKind::Immediate(_) => OperandKindValue::Immediate,
            InnerOperandKind::Memory(_) => OperandKindValue::Memory,
            InnerOperandKind::Float(_) => OperandKindValue::Float,
            InnerOperandKind::Special(_) => OperandKindValue::Special,
        };
        Self { inner }
    }
}

#[pymethods]
impl OperandKind {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Register: Self = Self {
        inner: OperandKindValue::Register,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Immediate: Self = Self {
        inner: OperandKindValue::Immediate,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Memory: Self = Self {
        inner: OperandKindValue::Memory,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Float: Self = Self {
        inner: OperandKindValue::Float,
    };
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Special: Self = Self {
        inner: OperandKindValue::Special,
    };

    pub fn __str__(&self) -> String {
        match self.inner {
            OperandKindValue::Register => "Register".to_string(),
            OperandKindValue::Immediate => "Immediate".to_string(),
            OperandKindValue::Memory => "Memory".to_string(),
            OperandKindValue::Float => "Float".to_string(),
            OperandKindValue::Special => "Special".to_string(),
        }
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&self.__str__())
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.__str__() == other.__str__(),
            CompareOp::Ne => self.__str__() != other.__str__(),
            _ => false,
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Operand {
    pub inner: Arc<Mutex<InnerOperand>>,
}

impl Operand {
    pub fn from_inner(inner: InnerOperand) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl Operand {
    pub fn kind(&self) -> OperandKind {
        let binding = self.inner.lock().unwrap();
        OperandKind::from_operand_kind(&binding.kind)
    }

    pub fn is_register(&self) -> bool {
        matches!(
            self.inner.lock().unwrap().kind,
            InnerOperandKind::Register(_)
        )
    }

    pub fn is_immediate(&self) -> bool {
        matches!(
            self.inner.lock().unwrap().kind,
            InnerOperandKind::Immediate(_)
        )
    }

    pub fn is_memory(&self) -> bool {
        matches!(self.inner.lock().unwrap().kind, InnerOperandKind::Memory(_))
    }

    pub fn is_float(&self) -> bool {
        matches!(self.inner.lock().unwrap().kind, InnerOperandKind::Float(_))
    }

    pub fn is_special(&self) -> bool {
        matches!(
            self.inner.lock().unwrap().kind,
            InnerOperandKind::Special(_)
        )
    }

    pub fn name(&self) -> Option<String> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Register(operand) => Some(operand.name.clone()),
            _ => None,
        }
    }

    pub fn value(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Immediate(operand) => {
                Ok(Some(operand.value.into_pyobject(py)?.unbind().into()))
            }
            InnerOperandKind::Float(operand) => {
                Ok(Some(operand.value.into_pyobject(py)?.unbind().into()))
            }
            _ => Ok(None),
        }
    }

    pub fn base(&self) -> Option<String> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Memory(operand) => operand.base.clone(),
            _ => None,
        }
    }

    pub fn index(&self) -> Option<String> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Memory(operand) => operand.index.clone(),
            _ => None,
        }
    }

    pub fn scale(&self) -> Option<i32> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Memory(operand) => operand.scale,
            _ => None,
        }
    }

    pub fn displacement(&self) -> Option<i64> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Memory(operand) => Some(operand.displacement),
            _ => None,
        }
    }

    pub fn segment(&self) -> Option<String> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Memory(operand) => operand.segment.clone(),
            _ => None,
        }
    }

    pub fn space(&self) -> Option<String> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Memory(operand) => operand.space.clone(),
            _ => None,
        }
    }

    pub fn special_kind(&self) -> Option<String> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Special(operand) => Some(operand.kind.clone()),
            _ => None,
        }
    }

    pub fn fields(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        let binding = self.inner.lock().unwrap();
        match &binding.kind {
            InnerOperandKind::Special(operand) => {
                let value = serde_json::to_value(&operand.fields).map_err(|error| {
                    pyo3::exceptions::PyRuntimeError::new_err(error.to_string())
                })?;
                Ok(Some(json_value_to_py(py, &value)?))
            }
            _ => Ok(None),
        }
    }

    pub fn __str__(&self) -> String {
        format!("{:?}", *self.inner.lock().unwrap())
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&serde_json::to_string(&*self.inner.lock().unwrap()).unwrap_or_default())
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        let lhs = self.inner.lock().unwrap();
        let rhs = other.inner.lock().unwrap();
        match op {
            CompareOp::Eq => *lhs == *rhs,
            CompareOp::Ne => *lhs != *rhs,
            _ => false,
        }
    }
}

/// Represent a single instruction inside a control-flow graph.
#[pyclass]
pub struct Instruction {
    pub address: u64,
    pub cfg: Py<Graph>,
    pub inner: Arc<Mutex<Option<InnerInstruction>>>,
}

impl Instruction {
    pub(crate) fn with_inner_instruction<F, R>(&self, py: Python, f: F) -> PyResult<R>
    where
        F: FnOnce(&InnerInstruction) -> PyResult<R>,
    {
        let mut cache = self.inner.lock().unwrap();

        if cache.is_none() {
            let binding = self.cfg.borrow(py);
            let inner = binding.inner.lock().unwrap();
            #[allow(mutable_transmutes)]
            #[allow(clippy::all)]
            let inner_ref: _ = unsafe { std::mem::transmute(&*inner) };
            let inner_instruction = InnerInstruction::new(self.address, inner_ref);
            if inner_instruction.is_err() {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "instruction does not exist",
                ));
            }
            *cache = Some(inner_instruction.unwrap());
        }

        f(cache.as_ref().unwrap())
    }
}

#[pymethods]
impl Instruction {
    #[new]
    #[pyo3(text_signature = "(address, cfg)")]
    /// Create an instruction wrapper for the instruction at `address` in `cfg`.
    pub fn new(address: u64, cfg: Py<Graph>) -> PyResult<Self> {
        Ok(Self {
            address,
            cfg,
            inner: Arc::new(Mutex::new(None)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the address of the instruction.
    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the entity kind for this instruction.
    pub fn kind(&self) -> EntityKind {
        EntityKind::from_inner(InnerEntityKind::Instruction)
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the chromosome associated with this instruction.
    ///
    /// # Returns
    /// - `PyResult<Chromosome>`: The chromosome associated with this instruction.
    pub fn chromosome(&self, py: Python) -> PyResult<Chromosome> {
        self.with_inner_instruction(py, |instruction| {
            let binding = self.cfg.borrow(py);
            let inner_config = binding.inner.lock().unwrap().config.clone();
            let inner_chromosome = instruction.chromosome();
            Ok(Chromosome {
                inner: Arc::new(Mutex::new(inner_chromosome)),
                minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
                minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
                minhash_seed: inner_config.chromosomes.minhash.seed,
                tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
            })
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn llvm(&self, py: Python<'_>) -> PyResult<Py<PyLlvmModule>> {
        self.with_inner_instruction(py, |instruction| {
            let inner = instruction.llvm()?;
            let cpu = binlex::irs::lir::LirCpu::from_architecture(instruction.architecture)
                .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
            Py::new(
                py,
                PyLlvmModule::from_inner(inner, instruction.config.clone(), cpu, None, None),
            )
        })
    }

    #[cfg(not(target_os = "windows"))]
    #[pyo3(text_signature = "($self)")]
    pub fn vex(&self, py: Python<'_>) -> PyResult<Py<PyVexModule>> {
        self.with_inner_instruction(py, |instruction| {
            let inner = instruction.vex()?;
            Py::new(
                py,
                PyVexModule::from_inner(inner, instruction.config.clone()),
            )
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the successor blocks reached by this instruction.
    pub fn successor_blocks(&self, py: Python) -> PyResult<Vec<Block>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction
                .successor_blocks()
                .into_iter()
                .map(|block| {
                    Block::new(block.address(), self.cfg.clone_ref(py))
                        .expect("failed to get successor block")
                })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the outgoing successor block references.
    pub fn successor_block_references(&self, py: Python) -> PyResult<Vec<Reference>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction
                .successor_block_references()
                .into_iter()
                .map(|reference| Reference { inner: reference })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the sequential fallthrough instruction address, if known.
    pub fn fallthrough(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.fallthrough()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the explicit branch target addresses of this instruction.
    pub fn branches(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.branches()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all outgoing CFG successor addresses for this instruction.
    pub fn successors(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.successors()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return whether this instruction has an indirect branch target.
    pub fn has_indirect_target(&self, py: Python) -> PyResult<bool> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.has_indirect_target()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return whether this instruction is conditional.
    pub fn is_conditional(&self, py: Python) -> PyResult<bool> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.is_conditional()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the directly called functions.
    pub fn callees(&self, py: Python) -> PyResult<Vec<Function>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction
                .callees()
                .into_iter()
                .map(|callee| {
                    Function::new(callee.address(), self.cfg.clone_ref(py))
                        .expect("failed to get callee")
                })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the direct outgoing call references.
    pub fn callee_references(&self, py: Python) -> PyResult<Vec<Reference>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(instruction
                .callee_references()
                .into_iter()
                .map(|reference| Reference { inner: reference })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the size of the instruction in bytes.
    pub fn size(&self, py: Python) -> PyResult<usize> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.size()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the decoded raw bytes for this instruction.
    pub fn bytes(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        self.with_inner_instruction(py, |instruction| {
            Ok(PyBytes::new(py, &instruction.bytes()).unbind())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the decoded mnemonic of the instruction.
    pub fn mnemonic(&self, py: Python<'_>) -> PyResult<String> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.mnemonic()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the canonical disassembly text of the instruction.
    pub fn disassembly(&self, py: Python<'_>) -> PyResult<String> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.disassembly()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return normalized decoded operands.
    pub fn operands(&self, py: Python<'_>) -> PyResult<Vec<Py<Operand>>> {
        self.with_inner_instruction(py, |instruction| {
            instruction
                .operands()
                .into_iter()
                .map(|operand| Py::new(py, Operand::from_inner(operand)))
                .collect()
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the canonical LIR for this instruction, building it on demand if possible.
    pub fn lir(&self, py: Python) -> PyResult<Option<Py<PyLir>>> {
        self.with_inner_instruction(py, |instruction| {
            let Some(lir) = instruction.lir.clone().or_else(|| instruction.build_lir()) else {
                return Ok(None);
            };
            Ok(Some(Py::new(py, PyLir::from_inner(lir))?))
        })
    }

    #[pyo3(text_signature = "($self, lir)")]
    /// Replace the canonical LIR attached to this instruction and persist it in the CFG.
    pub fn set_lir(&self, py: Python<'_>, lir: Py<PyLir>) -> PyResult<()> {
        let replacement = lir.borrow(py).inner.lock().unwrap().clone();
        let mut updated = self.with_inner_instruction(py, |instruction| Ok(instruction.clone()))?;
        updated.set_lir(replacement);
        {
            let binding = self.cfg.borrow(py);
            let mut inner = binding.inner.lock().unwrap();
            inner.update_instruction(updated.clone());
        }
        *self.inner.lock().unwrap() = Some(updated);
        Ok(())
    }

    pub fn __str__(&self) -> String {
        format!("Instruction(address=0x{:x})", self.address)
    }
}

#[pymodule]
#[pyo3(name = "instruction")]
pub fn instruction_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OperandKind>()?;
    m.add_class::<Operand>()?;
    m.add_class::<Instruction>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.instruction", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.instruction")?;
    Ok(())
}
