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
use crate::controlflow::Graph;
use crate::genetics::Chromosome;
use crate::imaging::Imaging;
use crate::semantics::InstructionSemantics as PyInstructionSemantics;
use crate::Architecture;
use crate::Config;
use binlex::controlflow::Instruction as InnerInstruction;
use binlex::controlflow::InstructionJson as InnerInstructionJson;
use binlex::controlflow::Operand as InnerOperand;
use binlex::controlflow::OperandKind as InnerOperandKind;
use binlex::genetics::Chromosome as InnerChromosome;
use binlex::hex;
use binlex::imaging::Imaging as InnerImaging;
use binlex::io::Stderr;
use pyo3::class::basic::CompareOp;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyType};
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::Mutex;

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
    #[staticmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let json_module = py.import("json")?;
        let json_str = json_module
            .call_method1("dumps", (data,))?
            .extract::<String>()?;
        let inner: InnerOperand = serde_json::from_str(&json_str)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

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

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = serde_json::to_value(self.inner.lock().unwrap().clone())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        json_value_to_py(py, &value)
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __str__(&self) -> PyResult<String> {
        self.json()
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

/// Deserialize a serialized instruction JSON payload back into typed accessors.
#[pyclass]
pub struct InstructionJsonDeserializer {
    pub inner: Arc<Mutex<InnerInstructionJson>>,
    pub config: binlex::Config,
    chromosome_minhash_num_hashes: usize,
    chromosome_minhash_shingle_size: usize,
    chromosome_minhash_seed: u64,
    chromosome_tlsh_minimum_byte_size: usize,
}

#[pymethods]
impl InstructionJsonDeserializer {
    #[new]
    #[pyo3(text_signature = "(string, config)")]
    pub fn new(py: Python<'_>, string: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner: InnerInstructionJson = serde_json::from_str(&string)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        if inner.type_ != "instruction" {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "serialized payload is not an instruction",
            ));
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            config: inner_config.clone(),
            chromosome_minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
            chromosome_minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
            chromosome_minhash_seed: inner_config.chromosomes.minhash.seed,
            chromosome_tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
        })
    }

    pub fn architecture(&self) -> PyResult<Architecture> {
        let inner = binlex::Architecture::from_string(&self.inner.lock().unwrap().architecture)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(Architecture { inner })
    }

    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address
    }

    pub fn bytes(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let bytes = hex::decode(&self.inner.lock().unwrap().bytes)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }

    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().size
    }

    pub fn mnemonic(&self) -> String {
        self.inner.lock().unwrap().mnemonic.clone()
    }

    pub fn disassembly(&self) -> String {
        self.inner.lock().unwrap().disassembly.clone()
    }

    pub fn operands(&self, py: Python<'_>) -> PyResult<Vec<Py<Operand>>> {
        self.inner
            .lock()
            .unwrap()
            .operands
            .iter()
            .cloned()
            .map(|operand| Py::new(py, Operand::from_inner(operand)))
            .collect()
    }

    pub fn blocks(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().blocks.clone()
    }

    pub fn next(&self) -> Option<u64> {
        self.inner.lock().unwrap().next
    }

    pub fn to(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().to.clone()
    }

    pub fn has_indirect_target(&self) -> bool {
        self.inner.lock().unwrap().has_indirect_target
    }

    pub fn functions(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().functions.clone()
    }

    pub fn chromosome(&self) -> PyResult<Chromosome> {
        let binding = self.inner.lock().unwrap();
        let bytes =
            hex::decode(&binding.bytes).map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        let mask = if binding.chromosome.mask.is_empty() {
            vec![0; bytes.len()]
        } else {
            hex::decode(&binding.chromosome.mask)
                .map_err(pyo3::exceptions::PyRuntimeError::new_err)?
        };
        let chromosome = InnerChromosome::new(bytes, mask, self.config.clone())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Chromosome {
            inner: Arc::new(Mutex::new(chromosome)),
            minhash_num_hashes: self.chromosome_minhash_num_hashes,
            minhash_shingle_size: self.chromosome_minhash_shingle_size,
            minhash_seed: self.chromosome_minhash_seed,
            tlsh_minimum_byte_size: self.chromosome_tlsh_minimum_byte_size,
        })
    }

    pub fn imaging(&self) -> PyResult<Imaging> {
        let bytes = hex::decode(&self.inner.lock().unwrap().bytes)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(Imaging::from_inner(InnerImaging::new(
            bytes,
            self.config.clone(),
        )))
    }

    pub fn processors(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = serde_json::to_value(self.inner.lock().unwrap().processors.clone())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        json_value_to_py(py, &value)
    }

    pub fn processor(&self, py: Python<'_>, name: String) -> PyResult<Py<PyAny>> {
        let value = self
            .inner
            .lock()
            .unwrap()
            .processors
            .as_ref()
            .and_then(|items| items.get(&name))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        json_value_to_py(py, &value)
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let json_str = self.json()?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    pub fn semantics(&self, py: Python<'_>) -> PyResult<Option<Py<PyInstructionSemantics>>> {
        let binding = self.inner.lock().unwrap();
        let Some(semantics) = binding.semantics.as_ref() else {
            return Ok(None);
        };
        Ok(Some(Py::new(
            py,
            PyInstructionSemantics::from_inner(semantics.clone().into_semantics()),
        )?))
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn print(&self) -> PyResult<()> {
        println!("{}", self.json()?);
        Ok(())
    }

    pub fn __str__(&self) -> PyResult<String> {
        self.json()
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
    /// Return the block addresses containing this instruction.
    pub fn blocks(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.blocks()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the next linear instruction address, if known.
    pub fn next(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.next()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the successor addresses targeted by this instruction.
    pub fn to(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.to()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return whether this instruction has an indirect branch target.
    pub fn has_indirect_target(&self, py: Python) -> PyResult<bool> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.has_indirect_target()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the function addresses associated with this instruction.
    pub fn functions(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.functions()))
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
    /// Return the imaging pipeline for the instruction bytes.
    pub fn imaging(&self, py: Python) -> PyResult<Imaging> {
        self.with_inner_instruction(py, |instruction| {
            Ok(Imaging::from_inner(instruction.imaging()))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the LLVM embedding vector for this instruction, if available.
    pub fn embedding(&self, py: Python) -> PyResult<Option<Vec<f32>>> {
        let config = self.cfg.borrow(py).inner.lock().unwrap().config.clone();
        match self.with_inner_instruction(py, |instruction| Ok(instruction.embeddings().llvm())) {
            Ok(result) => Ok(result),
            Err(error) => {
                Stderr::print_debug(
                    &config,
                    format!(
                        "llvm instruction embedding skipped address=0x{:x} error={}",
                        self.address, error
                    ),
                );
                Ok(None)
            }
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all processor outputs attached to this instruction.
    pub fn processors(&self, py: Python) -> PyResult<Py<PyAny>> {
        self.with_inner_instruction(py, |instruction| {
            let value = serde_json::to_value(instruction.processors())
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
            json_value_to_py(py, &value)
        })
    }

    #[pyo3(text_signature = "($self, name)")]
    /// Return a single processor output attached to this instruction.
    pub fn processor(&self, py: Python, name: String) -> PyResult<Py<PyAny>> {
        self.with_inner_instruction(py, |instruction| {
            let value = instruction.processor(&name);
            json_value_to_py(py, &value)
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the canonical semantics attached to this instruction, if present.
    pub fn semantics(&self, py: Python) -> PyResult<Option<Py<PyInstructionSemantics>>> {
        self.with_inner_instruction(py, |instruction| {
            let Some(semantics) = instruction.semantics.as_ref() else {
                return Ok(None);
            };
            Ok(Some(Py::new(
                py,
                PyInstructionSemantics::from_inner(semantics.clone()),
            )?))
        })
    }

    #[pyo3(text_signature = "($self, semantics)")]
    /// Replace the canonical semantics attached to this instruction and persist it in the CFG.
    pub fn set_semantics(
        &self,
        py: Python<'_>,
        semantics: Py<PyInstructionSemantics>,
    ) -> PyResult<()> {
        let replacement = semantics.borrow(py).inner.lock().unwrap().clone();
        let mut updated = self.with_inner_instruction(py, |instruction| Ok(instruction.clone()))?;
        updated.set_semantics(replacement);
        {
            let binding = self.cfg.borrow(py);
            let mut inner = binding.inner.lock().unwrap();
            inner.update_instruction(updated.clone());
        }
        *self.inner.lock().unwrap() = Some(updated);
        Ok(())
    }

    #[pyo3(text_signature = "($self)")]
    /// Convert the instruction to a Python dictionary.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the JSON representation of the instruction.
    pub fn json(&self, py: Python) -> PyResult<String> {
        self.with_inner_instruction(py, |instruction| {
            instruction
                .json()
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
        })
    }

    /// Return the JSON representation when converted to a string.
    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the instruction representation to stdout.
    pub fn print(&self, py: Python) -> PyResult<()> {
        self.with_inner_instruction(py, |instruction| {
            instruction.print();
            Ok(())
        })
    }
}

#[pymodule]
#[pyo3(name = "instruction")]
pub fn instruction_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<OperandKind>()?;
    m.add_class::<Operand>()?;
    m.add_class::<InstructionJsonDeserializer>()?;
    m.add_class::<Instruction>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.instruction", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.instruction")?;
    Ok(())
}
