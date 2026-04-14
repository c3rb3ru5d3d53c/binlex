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
use crate::Config;
use crate::controlflow::Graph;
use crate::controlflow::json_value_to_py;
use crate::genetics::Chromosome;
use crate::imaging::Imaging;
use crate::semantics::InstructionSemantics as PyInstructionSemantics;
use binlex::controlflow::Instruction as InnerInstruction;
use binlex::controlflow::InstructionJson as InnerInstructionJson;
use binlex::genetics::Chromosome as InnerChromosome;
use binlex::hex;
use binlex::imaging::Imaging as InnerImaging;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

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
        serde_json::to_string_pretty(&*self.inner.lock().unwrap())
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

    #[getter]
    /// Return the address of the instruction.
    pub fn get_address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the chromosome associated with this instruction.
    ///
    /// # Returns
    /// - `PyResult<Option<Chromosome>>`: The chromosome associated with this instruction.
    pub fn chromosome(&self, py: Python) -> PyResult<Option<Chromosome>> {
        self.with_inner_instruction(py, |instruction| {
            let binding = self.cfg.borrow(py);
            let inner_config = binding.inner.lock().unwrap().config.clone();
            let inner_chromosome = instruction.chromosome();
            Ok(Some(Chromosome {
                inner: Arc::new(Mutex::new(inner_chromosome)),
                minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
                minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
                minhash_seed: inner_config.chromosomes.minhash.seed,
                tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
            }))
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
    /// Return the imaging pipeline for the instruction bytes.
    pub fn imaging(&self, py: Python) -> PyResult<Imaging> {
        self.with_inner_instruction(py, |instruction| {
            Ok(Imaging::from_inner(instruction.imaging()))
        })
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
    m.add_class::<InstructionJsonDeserializer>()?;
    m.add_class::<Instruction>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.instruction", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.instruction")?;
    Ok(())
}
