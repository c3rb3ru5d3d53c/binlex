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

use crate::controlflow::Graph;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeSimilarity;
use crate::Config;
use binlex::controlflow::Instruction as InnerInstruction;
use pyo3::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass]
pub struct Instruction {
    pub address: u64,
    pub cfg: Py<Graph>,
    pub inner: Arc<Mutex<Option<InnerInstruction>>>,
}

impl Instruction {
    fn with_inner_instruction<F, R>(&self, py: Python, f: F) -> PyResult<R>
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
    pub fn new(address: u64, cfg: Py<Graph>) -> PyResult<Self> {
        Ok(Self {
            address,
            cfg,
            inner: Arc::new(Mutex::new(None)),
        })
    }

    #[getter]
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
            let inner_config = self.cfg.borrow(py).inner.lock().unwrap().config.clone();
            let config = Py::new(
                py,
                Config {
                    inner: Arc::new(Mutex::new(inner_config)),
                },
            )
            .unwrap();
            let pattern = instruction.pattern();
            let chromosome = Chromosome::new(py, pattern, config).ok();
            Ok(chromosome)
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Compares this instruction with another returning the similarity.
    ///
    /// # Returns
    ///
    /// Returns an `Option<ChromosomeSimilarity>` reprenting the similarity between this instruction and another.
    pub fn compare(
        &self,
        py: Python,
        rhs: Py<Instruction>,
    ) -> PyResult<Option<ChromosomeSimilarity>> {
        self.with_inner_instruction(py, |instruction| {
            let rhs_address = rhs.borrow(py).address;
            let rhs_binding_0 = rhs.borrow(py);
            let rhs_binding_1 = rhs_binding_0.cfg.borrow(py);
            let rhs_cfg = rhs_binding_1.inner.lock().unwrap();
            let rhs_inner =
                InnerInstruction::new(rhs_address, &rhs_cfg).expect("rhs instruction is invalid");
            let inner = instruction.compare(&rhs_inner);
            if inner.is_none() {
                return Ok(None);
            }
            let similarity = ChromosomeSimilarity {
                inner: Arc::new(Mutex::new(inner.unwrap())),
            };
            Ok(Some(similarity))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn blocks(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.blocks()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn next(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.next()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.to()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn functions(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.functions()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self, py: Python) -> PyResult<usize> {
        self.with_inner_instruction(py, |instruction| Ok(instruction.size()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self, py: Python) -> PyResult<String> {
        self.with_inner_instruction(py, |instruction| {
            instruction
                .json()
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
        })
    }

    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }

    #[pyo3(text_signature = "($self)")]
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
    m.add_class::<Instruction>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.instruction", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.instruction")?;
    Ok(())
}
