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
use binlex::assemblers::Assembler as InnerAssembler;
use binlex::assemblers::AssemblerBackend;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};

#[pyclass]
pub struct Assembler {
    inner: InnerAssembler,
}

#[pymethods]
impl Assembler {
    #[new]
    #[pyo3(text_signature = "(architecture, config)")]
    pub fn new(
        py: Python<'_>,
        architecture: Py<Architecture>,
        config: Py<Config>,
    ) -> PyResult<Self> {
        let architecture = architecture.borrow(py).inner;
        let config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerAssembler::new(architecture, config, AssemblerBackend::LLVM)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[pyo3(text_signature = "($self, address, text)")]
    pub fn assemble(&self, py: Python<'_>, address: u64, text: String) -> PyResult<Py<PyBytes>> {
        let bytes = self
            .inner
            .assemble(address, &text)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }
}

#[pymodule]
#[pyo3(name = "_llvm_assembler")]
pub fn llvm_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Assembler>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.assemblers._llvm_assembler", m)?;
    m.setattr(
        "__name__",
        "binlex_bindings.binlex.assemblers._llvm_assembler",
    )?;
    Ok(())
}
