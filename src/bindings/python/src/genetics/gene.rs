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

use pyo3::prelude::*;
use binlex::genetics::Gene as InnerGene;
use std::sync::Arc;
use std::sync::Mutex;
use pyo3::exceptions::PyRuntimeError;

#[pyclass]
#[derive(Debug, Clone)]
pub struct Gene {
    pub inner: Arc<Mutex<InnerGene>>,
}

#[pymethods]
impl Gene {
    #[staticmethod]
    #[pyo3(text_signature = "(c)")]
    pub fn from_char(c: char) -> PyResult<Self> {
        let inner = InnerGene::from_char(c)?;
        Ok(Self { inner: Arc::new(Mutex::new(inner)) })
    }

    #[staticmethod]
    #[pyo3(text_signature = "(pattern, config)")]
    pub fn from_value(v: u8) -> PyResult<Self> {
        let inner = InnerGene::from_value(v);
        Ok(Self{inner: Arc::new(Mutex::new(inner))})
    }

    #[staticmethod]
    #[pyo3(text_signature = "()")]
    pub fn from_wildcard() -> PyResult<Self> {
        let inner = InnerGene::from_wildcard();
        Ok(Self{inner: Arc::new(Mutex::new(inner))})
    }

    #[pyo3(text_signature = "($self, c)")]
    pub fn mutate(&mut self, c: char) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .mutate(c)
            .map_err(|error| PyRuntimeError::new_err(format!("{}", error)))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn wildcard(&self) -> Option<String> {
        self.inner.lock().unwrap().wildcard()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn is_wildcard(&self) -> bool {
        self.inner.lock().unwrap().is_wildcard()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn is_value(&self) -> bool {
        self.inner.lock().unwrap().is_value()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_char(&self) -> String {
        self.inner.lock().unwrap().to_char()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    pub fn __str__(&self) -> String {
        self.to_char()
    }
}


#[pymodule]
#[pyo3(name = "gene")]
pub fn gene_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Gene>()?;
     py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.genetics.gene", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.genetics.gene")?;
    Ok(())
}
