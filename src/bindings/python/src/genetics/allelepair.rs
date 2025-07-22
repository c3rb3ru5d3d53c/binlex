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

use crate::genetics::Gene;
use binlex::genetics::AllelePair as InnerAllelePair;
use pyo3::prelude::*;
use pyo3::Py;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass]
pub struct AllelePair {
    pub inner: Arc<Mutex<InnerAllelePair>>,
}

#[pymethods]
impl AllelePair {
    #[new]
    #[pyo3(text_signature = "(low, high)")]
    pub fn new(py: Python, low: Py<Gene>, high: Py<Gene>) -> PyResult<Self> {
        let high_binding = high.borrow(py);
        #[allow(clippy::all)]
        let high_inner = high_binding.inner.lock().unwrap().clone();
        let low_binding = low.borrow(py);
        #[allow(clippy::all)]
        let low_inner = low_binding.inner.lock().unwrap().clone();
        let inner = InnerAllelePair::new(high_inner, low_inner);
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_mutations(&self) -> usize {
        self.inner.lock().unwrap().number_of_mutations()
    }

    #[pyo3(text_signature = "($self, low, high)")]
    pub fn mutate(&mut self, py: Python, low: Py<Gene>, high: Py<Gene>) {
        let high_binding = high.borrow(py);
        #[allow(clippy::all)]
        let high_inner = high_binding.inner.lock().unwrap().clone();
        let low_binding = low.borrow(py);
        #[allow(clippy::all)]
        let low_inner = low_binding.inner.lock().unwrap().clone();
        self.inner.lock().unwrap().mutate(high_inner, low_inner);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn genes(&self) -> Vec<Gene> {
        vec![self.low(), self.low()]
    }

    #[staticmethod]
    #[pyo3(text_signature = "(pair)")]
    pub fn from_string(pair: String) -> PyResult<Self> {
        let inner = InnerAllelePair::from_string(pair)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn low(&self) -> Gene {
        let low = self.inner.lock().unwrap().low;
        Gene {
            inner: Arc::new(Mutex::new(low)),
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn high(&self) -> Gene {
        let high = self.inner.lock().unwrap().high;
        Gene {
            inner: Arc::new(Mutex::new(high)),
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        println!("{}", self.inner.lock().unwrap());
    }

    pub fn __str__(&self) -> String {
        self.inner.lock().unwrap().to_string()
    }
}

#[pymodule]
#[pyo3(name = "allelepair")]
pub fn allelepair_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AllelePair>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.genetics.allelepair", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.genetics.allelepair")?;
    Ok(())
}
