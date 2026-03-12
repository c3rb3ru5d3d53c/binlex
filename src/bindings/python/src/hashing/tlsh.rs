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

use binlex::hashing::tlsh::TLSH as InnerTLSH;
use pyo3::prelude::*;

#[pyclass]
pub struct TLSH {
    bytes: Vec<u8>,
}

#[pymethods]
impl TLSH {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn hexdigest(&self, mininum_byte_size: usize) -> Option<String> {
        InnerTLSH::new(&self.bytes, mininum_byte_size).hexdigest()
    }

    #[staticmethod]
    #[pyo3(text_signature = "(lhs, rhs)")]
    pub fn compare(lhs: String, rhs: String) -> Option<f64> {
        InnerTLSH::compare(lhs, rhs)
    }
}

#[pymodule]
#[pyo3(name = "tlsh")]
pub fn tlsh_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TLSH>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.tlsh", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.tlsh")?;
    Ok(())
}
