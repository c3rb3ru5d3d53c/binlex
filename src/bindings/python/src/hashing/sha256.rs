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

use binlex::hashing::sha256::SHA256 as InnerSHA256;

#[pyclass]
pub struct SHA256 {
    pub bytes: Vec<u8>,
}

#[pymethods]
impl SHA256 {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn hexdigest(&self) -> Option<String> {
        InnerSHA256::new(&self.bytes).hexdigest()
    }
}

#[pymodule]
#[pyo3(name = "sha256")]
pub fn sha256_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SHA256>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.sha256", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.sha256")?;
    Ok(())
}
