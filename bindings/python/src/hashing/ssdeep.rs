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

use binlex::hashing::ssdeep::SSDeep as InnerSSDeep;
use pyo3::prelude::*;

/// Compute and compare ssdeep-style fuzzy hashes.
#[pyclass]
pub struct SSDeep {
    pub(crate) bytes: Vec<u8>,
}

#[pymethods]
impl SSDeep {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    /// Create an ssdeep helper for the provided bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the ssdeep digest for the stored bytes.
    pub fn hexdigest(&self) -> Option<String> {
        InnerSSDeep::new(&self.bytes).hexdigest()
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this ssdeep object against another ssdeep object.
    pub fn compare(&self, other: &Self) -> Option<f64> {
        InnerSSDeep::new(&self.bytes).compare(&InnerSSDeep::new(&other.bytes))
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this ssdeep object against an ssdeep digest.
    pub fn compare_hexdigest(&self, other: String) -> Option<f64> {
        InnerSSDeep::new(&self.bytes).compare_hexdigest(&other)
    }

    #[staticmethod]
    #[pyo3(text_signature = "(lhs, rhs)")]
    /// Compare two ssdeep digests and return their similarity score.
    pub fn compare_hexdigests(lhs: String, rhs: String) -> Option<f64> {
        InnerSSDeep::compare_hexdigests(&lhs, &rhs)
    }
}

#[pymodule]
#[pyo3(name = "ssdeep")]
pub fn ssdeep_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SSDeep>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.ssdeep", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.ssdeep")?;
    Ok(())
}
