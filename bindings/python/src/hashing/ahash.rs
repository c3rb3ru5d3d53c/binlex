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

use binlex::hashing::ahash::AHash as InnerAHash;
use pyo3::prelude::*;

/// Compute and compare average perceptual hashes for image bytes.
#[pyclass]
pub struct AHash {
    bytes: Vec<u8>,
}

#[pymethods]
impl AHash {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    /// Create an average hash helper for the provided image bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the hexadecimal average hash digest for the stored image bytes.
    pub fn hexdigest(&self) -> Option<String> {
        InnerAHash::new(&self.bytes).hexdigest()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the average hash digest as a normalized vector.
    pub fn vector(&self) -> Option<Vec<f32>> {
        InnerAHash::new(&self.bytes).vector()
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this average hash object against another average hash object.
    pub fn compare(&self, other: &Self) -> Option<f64> {
        InnerAHash::new(&self.bytes).compare(&InnerAHash::new(&other.bytes))
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this average hash object against an average hash digest.
    pub fn compare_hexdigest(&self, other: String) -> Option<f64> {
        InnerAHash::new(&self.bytes).compare_hexdigest(&other)
    }

    #[staticmethod]
    #[pyo3(text_signature = "(lhs, rhs)")]
    /// Compare two average hash digests and return their similarity score.
    pub fn compare_hexdigests(lhs: String, rhs: String) -> Option<f64> {
        InnerAHash::compare_hexdigests(&lhs, &rhs)
    }
}

#[pymodule]
#[pyo3(name = "ahash")]
pub fn ahash_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AHash>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.ahash", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.ahash")?;
    Ok(())
}
