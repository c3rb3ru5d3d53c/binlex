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

use binlex::hashing::dhash::DHash as InnerDHash;
use pyo3::prelude::*;

/// Compute and compare difference perceptual hashes for image bytes.
#[pyclass]
pub struct DHash {
    bytes: Vec<u8>,
}

#[pymethods]
impl DHash {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    /// Create a difference hash helper for the provided image bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the hexadecimal difference hash digest for the stored image bytes.
    pub fn hexdigest(&self) -> Option<String> {
        InnerDHash::new(&self.bytes).hexdigest()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the difference hash digest as a normalized vector.
    pub fn vector(&self) -> Option<Vec<f32>> {
        InnerDHash::new(&self.bytes).vector()
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this difference hash object against another difference hash object.
    pub fn compare(&self, other: &Self) -> Option<f64> {
        InnerDHash::new(&self.bytes).compare(&InnerDHash::new(&other.bytes))
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this difference hash object against a difference hash digest.
    pub fn compare_hexdigest(&self, other: String) -> Option<f64> {
        InnerDHash::new(&self.bytes).compare_hexdigest(&other)
    }

    #[staticmethod]
    #[pyo3(text_signature = "(lhs, rhs)")]
    /// Compare two difference hash digests and return their similarity score.
    pub fn compare_hexdigests(lhs: String, rhs: String) -> Option<f64> {
        InnerDHash::compare_hexdigests(&lhs, &rhs)
    }
}

#[pymodule]
#[pyo3(name = "dhash")]
pub fn dhash_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<DHash>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.dhash", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.dhash")?;
    Ok(())
}
