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

use binlex::hashing::phash::PHash as InnerPHash;
use pyo3::prelude::*;

/// Compute and compare DCT-based perceptual hashes for image bytes.
#[pyclass]
pub struct PHash {
    bytes: Vec<u8>,
}

#[pymethods]
impl PHash {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    /// Create a perceptual hash helper for the provided image bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the hexadecimal perceptual hash digest for the stored image bytes.
    pub fn hexdigest(&self) -> Option<String> {
        InnerPHash::new(&self.bytes).hexdigest()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the perceptual hash digest as a normalized vector.
    pub fn vector(&self) -> Option<Vec<f32>> {
        InnerPHash::new(&self.bytes).vector()
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this perceptual hash object against another perceptual hash object.
    pub fn compare(&self, other: &Self) -> Option<f64> {
        InnerPHash::new(&self.bytes).compare(&InnerPHash::new(&other.bytes))
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this perceptual hash object against a perceptual hash digest.
    pub fn compare_hexdigest(&self, other: String) -> Option<f64> {
        InnerPHash::new(&self.bytes).compare_hexdigest(&other)
    }

    #[staticmethod]
    #[pyo3(text_signature = "(lhs, rhs)")]
    /// Compare two perceptual hash digests and return their similarity score.
    pub fn compare_hexdigests(lhs: String, rhs: String) -> Option<f64> {
        InnerPHash::compare_hexdigests(&lhs, &rhs)
    }
}

#[pymodule]
#[pyo3(name = "phash")]
pub fn phash_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PHash>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.phash", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.phash")?;
    Ok(())
}
