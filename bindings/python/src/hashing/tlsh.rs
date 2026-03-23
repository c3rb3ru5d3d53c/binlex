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

/// Compute and compare TLSH similarity hashes.
#[pyclass]
pub struct TLSH {
    pub(crate) bytes: Vec<u8>,
}

#[pymethods]
impl TLSH {
    #[new]
    #[pyo3(text_signature = "(bytes)")]
    /// Create a TLSH helper for the provided bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the TLSH hexadecimal digest, if the byte sequence is large enough.
    pub fn hexdigest(&self, mininum_byte_size: usize) -> Option<String> {
        InnerTLSH::new(&self.bytes, mininum_byte_size).hexdigest()
    }

    #[pyo3(text_signature = "($self, mininum_byte_size)")]
    /// Return the TLSH digest as a normalized vector, if the byte sequence is large enough.
    pub fn vector(&self, mininum_byte_size: usize) -> Option<Vec<f32>> {
        InnerTLSH::new(&self.bytes, mininum_byte_size).vector()
    }

    #[pyo3(text_signature = "($self, other, mininum_byte_size)")]
    /// Compare this TLSH object against another TLSH object.
    pub fn compare(&self, other: &Self, mininum_byte_size: usize) -> Option<f64> {
        InnerTLSH::new(&self.bytes, mininum_byte_size)
            .compare(&InnerTLSH::new(&other.bytes, mininum_byte_size))
    }

    #[pyo3(text_signature = "($self, other, mininum_byte_size)")]
    /// Compare this TLSH object against a TLSH digest.
    pub fn compare_hexdigest(&self, other: String, mininum_byte_size: usize) -> Option<f64> {
        InnerTLSH::new(&self.bytes, mininum_byte_size).compare_hexdigest(&other)
    }

    #[staticmethod]
    #[pyo3(text_signature = "(lhs, rhs)")]
    /// Compare two TLSH digests and return their similarity score.
    pub fn compare_hexdigests(lhs: String, rhs: String) -> Option<f64> {
        InnerTLSH::compare_hexdigests(&lhs, &rhs)
    }
}

#[pymodule]
#[pyo3(name = "tlsh")]
pub fn tlsh_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<TLSH>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.tlsh", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.tlsh")?;
    Ok(())
}
