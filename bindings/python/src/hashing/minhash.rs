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

use binlex::hashing::minhash::MinHash32 as InnerMinHash32;

/// Compute and compare MinHash digests for byte sequences.
#[pyclass]
pub struct MinHash32 {
    pub(crate) num_hashes: usize,
    pub(crate) shingle_size: usize,
    pub(crate) seed: u64,
    pub(crate) bytes: Vec<u8>,
}

#[pymethods]
impl MinHash32 {
    #[new]
    #[pyo3(text_signature = "(bytes, num_hashes, shingle_size, seed)")]
    /// Create a MinHash helper with the given hashing parameters.
    pub fn new(bytes: Vec<u8>, num_hashes: usize, shingle_size: usize, seed: u64) -> Self {
        Self {
            bytes,
            num_hashes,
            shingle_size,
            seed,
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the hexadecimal MinHash digest for the stored bytes.
    pub fn hexdigest(&self) -> Option<String> {
        InnerMinHash32::new(&self.bytes, self.num_hashes, self.shingle_size, self.seed).hexdigest()
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this MinHash object against another MinHash object.
    pub fn compare(&self, other: &Self) -> Option<f64> {
        InnerMinHash32::new(&self.bytes, self.num_hashes, self.shingle_size, self.seed).compare(
            &InnerMinHash32::new(
                &other.bytes,
                other.num_hashes,
                other.shingle_size,
                other.seed,
            ),
        )
    }

    #[pyo3(text_signature = "($self, other)")]
    /// Compare this MinHash object against a MinHash digest.
    pub fn compare_hexdigest(&self, other: String) -> Option<f64> {
        InnerMinHash32::new(&self.bytes, self.num_hashes, self.shingle_size, self.seed)
            .compare_hexdigest(&other)
    }

    #[staticmethod]
    #[pyo3(text_signature = "(lhs, rhs)")]
    /// Compare two MinHash digests and return their similarity score.
    pub fn compare_hexdigests(lhs: String, rhs: String) -> Option<f64> {
        InnerMinHash32::compare_hexdigests(&lhs, &rhs)
    }
}

#[pymodule]
#[pyo3(name = "minhash")]
pub fn minhash_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MinHash32>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.hashing.minhash", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.hashing.minhash")?;
    Ok(())
}
