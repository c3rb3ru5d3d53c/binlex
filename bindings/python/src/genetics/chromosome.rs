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

use crate::genetics::AllelePair;
use crate::hashing::{MinHash32, SHA256, TLSH};
use crate::imaging::{PNG, SVG};
use crate::Config;
use binlex::genetics::Chromosome as InnerChromosome;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::sync::Arc;
use std::sync::Mutex;

/// Represent a chromosome pattern and its derived similarity features.
#[pyclass]
pub struct Chromosome {
    pub inner: Arc<Mutex<InnerChromosome>>,
    pub minhash_num_hashes: usize,
    pub minhash_shingle_size: usize,
    pub minhash_seed: u64,
    pub tlsh_minimum_byte_size: usize,
}

#[pymethods]
impl Chromosome {
    #[new]
    #[pyo3(text_signature = "(pattern, config)")]
    /// Create a chromosome from a YARA-like pattern string.
    pub fn new(py: Python, pattern: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerChromosome::new(pattern, inner_config.clone())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
            minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
            minhash_seed: inner_config.chromosomes.minhash.seed,
            tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the allele pairs that compose the chromosome.
    pub fn allelepairs(&self) -> Vec<AllelePair> {
        let mut result = Vec::<AllelePair>::new();
        for allelepair in self.inner.lock().unwrap().allelepairs() {
            result.push(AllelePair {
                inner: Arc::new(Mutex::new(allelepair)),
            });
        }
        result
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the number of mutations applied to the chromosome.
    pub fn mutations(&self) -> usize {
        self.inner.lock().unwrap().mutations()
    }

    #[pyo3(text_signature = "($self, pattern)")]
    /// Mutate the chromosome using a replacement pattern string.
    pub fn mutate(&mut self, pattern: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .mutate(pattern)
            .map_err(|error| PyRuntimeError::new_err(format!("{}", error)))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the normalized pattern string for the chromosome.
    pub fn pattern(&self) -> String {
        self.inner.lock().unwrap().pattern()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the vector bytes derived from the chromosome.
    pub fn vector(&self) -> Vec<u8> {
        self.inner.lock().unwrap().vector()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the TLSH helper for the chromosome, if available.
    pub fn tlsh(&self) -> Option<TLSH> {
        let chromosome = self.inner.lock().unwrap();
        chromosome.tlsh().map(|_| TLSH {
            bytes: chromosome.bytes(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the MinHash helper for the chromosome, if available.
    pub fn minhash(&self) -> Option<MinHash32> {
        let chromosome = self.inner.lock().unwrap();
        chromosome.minhash().map(|_| MinHash32 {
            bytes: chromosome.bytes(),
            num_hashes: self.minhash_num_hashes,
            shingle_size: self.minhash_shingle_size,
            seed: self.minhash_seed,
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the SHA-256 helper for the chromosome, if available.
    pub fn sha256(&self) -> Option<SHA256> {
        let chromosome = self.inner.lock().unwrap();
        chromosome.sha256().map(|_| SHA256 {
            bytes: chromosome.bytes(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the entropy of the chromosome bytes, if available.
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the chromosome bytes.
    pub fn bytes(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.lock().unwrap().bytes()).unbind()
    }

    #[pyo3(text_signature = "($self)")]
    /// Render the chromosome as a PNG image using default imaging settings.
    pub fn png(&self) -> PNG {
        PNG::from_inner(self.inner.lock().unwrap().png())
    }

    #[pyo3(text_signature = "($self)")]
    /// Render the chromosome as an SVG image using default imaging settings.
    pub fn svg(&self) -> SVG {
        SVG::from_inner(self.inner.lock().unwrap().svg())
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the chromosome representation to stdout.
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    #[pyo3(text_signature = "($self)")]
    /// Convert the chromosome to a Python dictionary.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the JSON representation of the chromosome.
    pub fn json(&self, _py: Python) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    /// Return the JSON representation when converted to a string.
    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }
}

#[pymodule]
#[pyo3(name = "chromosome")]
pub fn chromosome_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Chromosome>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.genetics.chromosome", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.genetics.chromosome")?;
    Ok(())
}
