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
use crate::hashing::{MinHash32, SSDeep, SHA256, TLSH};
use crate::imaging::Imaging;
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
    #[pyo3(text_signature = "(raw_bytes, wildcard_mask, config)")]
    /// Create a chromosome from raw bytes and a per-byte wildcard mask.
    pub fn new(
        py: Python,
        raw_bytes: &Bound<'_, PyBytes>,
        wildcard_mask: &Bound<'_, PyBytes>,
        config: Py<Config>,
    ) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerChromosome::new(
            raw_bytes.as_bytes().to_vec(),
            wildcard_mask.as_bytes().to_vec(),
            inner_config.clone(),
        )?;
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

    #[pyo3(text_signature = "($self, raw_bytes, wildcard_mask)")]
    /// Mutate the chromosome using replacement raw bytes and wildcard mask.
    pub fn mutate(
        &mut self,
        raw_bytes: &Bound<'_, PyBytes>,
        wildcard_mask: &Bound<'_, PyBytes>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .mutate(
                raw_bytes.as_bytes().to_vec(),
                wildcard_mask.as_bytes().to_vec(),
            )
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
            bytes: chromosome.masked(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the MinHash helper for the chromosome, if available.
    pub fn minhash(&self) -> Option<MinHash32> {
        let chromosome = self.inner.lock().unwrap();
        chromosome.minhash().map(|_| MinHash32 {
            bytes: chromosome.masked(),
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
            bytes: chromosome.masked(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the ssdeep helper for the chromosome, if available.
    pub fn ssdeep(&self) -> Option<SSDeep> {
        let chromosome = self.inner.lock().unwrap();
        chromosome.ssdeep().map(|_| SSDeep {
            bytes: chromosome.masked(),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the entropy of the masked chromosome bytes, if available.
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the original chromosome bytes.
    pub fn bytes(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.lock().unwrap().bytes()).unbind()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the wildcard bitmask for the chromosome.
    pub fn mask(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.lock().unwrap().mask()).unbind()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the masked chromosome bytes.
    pub fn masked(&self, py: Python) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.lock().unwrap().masked()).unbind()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the imaging pipeline for the masked chromosome bytes.
    pub fn imaging(&self) -> Imaging {
        Imaging::from_inner(self.inner.lock().unwrap().imaging())
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
