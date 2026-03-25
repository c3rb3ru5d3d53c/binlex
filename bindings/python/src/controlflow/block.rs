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

use crate::controlflow::graph::Graph;
use crate::controlflow::json_value_to_py;
use crate::controlflow::Instruction;
use crate::genetics::Chromosome;
use crate::hashing::{MinHash32, SHA256, TLSH};
use crate::imaging::Imaging;
use crate::Architecture;
use crate::Config;
use binlex::controlflow::Block as InnerBlock;
use binlex::controlflow::BlockJsonDeserializer as InnerBlockJsonDeserializer;
use binlex::hex;
use binlex::Architecture as InnerArchitecture;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::Mutex;

/// Deserialize a serialized block JSON payload back into typed accessors.
#[pyclass]
pub struct BlockJsonDeserializer {
    pub inner: Arc<Mutex<InnerBlockJsonDeserializer>>,
    chromosome_minhash_num_hashes: usize,
    chromosome_minhash_shingle_size: usize,
    chromosome_minhash_seed: u64,
    chromosome_tlsh_minimum_byte_size: usize,
}

#[pymethods]
impl BlockJsonDeserializer {
    #[new]
    #[pyo3(text_signature = "(string, config)")]
    /// Create a deserializer from a serialized block JSON string.
    pub fn new(py: Python, string: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerBlockJsonDeserializer::new(string, inner_config.clone())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            chromosome_minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
            chromosome_minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
            chromosome_minhash_seed: inner_config.chromosomes.minhash.seed,
            chromosome_tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the referenced function addresses contained in the block payload.
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.inner.lock().unwrap().functions()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the architecture encoded in the serialized block.
    pub fn architecture(&self) -> PyResult<Architecture> {
        let inner = InnerArchitecture::from_string(&self.inner.lock().unwrap().json.architecture)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(Architecture { inner })
    }

    #[pyo3(text_signature = "($self)")]
    /// Decode and return the raw bytes represented by the block payload.
    pub fn bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let bytes = hex::decode(&self.inner.lock().unwrap().json.bytes)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the starting address of the block.
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the MinHash value for the block, if available.
    pub fn minhash(&self) -> Option<String> {
        self.inner.lock().unwrap().minhash()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the TLSH value for the block, if available.
    pub fn tlsh(&self) -> Option<String> {
        self.inner.lock().unwrap().tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the SHA-256 digest for the block, if available.
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the number of control-flow edges leaving this block.
    pub fn edges(&self) -> usize {
        self.inner.lock().unwrap().edges()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the set of related block addresses referenced by this block.
    pub fn blocks(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().blocks()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the successor addresses targeted by this block.
    pub fn to(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().to()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return whether the block ends in a conditional transfer of control.
    pub fn conditional(&self) -> bool {
        self.inner.lock().unwrap().conditional()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the entropy of the block bytes, if available.
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the next linear address after the block, if available.
    pub fn next(&self) -> Option<u64> {
        self.inner.lock().unwrap().next()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the size of the block in bytes.
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().size()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the number of decoded instructions in the block.
    pub fn number_of_instructions(&self) -> usize {
        self.inner.lock().unwrap().number_of_instructions()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the chromosome derived from the block pattern.
    pub fn chromosome(&self) -> Chromosome {
        let inner_chromosome = self.inner.lock().unwrap().chromosome();
        Chromosome {
            inner: Arc::new(Mutex::new(inner_chromosome)),
            minhash_num_hashes: self.chromosome_minhash_num_hashes,
            minhash_shingle_size: self.chromosome_minhash_shingle_size,
            minhash_seed: self.chromosome_minhash_seed,
            tlsh_minimum_byte_size: self.chromosome_tlsh_minimum_byte_size,
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Convert the block payload into a Python dictionary.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json()?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the normalized JSON representation of the block payload.
    pub fn json(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the block payload in its textual form.
    pub fn print(&self) {
        self.inner.lock().unwrap().print()
    }

    /// Return the JSON representation when converted to a string.
    pub fn __str__(&self) -> PyResult<String> {
        self.json()
    }
}

/// A class representing a control flow block in the binary analysis.
#[pyclass]
pub struct Block {
    /// The starting address of the block.
    pub address: u64,
    /// A reference to the control flow graph associated with the block.
    pub cfg: Py<Graph>,
    pub inner_block_cache: Arc<Mutex<Option<InnerBlock<'static>>>>,
}

impl Block {
    fn with_inner_block<F, R>(&self, py: Python, f: F) -> PyResult<R>
    where
        F: FnOnce(&InnerBlock<'static>) -> PyResult<R>,
    {
        let mut cache = self.inner_block_cache.lock().unwrap();

        if cache.is_none() {
            let binding = self.cfg.borrow(py);
            let inner = binding.inner.lock().unwrap();

            let inner_ref: &'static _ = unsafe { std::mem::transmute(&*inner) };
            let inner_block = InnerBlock::new(self.address, inner_ref)?;
            *cache = Some(inner_block);
        }

        f(cache.as_ref().unwrap())
    }
}

#[pymethods]
impl Block {
    #[new]
    #[pyo3(text_signature = "(address, cfg)")]
    /// Creates a new `Block` instance.
    ///
    /// # Arguments
    /// - `address`: The starting address of the block.
    /// - `cfg`: The control flow graph associated with the block.
    ///
    /// # Returns
    /// A new `Block` object.
    pub fn new(address: u64, cfg: Py<Graph>) -> PyResult<Self> {
        Ok(Self {
            address,
            cfg,
            inner_block_cache: Arc::new(Mutex::new(None)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the starting address of the block.
    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the block architecture.
    pub fn architecture(&self, py: Python) -> PyResult<Architecture> {
        self.with_inner_block(py, |block| {
            Ok(Architecture {
                inner: block.architecture(),
            })
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the chromosome associated with this block.
    ///
    /// # Returns
    /// - `PyResult<Option<Chromosome>>`: The chromosome associated with this block.
    pub fn chromosome(&self, py: Python) -> PyResult<Option<Chromosome>> {
        self.with_inner_block(py, |block| {
            let binding = self.cfg.borrow(py);
            let inner_config = binding.inner.lock().unwrap().config.clone();
            let inner_chromosome = block.chromosome();
            Ok(Some(Chromosome {
                inner: Arc::new(Mutex::new(inner_chromosome)),
                minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
                minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
                minhash_seed: inner_config.chromosomes.minhash.seed,
                tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the instructions associated with this block.
    ///
    /// # Returns
    /// - `PyResult<Vec<Instruction>>`: The instructions associated with this block
    pub fn instructions(&self, py: Python) -> PyResult<Vec<Instruction>> {
        self.with_inner_block(py, |block| {
            let mut result = Vec::<Instruction>::new();
            for instruction in &block.instructions() {
                let instruction = Instruction::new(instruction.address, self.cfg.clone_ref(py))
                    .expect("failed to get instruction");
                result.push(instruction);
            }
            Ok(result)
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the raw bytes of the block.
    pub fn bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        self.with_inner_block(py, |block| Ok(PyBytes::new(py, &block.bytes()).unbind()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the imaging pipeline for the block bytes.
    pub fn imaging(&self, py: Python) -> PyResult<Imaging> {
        self.with_inner_block(py, |block| Ok(Imaging::from_inner(block.imaging())))
    }

    #[pyo3(text_signature = "($self)")]
    /// Checks if the block is a prologue block.
    pub fn prologue(&self, py: Python) -> PyResult<bool> {
        self.with_inner_block(py, |block| Ok(block.prologue()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the number of edges from the block.
    pub fn edges(&self, py: Python) -> PyResult<usize> {
        self.with_inner_block(py, |block| Ok(block.edges()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the next address in the block.
    pub fn next(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_block(py, |block| Ok(block.next()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the set of addresses the block points to.
    pub fn to(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_block(py, |block| Ok(block.to()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Calculates the entropy of the block.
    pub fn entropy(&self, py: Python) -> PyResult<Option<f64>> {
        self.with_inner_block(py, |block| Ok(block.entropy()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the set of addresses of blocks referenced by this block.
    pub fn blocks(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_block(py, |block| Ok(block.blocks()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the number of instructions in the block.
    pub fn number_of_instructions(&self, py: Python) -> PyResult<usize> {
        self.with_inner_block(py, |block| Ok(block.number_of_instructions()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the functions referenced in the block as a map.
    pub fn functions(&self, py: Python) -> PyResult<BTreeMap<u64, u64>> {
        self.with_inner_block(py, |block| Ok(block.functions()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all processor outputs attached to this block.
    pub fn processors(&self, py: Python) -> PyResult<Py<PyAny>> {
        self.with_inner_block(py, |block| {
            let value = serde_json::to_value(block.processors())
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
            json_value_to_py(py, &value)
        })
    }

    #[pyo3(text_signature = "($self, name)")]
    /// Return a single processor output attached to this block.
    pub fn processor(&self, py: Python, name: String) -> PyResult<Py<PyAny>> {
        self.with_inner_block(py, |block| {
            let value = block.processor(&name);
            json_value_to_py(py, &value)
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the TLSH (Trend Micro Locality Sensitive Hash) of the block.
    pub fn tlsh(&self, py: Python) -> PyResult<Option<TLSH>> {
        self.with_inner_block(py, |block| {
            Ok(block.tlsh().map(|hash| TLSH {
                bytes: hash.bytes.into_owned(),
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the SHA-256 hash of the block.
    pub fn sha256(&self, py: Python) -> PyResult<Option<SHA256>> {
        self.with_inner_block(py, |block| {
            Ok(block.sha256().map(|hash| SHA256 {
                bytes: hash.bytes.into_owned(),
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the MinHash of the block.
    pub fn minhash(&self, py: Python) -> PyResult<Option<MinHash32>> {
        self.with_inner_block(py, |block| {
            Ok(block.minhash().map(|hash| MinHash32 {
                bytes: hash.bytes.into_owned(),
                num_hashes: block.cfg.config.blocks.minhash.number_of_hashes,
                shingle_size: block.cfg.config.blocks.minhash.shingle_size,
                seed: block.cfg.config.blocks.minhash.seed,
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the ending address of the block.
    pub fn end(&self, py: Python) -> PyResult<u64> {
        self.with_inner_block(py, |block| Ok(block.end()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the size of the block in bytes.
    pub fn size(&self, py: Python) -> PyResult<usize> {
        self.with_inner_block(py, |block| Ok(block.size()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Prints a human-readable representation of the block.
    pub fn print(&self, py: Python) -> PyResult<()> {
        self.with_inner_block(py, |block| {
            block.print();
            Ok(())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the block to a Python dictionary.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the block to a JSON string.
    pub fn json(&self, py: Python) -> PyResult<String> {
        self.with_inner_block(py, |block| {
            block
                .json()
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
        })
    }

    /// Return the JSON representation when converted to a string.
    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }
}

#[pymodule]
#[pyo3(name = "block")]
pub fn block_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Block>()?;
    m.add_class::<BlockJsonDeserializer>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.block", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.block")?;
    Ok(())
}
