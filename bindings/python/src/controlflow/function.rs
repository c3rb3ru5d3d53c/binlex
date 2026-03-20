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

use crate::controlflow::json_value_to_py;
use crate::controlflow::Block;
use crate::controlflow::Graph;
use crate::genetics::Chromosome;
use crate::hashing::{MinHash32, SHA256, TLSH};
use crate::Architecture;
use crate::Config;
use binlex::controlflow::Function as InnerFunction;
use binlex::controlflow::FunctionJsonDeserializer as InnerFunctionJsonDeserializer;
use binlex::hex;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

/// Deserialize a serialized function JSON payload back into typed accessors.
#[pyclass]
pub struct FunctionJsonDeserializer {
    pub inner: Arc<Mutex<InnerFunctionJsonDeserializer>>,
    chromosome_minhash_num_hashes: usize,
    chromosome_minhash_shingle_size: usize,
    chromosome_minhash_seed: u64,
    chromosome_tlsh_minimum_byte_size: usize,
}

#[pymethods]
impl FunctionJsonDeserializer {
    #[new]
    #[pyo3(text_signature = "(string, config)")]
    /// Create a deserializer from a serialized function JSON string.
    pub fn new(py: Python, string: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerFunctionJsonDeserializer::new(string, inner_config.clone())?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            chromosome_minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
            chromosome_minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
            chromosome_minhash_seed: inner_config.chromosomes.minhash.seed,
            chromosome_tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the block addresses contained in the serialized function.
    pub fn blocks(&self) -> Vec<u64> {
        self.inner.lock().unwrap().blocks()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the referenced function addresses contained in the payload.
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.inner.lock().unwrap().functions()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the total size of the function in bytes.
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().size()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return whether the serialized function occupies a contiguous range.
    pub fn contiguous(&self) -> bool {
        self.inner.lock().unwrap().contiguous()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the architecture encoded in the serialized function.
    pub fn architecture(&self) -> PyResult<Architecture> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .architecture()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", err)))?;
        Ok(Architecture { inner })
    }

    #[pyo3(text_signature = "($self)")]
    /// Decode and return the raw function bytes, if the payload contains them.
    pub fn bytes(&self, py: Python) -> PyResult<Option<Py<PyBytes>>> {
        let binding = self.inner.lock().unwrap();
        let string = binding.json.bytes.clone();
        if string.is_none() {
            return Ok(None);
        }
        let bytes =
            hex::decode(&string.unwrap()).map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(Some(PyBytes::new(py, &bytes).unbind()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the starting address of the function.
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the number of instructions in the function.
    pub fn number_of_instructions(&self) -> usize {
        self.inner.lock().unwrap().number_of_instructions()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the number of basic blocks in the function.
    pub fn number_of_blocks(&self) -> usize {
        self.inner.lock().unwrap().number_of_blocks()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the average number of instructions per block.
    pub fn average_instructions_per_block(&self) -> f64 {
        self.inner.lock().unwrap().average_instructions_per_block()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the entropy of the function bytes, if available.
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the number of control-flow edges in the function.
    pub fn edges(&self) -> usize {
        self.inner.lock().unwrap().edges()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the SHA-256 digest for the function, if available.
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the MinHash value for the function, if available.
    pub fn minhash(&self) -> Option<String> {
        self.inner.lock().unwrap().minhash()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the TLSH value for the function, if available.
    pub fn tlsh(&self) -> Option<String> {
        self.inner.lock().unwrap().tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the chromosome derived from the serialized function.
    pub fn chromosome(&self) -> Chromosome {
        let inner_chromosome = self.inner.lock().unwrap().chromosome();
        Chromosome {
            inner: Arc::new(Mutex::new(inner_chromosome.unwrap())),
            minhash_num_hashes: self.chromosome_minhash_num_hashes,
            minhash_shingle_size: self.chromosome_minhash_shingle_size,
            minhash_seed: self.chromosome_minhash_seed,
            tlsh_minimum_byte_size: self.chromosome_tlsh_minimum_byte_size,
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Convert the serialized function payload into a Python dictionary.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json()?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the normalized JSON representation of the function payload.
    pub fn json(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Print the function payload in its textual form.
    pub fn print(&self) {
        self.inner.lock().unwrap().print()
    }

    /// Return the JSON representation when converted to a string.
    pub fn __str__(&self) -> PyResult<String> {
        self.json()
    }
}

#[pyclass]
/// Represents a function within a control flow graph (CFG).
pub struct Function {
    /// The address of the function.
    pub address: u64,
    /// The control flow graph associated with the function.
    pub cfg: Py<Graph>,
    inner_function_cache: Arc<Mutex<Option<InnerFunction<'static>>>>,
}

impl Function {
    fn with_inner_function<F, R>(&self, py: Python, f: F) -> PyResult<R>
    where
        F: FnOnce(&InnerFunction<'static>) -> PyResult<R>,
    {
        let mut cache = self.inner_function_cache.lock().unwrap();

        if cache.is_none() {
            let binding = self.cfg.borrow(py);
            let inner = binding.inner.lock().unwrap();

            let inner_ref: &'static _ = unsafe { std::mem::transmute(&*inner) };
            let inner_block = InnerFunction::new(self.address, inner_ref)?;
            *cache = Some(inner_block);
        }

        f(cache.as_ref().unwrap())
    }
}

#[pymethods]
impl Function {
    #[new]
    #[pyo3(text_signature = "(address, cfg)")]
    /// Creates a new `Function` instance.
    ///
    /// # Arguments
    /// - `address` (`u64`): The address of the function.
    /// - `cfg` (`Graph`): The control flow graph associated with the function.
    ///
    /// # Returns
    /// - A new instance of `Function`.
    pub fn new(address: u64, cfg: Py<Graph>) -> PyResult<Self> {
        Ok(Self {
            address,
            cfg,
            inner_function_cache: Arc::new(Mutex::new(None)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the starting address of the function.
    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the function architecture.
    pub fn architecture(&self, py: Python) -> PyResult<Architecture> {
        self.with_inner_function(py, |function| {
            Ok(Architecture {
                inner: function.architecture(),
            })
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the chromosome associated with this function.
    ///
    /// # Returns
    /// - `PyResult<Option<Chromosome>>`: The chromosome associated with this function
    pub fn chromosome(&self, py: Python) -> PyResult<Option<Chromosome>> {
        self.with_inner_function(py, |function| {
            let inner_config = self.cfg.borrow(py).inner.lock().unwrap().config.clone();
            let config = Py::new(
                py,
                Config {
                    inner: Arc::new(Mutex::new(inner_config)),
                },
            )
            .unwrap();
            let pattern = function.pattern();
            if pattern.is_none() {
                return Ok(None);
            }
            let chromosome = Chromosome::new(py, pattern.unwrap(), config).ok();
            Ok(chromosome)
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the cyclomatic complexity of the function.
    pub fn cyclomatic_complexity(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.cyclomatic_complexity()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the average number of instructions per block.
    pub fn average_instructions_per_block(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| Ok(function.average_instructions_per_block()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the blocks associated with this function.
    ///
    /// # Returns
    /// - `PyResult<Vec<Block>>`: The blocks associated with this function
    pub fn blocks(&self, py: Python) -> PyResult<Vec<Block>> {
        self.with_inner_function(py, |function| {
            let mut result = Vec::<Block>::new();
            for block_address in function.blocks.keys() {
                let block = Block::new(*block_address, self.cfg.clone_ref(py))
                    .expect("failed to get block");
                result.push(block);
            }
            Ok(result)
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the raw bytes of the function.
    ///
    /// # Returns
    /// - `bytes | None`: The raw bytes of the function, if available
    pub fn bytes(&self, py: Python) -> PyResult<Option<Py<PyBytes>>> {
        self.with_inner_function(py, |function| {
            if let Some(raw_bytes) = function.bytes() {
                Ok(Some(PyBytes::new(py, &raw_bytes).unbind()))
            } else {
                Ok(None)
            }
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Determines if the function starts with a prologue.
    ///
    /// # Returns
    /// - `bool`: `true` if the function starts with a prologue; otherwise, `false`.
    pub fn prologue(&self, py: Python) -> PyResult<bool> {
        self.with_inner_function(py, |function| Ok(function.prologue()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the number of edges in the control flow graph.
    ///
    /// # Returns
    /// - `usize`: The number of edges.
    pub fn edges(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.edges()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the entropy of the function.
    ///
    /// # Returns
    /// - `Option<f64>`: The entropy value, if available.
    pub fn entropy(&self, py: Python) -> PyResult<Option<f64>> {
        self.with_inner_function(py, |function| Ok(function.entropy()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the number of instructions in the function.
    ///
    /// # Returns
    /// - `usize`: The number of instructions.
    pub fn number_of_instructions(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.number_of_instructions()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the number of blocks in the function.
    ///
    /// # Returns
    /// - `usize`: The number of blocks.
    pub fn number_of_blocks(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.number_of_blocks()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns a mapping of function calls within the current function.
    ///
    /// # Returns
    /// - `BTreeMap<u64, u64>`: A map of called functions' addresses and counts.
    pub fn functions(&self, py: Python) -> PyResult<BTreeMap<u64, u64>> {
        self.with_inner_function(py, |function| Ok(function.functions()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all processor outputs attached to this function.
    pub fn processors(&self, py: Python) -> PyResult<Py<PyAny>> {
        self.with_inner_function(py, |function| {
            let value = serde_json::to_value(function.processors())
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
            json_value_to_py(py, &value)
        })
    }

    #[pyo3(text_signature = "($self, name)")]
    /// Return a single processor output attached to this function, if present.
    pub fn processor(&self, py: Python, name: String) -> PyResult<Option<Py<PyAny>>> {
        self.with_inner_function(py, |function| {
            function
                .processor(&name)
                .map(|value| json_value_to_py(py, &value))
                .transpose()
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the TLSH (Trend Micro Locality Sensitive Hash) of the function.
    ///
    /// # Returns
    /// - `Option<TLSH>`: The TLSH object, if available.
    pub fn tlsh(&self, py: Python) -> PyResult<Option<TLSH>> {
        self.with_inner_function(py, |function| {
            Ok(function.tlsh().map(|hash| TLSH {
                bytes: hash.bytes.into_owned(),
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the SHA-256 hash of the function.
    ///
    /// # Returns
    /// - `Option<SHA256>`: The SHA-256 hash object, if available.
    pub fn sha256(&self, py: Python) -> PyResult<Option<SHA256>> {
        self.with_inner_function(py, |function| {
            Ok(function.sha256().map(|hash| SHA256 {
                bytes: hash.bytes.into_owned(),
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the MinHash of the function.
    ///
    /// # Returns
    /// - `Option<MinHash32>`: The MinHash object, if available.
    pub fn minhash(&self, py: Python) -> PyResult<Option<MinHash32>> {
        self.with_inner_function(py, |function| {
            Ok(function.minhash().map(|hash| MinHash32 {
                bytes: hash.bytes.into_owned(),
                num_hashes: function.cfg.config.functions.minhash.number_of_hashes,
                shingle_size: function.cfg.config.functions.minhash.shingle_size,
                seed: function.cfg.config.functions.minhash.seed,
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the size of the function in bytes.
    ///
    /// # Returns
    /// - `usize`: The size of the function in bytes.
    pub fn size(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.size()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Determines if the function's memory layout is contiguous.
    ///
    /// # Returns
    /// - `bool`: `True` if contiguous; otherwise, `False`.
    pub fn contiguous(&self, py: Python) -> PyResult<bool> {
        self.with_inner_function(py, |function| Ok(function.contiguous()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the ending address of the function.
    ///
    /// # Returns
    /// - `int | None`: The ending address, if available.
    pub fn end(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_function(py, |function| Ok(function.end()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Prints a textual representation of the function in JSON.
    ///
    /// # Returns
    /// - `()` (unit): Output is sent to stdout.
    pub fn print(&self, py: Python) -> PyResult<()> {
        self.with_inner_function(py, |function| {
            function.print();
            Ok(())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the function to a JSON dictionary representation.
    ///
    /// # Returns
    /// - `dict`: A Python dictionary representation of the function.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the function to JSON representation.
    ///
    /// # Returns
    /// - `str`: JSON string representing the function.
    pub fn json(&self, py: Python) -> PyResult<String> {
        self.with_inner_function(py, |function| {
            function
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
#[pyo3(name = "function")]
pub fn function_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Function>()?;
    m.add_class::<FunctionJsonDeserializer>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.function", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.function")?;
    Ok(())
}
