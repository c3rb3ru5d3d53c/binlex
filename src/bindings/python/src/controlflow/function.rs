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

use crate::controlflow::Block;
use crate::controlflow::Graph;
use crate::genetics::Chromosome;
use crate::Architecture;
use crate::Config;
use binlex::controlflow::Function as InnerFunction;
use binlex::controlflow::FunctionJsonDeserializer as InnerFunctionJsonDeserializer;
use binlex::controlflow::Graph as InnerGraph;
use binlex::Binary as InnerBinary;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass]
pub struct FunctionJsonDeserializer {
    pub inner: Arc<Mutex<InnerFunctionJsonDeserializer>>,
}

#[pymethods]
impl FunctionJsonDeserializer {
    #[new]
    #[pyo3(text_signature = "(string, config)")]
    pub fn new(py: Python, string: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerFunctionJsonDeserializer::new(string, inner_config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn blocks(&self) -> Vec<u64> {
        self.inner.lock().unwrap().blocks()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.inner.lock().unwrap().functions()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().size()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn contiguous(&self) -> bool {
        self.inner.lock().unwrap().contiguous()
    }

    #[pyo3(text_signature = "($self)")]
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
    pub fn bytes(&self, py: Python) -> PyResult<Option<Py<PyBytes>>> {
        let binding = self.inner.lock().unwrap();
        let string = binding.json.bytes.clone();
        if string.is_none() {
            return Ok(None);
        }
        let bytes = InnerBinary::from_hex(&string.unwrap())
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        let result = PyBytes::new_bound(py, &bytes);
        Ok(Some(result.into()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_instructions(&self) -> usize {
        self.inner.lock().unwrap().number_of_instructions()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_blocks(&self) -> usize {
        self.inner.lock().unwrap().number_of_blocks()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn average_instructions_per_block(&self) -> f64 {
        self.inner.lock().unwrap().average_instructions_per_block()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn edges(&self) -> usize {
        self.inner.lock().unwrap().edges()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash(&self) -> Option<String> {
        self.inner.lock().unwrap().minhash()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh(&self) -> Option<String> {
        self.inner.lock().unwrap().tlsh()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh_ratio(&self) -> f64 {
        self.inner.lock().unwrap().tlsh_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash_ratio(&self) -> f64 {
        self.inner.lock().unwrap().minhash_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome_minhash_ratio(&self) -> f64 {
        self.inner.lock().unwrap().chromosome_minhash_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome_tlsh_ratio(&self) -> f64 {
        self.inner.lock().unwrap().chromosome_tlsh_ratio()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn prologue(&self) -> bool {
        self.inner.lock().unwrap().prologue()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome(&self) -> Chromosome {
        let inner_chromosome = self.inner.lock().unwrap().chromosome();
        Chromosome {
            inner: Arc::new(Mutex::new(inner_chromosome.unwrap())),
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json()?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    pub fn json(&self) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .json()
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print()
    }

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
    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
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
    pub fn chromosome_minhash_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| Ok(function.chromosome_minhash_ratio()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome_tlsh_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| Ok(function.chromosome_tlsh_ratio()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn minhash_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| Ok(function.minhash_ratio()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn tlsh_ratio(&self, py: Python) -> PyResult<f64> {
        self.with_inner_function(py, |function| Ok(function.tlsh_ratio()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn cyclomatic_complexity(&self, py: Python) -> PyResult<usize> {
        self.with_inner_function(py, |function| Ok(function.cyclomatic_complexity()))
    }

    #[pyo3(text_signature = "($self)")]
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
                let bytes = PyBytes::new_bound(py, &raw_bytes);
                Ok(Some(bytes.into()))
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
    /// Returns the TLSH (Trend Micro Locality Sensitive Hash) of the function.
    ///
    /// # Returns
    /// - `Option<String>`: The TLSH hash, if available.
    pub fn tlsh(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_function(py, |function| Ok(function.tlsh()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the SHA-256 hash of the function.
    ///
    /// # Returns
    /// - `Option<String>`: The SHA-256 hash, if available.
    pub fn sha256(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_function(py, |function| Ok(function.sha256()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the MinHash of the function.
    ///
    /// # Returns
    /// - `Option<String>`: The MinHash, if available.
    pub fn minhash(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_function(py, |function| Ok(function.minhash()))
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
        let json_module = py.import_bound("json")?;
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

    /// When printed directly print the JSON representation of the function.
    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }
}

#[pymodule]
#[pyo3(name = "function")]
pub fn function_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Function>()?;
    m.add_class::<FunctionJsonDeserializer>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.function", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.function")?;
    Ok(())
}
