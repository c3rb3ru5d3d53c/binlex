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
use crate::controlflow::EntityKind;
use crate::controlflow::Graph;
use crate::genetics::Chromosome;
use crate::hashing::{MinHash32, SSDeep, SHA256, TLSH};
use crate::irs::ast::PyAstFunction;
use crate::irs::hir::PyHirFunction;
use crate::irs::lir::LirFunction as PyLirFunction;
use crate::irs::llvm::LlvmModule as PyLlvmModule;
use crate::irs::mir::PyMirFunction;
#[cfg(not(target_os = "windows"))]
use crate::irs::vex::VexModule as PyVexModule;
use crate::Architecture;
use binlex::controlflow::EntityKind as InnerEntityKind;
use binlex::controlflow::Function as InnerFunction;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;

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
    pub(crate) fn from_inner(address: u64, cfg: Py<Graph>, inner: InnerFunction<'static>) -> Self {
        Self {
            address,
            cfg,
            inner_function_cache: Arc::new(Mutex::new(Some(inner))),
        }
    }

    pub(crate) fn with_inner_function<F, R>(&self, py: Python, f: F) -> PyResult<R>
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

#[pyclass(skip_from_py_object)]
pub struct FunctionCallee {
    address: u64,
    function_address: u64,
    cfg: Py<Graph>,
}

impl FunctionCallee {
    fn new(address: u64, function_address: u64, cfg: Py<Graph>) -> Self {
        Self {
            address,
            function_address,
            cfg,
        }
    }
}

#[pymethods]
impl FunctionCallee {
    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    pub fn function(&self, py: Python<'_>) -> PyResult<Function> {
        Function::new(self.function_address, self.cfg.clone_ref(py))
    }

    pub fn __str__(&self) -> String {
        format!(
            "FunctionCallee(address=0x{:x}, function=0x{:x})",
            self.address, self.function_address
        )
    }
}

#[pyclass(skip_from_py_object)]
pub struct FunctionCaller {
    address: u64,
    function_address: u64,
    cfg: Py<Graph>,
}

impl FunctionCaller {
    fn new(address: u64, function_address: u64, cfg: Py<Graph>) -> Self {
        Self {
            address,
            function_address,
            cfg,
        }
    }
}

#[pymethods]
impl FunctionCaller {
    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    pub fn function(&self, py: Python<'_>) -> PyResult<Function> {
        Function::new(self.function_address, self.cfg.clone_ref(py))
    }

    pub fn __str__(&self) -> String {
        format!(
            "FunctionCaller(address=0x{:x}, function=0x{:x})",
            self.address, self.function_address
        )
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
    /// Return the entity kind for this function.
    pub fn kind(&self) -> EntityKind {
        EntityKind::from_inner(InnerEntityKind::Function)
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
            let binding = self.cfg.borrow(py);
            let inner_config = binding.inner.lock().unwrap().config.clone();
            let inner_chromosome = function.chromosome();
            if inner_chromosome.is_none() {
                return Ok(None);
            }
            Ok(Some(Chromosome {
                inner: Arc::new(Mutex::new(inner_chromosome.unwrap())),
                minhash_num_hashes: inner_config.hashing.minhash.number_of_hashes,
                minhash_shingle_size: inner_config.hashing.minhash.shingle_size,
                minhash_seed: inner_config.hashing.minhash.seed,
                tlsh_minimum_byte_size: inner_config.hashing.tlsh.minimum_byte_size,
            }))
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
    pub fn lir(&self, py: Python<'_>) -> PyResult<Py<PyLirFunction>> {
        self.with_inner_function(py, |function| {
            let inner = py.detach(|| function.lir())?;
            Py::new(py, PyLirFunction::from_inner(inner))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn mir(&self, py: Python<'_>) -> PyResult<Py<PyMirFunction>> {
        self.with_inner_function(py, |function| {
            let inner = py.detach(|| function.mir())?;
            Py::new(py, PyMirFunction::from_inner(inner))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn hir(&self, py: Python<'_>) -> PyResult<Py<PyHirFunction>> {
        self.with_inner_function(py, |function| {
            let inner = py.detach(|| function.hir())?;
            Py::new(py, PyHirFunction::from_inner(inner))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn ast(&self, py: Python<'_>) -> PyResult<Py<PyAstFunction>> {
        self.with_inner_function(py, |function| {
            let inner = py.detach(|| function.ast())?;
            Py::new(py, PyAstFunction::from_inner(inner))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn llvm(&self, py: Python<'_>) -> PyResult<Py<PyLlvmModule>> {
        self.with_inner_function(py, |function| {
            let inner = function.llvm()?;
            let cpu = binlex::irs::lir::LirCpu::from_architecture(function.architecture())
                .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
            Py::new(
                py,
                PyLlvmModule::from_inner(inner, function.cfg.config.clone(), cpu, None, None),
            )
        })
    }

    #[cfg(not(target_os = "windows"))]
    #[pyo3(text_signature = "($self)")]
    pub fn vex(&self, py: Python<'_>) -> PyResult<Py<PyVexModule>> {
        self.with_inner_function(py, |function| {
            let inner = function.vex()?;
            Py::new(
                py,
                PyVexModule::from_inner(inner, function.cfg.config.clone()),
            )
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
    /// Return direct outgoing call relationships.
    ///
    /// # Returns
    /// - `Vec<FunctionCallee>`: The direct outgoing call relationships.
    pub fn callees(&self, py: Python) -> PyResult<Vec<FunctionCallee>> {
        self.with_inner_function(py, |function| {
            Ok(function
                .callees()
                .into_iter()
                .map(|callee| {
                    FunctionCallee::new(
                        callee.address,
                        callee.function.address(),
                        self.cfg.clone_ref(py),
                    )
                })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return direct incoming call relationships.
    ///
    /// # Returns
    /// - `Vec<FunctionCaller>`: The direct incoming call relationships.
    pub fn callers(&self, py: Python) -> PyResult<Vec<FunctionCaller>> {
        self.with_inner_function(py, |function| {
            Ok(function
                .callers()
                .into_iter()
                .map(|caller| {
                    FunctionCaller::new(
                        caller.address,
                        caller.function.address(),
                        self.cfg.clone_ref(py),
                    )
                })
                .collect())
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
                num_hashes: function.cfg.config.hashing.minhash.number_of_hashes,
                shingle_size: function.cfg.config.hashing.minhash.shingle_size,
                seed: function.cfg.config.hashing.minhash.seed,
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the ssdeep helper for this function, if available.
    pub fn ssdeep(&self, py: Python) -> PyResult<Option<SSDeep>> {
        self.with_inner_function(py, |function| {
            Ok(function.ssdeep().map(|hash| SSDeep {
                bytes: hash.bytes.into_owned(),
            }))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return normalized Markov importance scores for each block in the function.
    pub fn markov(&self, py: Python) -> PyResult<BTreeMap<u64, f64>> {
        self.with_inner_function(py, |function| Ok(function.markov()))
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

    pub fn __str__(&self) -> String {
        format!("Function(address=0x{:x})", self.address)
    }
}

#[pymodule]
#[pyo3(name = "function")]
pub fn function_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Function>()?;
    m.add_class::<FunctionCallee>()?;
    m.add_class::<FunctionCaller>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.function", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.function")?;
    Ok(())
}
