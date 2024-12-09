use pyo3::prelude::*;
use pyo3::Py;
use std::collections::{BTreeMap, BTreeSet};
use binlex::controlflow::Block as InnerBlock;
use crate::controlflow::graph::Graph;
use std::sync::Arc;
use std::sync::Mutex;
use pyo3::types::PyBytes;

/// A class representing a control flow block in the binary analysis.
#[pyclass]
pub struct Block {
    /// The starting address of the block.
    pub address: u64,
    /// A reference to the control flow graph associated with the block.
    pub cfg: Py<Graph>,
    inner_block_cache: Arc<Mutex<Option<InnerBlock<'static>>>>,
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
    fn new(address: u64, cfg: Py<Graph>) -> PyResult<Self> {
        Ok(Self {
            address,
            cfg,
            inner_block_cache: Arc::new(Mutex::new(None)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the raw bytes of the block.
    fn bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        self.with_inner_block(py, |block| {
            let bytes = PyBytes::new_bound(py, &block.bytes());
            Ok(bytes.into())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Checks if the block is a prologue block.
    pub fn is_prologue(&self, py: Python) -> PyResult<bool> {
        self.with_inner_block(py, |block| Ok(block.is_prologue()))
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
    /// Retrieves the TLSH (Trend Micro Locality Sensitive Hash) of the block.
    pub fn tlsh(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_block(py, |block| Ok(block.tlsh()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the SHA-256 hash of the block.
    pub fn sha256(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_block(py, |block| Ok(block.sha256()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the MinHash of the block.
    pub fn minhash(&self, py: Python) -> PyResult<Option<String>> {
        self.with_inner_block(py, |block| Ok(block.minhash()))
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
        self.with_inner_block(py, |block| Ok(block.print()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the block to a Python dictionary.
    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_str = self.json(py)?;
        let json_module = py.import_bound("json")?;
        let py_dict = json_module.call_method1("loads", (json_str,))?;
        Ok(py_dict.into())
    }

    #[pyo3(text_signature = "($self)")]
    /// Converts the block to a JSON string.
    pub fn json(&self, py: Python) -> PyResult<String> {
        self.with_inner_block(py, |block| {
            block.json().map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
        })
    }

    /// Converts the block to a JSON string when printed.
    pub fn __str__(&self, py: Python) -> PyResult<String> {
        self.json(py)
    }
}

#[pymodule]
#[pyo3(name = "block")]
pub fn block_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Block>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex.controlflow.block", m)?;
    m.setattr("__name__", "binlex.controlflow.block")?;
    Ok(())
}
