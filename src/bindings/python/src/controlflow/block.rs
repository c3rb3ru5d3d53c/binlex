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
use crate::controlflow::Instruction;
use crate::genetics::Chromosome;
use crate::genetics::ChromosomeSimilarity;
use crate::Architecture;
use crate::Config;
use binlex::controlflow::Block as InnerBlock;
use binlex::controlflow::BlockJsonDeserializer as InnerBlockJsonDeserializer;
use binlex::controlflow::Graph as InnerGraph;
use binlex::Architecture as InnerArchitecture;
use binlex::Binary as InnerBinary;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyList;
use pyo3::Py;
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::Mutex;

#[pyclass]
pub struct BlockJsonDeserializer {
    pub inner: Arc<Mutex<InnerBlockJsonDeserializer>>,
}

#[pymethods]
impl BlockJsonDeserializer {
    #[new]
    #[pyo3(text_signature = "(string, config)")]
    pub fn new(py: Python, string: String, config: Py<Config>) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerBlockJsonDeserializer::new(string, inner_config)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn functions(&self) -> BTreeMap<u64, u64> {
        self.inner.lock().unwrap().functions()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self) -> PyResult<Architecture> {
        let inner = InnerArchitecture::from_string(&self.inner.lock().unwrap().json.architecture)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        Ok(Architecture { inner })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        let bytes = InnerBinary::from_hex(&self.inner.lock().unwrap().json.bytes)
            .map_err(pyo3::exceptions::PyRuntimeError::new_err)?;
        let result = PyBytes::new_bound(py, &bytes);
        Ok(result.into())
    }

    #[pyo3(text_signature = "($self, rhs)")]
    pub fn compare(
        &self,
        py: Python,
        rhs: Py<BlockJsonDeserializer>,
    ) -> Option<ChromosomeSimilarity> {
        let binding = rhs.borrow(py);
        let rhs_inner = binding.inner.lock().unwrap();
        let similarity = self.inner.lock().unwrap().compare(&rhs_inner);
        similarity.as_ref()?;
        Some(ChromosomeSimilarity {
            inner: Arc::new(Mutex::new(similarity.unwrap())),
        })
    }

    #[pyo3(text_signature = "($self, rhs_blocks)")]
    pub fn compare_many(
        &self,
        py: Python,
        rhs_blocks: Py<PyList>,
    ) -> PyResult<BTreeMap<u64, ChromosomeSimilarity>> {
        let block = InnerBlockJsonDeserializer::new(
            self.json()?,
            self.inner.lock().unwrap().config.clone(),
        )?;

        let inner_config = self.inner.lock().unwrap().config.clone();

        let mut tasks = Vec::<InnerBlockJsonDeserializer>::new();

        let list = rhs_blocks.bind(py);

        let items: Vec<Py<PyAny>> = list.iter().map(|item| item.into()).collect();

        for item in items {
            let py_item = item.bind(py);
            if !py_item.is_instance_of::<BlockJsonDeserializer>() {
                return Err(pyo3::exceptions::PyTypeError::new_err(
                    "all items in rhs_blocks must be instances of BlockJsonDeserializer",
                ));
            }
            let rhs: Option<Py<BlockJsonDeserializer>> = py_item.extract().ok();
            if rhs.is_none() {
                continue;
            }
            let rhs_binding_0 = rhs.unwrap();
            let rhs_binding_1 = rhs_binding_0.borrow(py);
            let a = rhs_binding_1.inner.lock().unwrap().clone();
            tasks.push(a);
        }

        let pool = ThreadPoolBuilder::new()
            .num_threads(inner_config.general.threads)
            .build()
            .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", err)))?;

        let results: BTreeMap<u64, ChromosomeSimilarity> = pool.install(|| {
            tasks
                .par_iter()
                .filter_map(|rhs_block| {
                    block.compare(rhs_block).map(|similarity| {
                        (
                            rhs_block.address(),
                            ChromosomeSimilarity {
                                inner: Arc::new(Mutex::new(similarity)),
                            },
                        )
                    })
                })
                .collect()
        });
        Ok(results)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn address(&self) -> u64 {
        self.inner.lock().unwrap().address()
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
    pub fn sha256(&self) -> Option<String> {
        self.inner.lock().unwrap().sha256()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn edges(&self) -> usize {
        self.inner.lock().unwrap().edges()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn blocks(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().blocks()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn to(&self) -> BTreeSet<u64> {
        self.inner.lock().unwrap().to()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn conditional(&self) -> bool {
        self.inner.lock().unwrap().conditional()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn entropy(&self) -> Option<f64> {
        self.inner.lock().unwrap().entropy()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn next(&self) -> Option<u64> {
        self.inner.lock().unwrap().next()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().size()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn number_of_instructions(&self) -> usize {
        self.inner.lock().unwrap().number_of_instructions()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn chromosome(&self) -> Chromosome {
        let inner_chromosome = self.inner.lock().unwrap().chromosome();
        Chromosome {
            inner: Arc::new(Mutex::new(inner_chromosome)),
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
    pub fn address(&self) -> u64 {
        self.address
    }

    #[pyo3(text_signature = "($self)")]
    pub fn architecture(&self, py: Python) -> PyResult<Architecture> {
        self.with_inner_block(py, |block| {
            Ok(Architecture {
                inner: block.architecture(),
            })
        })
    }

    #[pyo3(text_signature = "($self, rhs)")]
    /// Compares this block with another returning the similarity.
    ///
    /// # Returns
    ///
    /// Returns an `Option<ChromosomeSimilarity>` reprenting the similarity between this block and another.
    pub fn compare(&self, py: Python, rhs: Py<Block>) -> PyResult<Option<ChromosomeSimilarity>> {
        self.with_inner_block(py, |block| {
            let rhs_address = rhs.borrow(py).address;
            let rhs_binding_0 = rhs.borrow(py);
            let rhs_binding_1 = rhs_binding_0.cfg.borrow(py);
            let rhs_cfg = rhs_binding_1.inner.lock().unwrap();
            let rhs_inner = InnerBlock::new(rhs_address, &rhs_cfg).expect("rhs block is invalid");
            let inner = block.compare(&rhs_inner);
            if inner.is_none() {
                return Ok(None);
            }
            let similarity = ChromosomeSimilarity {
                inner: Arc::new(Mutex::new(inner.unwrap())),
            };
            Ok(Some(similarity))
        })
    }

    #[pyo3(text_signature = "($self, rhs_blocks)")]
    /// Compares this block with many othe rblocks returning the similarity.
    ///
    /// # Returns
    ///
    /// Returns an `PyResult<BTreeMap<u64, ChromosomeSimilarity>>` reprenting the similarity between this block and many others.
    pub fn compare_many(
        &self,
        py: Python,
        rhs_blocks: Py<PyList>,
    ) -> PyResult<BTreeMap<u64, ChromosomeSimilarity>> {
        self.with_inner_block(py, |block| {
            let mut tasks = Vec::<(u64, Arc<Mutex<InnerGraph>>)>::new();

            let list = rhs_blocks.bind(py);

            let items: Vec<Py<PyAny>> = list.iter().map(|item| item.into()).collect();

            for item in items {
                let py_item = item.bind(py);
                if !py_item.is_instance_of::<Block>() {
                    return Err(pyo3::exceptions::PyTypeError::new_err(
                        "all items in rhs_blocks must be instances of Block",
                    ));
                }
                let rhs: Option<Py<Block>> = py_item.extract().ok();
                if rhs.is_none() {
                    continue;
                }
                let rhs_binding_0 = rhs.unwrap();
                let rhs_binding_1 = rhs_binding_0.borrow(py);
                let address = rhs_binding_1.address();
                let rhs_cfg = Arc::clone(&rhs_binding_1.cfg.borrow(py).inner);
                tasks.push((address, rhs_cfg));
            }

            let pool = ThreadPoolBuilder::new()
                .num_threads(block.cfg.config.general.threads)
                .build()
                .map_err(|err| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", err)))?;

            let results: BTreeMap<u64, ChromosomeSimilarity> = pool.install(|| {
                tasks
                    .par_iter()
                    .filter_map(|(address, inner_cfg)| {
                        let c = inner_cfg.lock().unwrap();
                        let rhs_block = InnerBlock::new(*address, &c).ok()?;
                        block.compare(&rhs_block).map(|similarity| {
                            (
                                *address,
                                ChromosomeSimilarity {
                                    inner: Arc::new(Mutex::new(similarity)),
                                },
                            )
                        })
                    })
                    .collect()
            });
            Ok(results)
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Returns the chromosome associated with this block.
    ///
    /// # Returns
    /// - `PyResult<Option<Chromosome>>`: The chromosome associated with this block.
    pub fn chromosome(&self, py: Python) -> PyResult<Option<Chromosome>> {
        self.with_inner_block(py, |block| {
            let inner_config = self.cfg.borrow(py).inner.lock().unwrap().config.clone();
            let config = Py::new(
                py,
                Config {
                    inner: Arc::new(Mutex::new(inner_config)),
                },
            )
            .unwrap();
            let pattern = block.pattern();
            let chromosome = Chromosome::new(py, pattern, config).ok();
            Ok(chromosome)
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
        self.with_inner_block(py, |block| {
            let bytes = PyBytes::new_bound(py, &block.bytes());
            Ok(bytes.into())
        })
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
        self.with_inner_block(py, |block| {
            block.print();
            Ok(())
        })
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
            block
                .json()
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
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
    m.add_class::<BlockJsonDeserializer>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.block", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.block")?;
    Ok(())
}
