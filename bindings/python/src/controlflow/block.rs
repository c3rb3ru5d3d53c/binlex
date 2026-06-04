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
use crate::controlflow::EntityKind;
use crate::controlflow::Function;
use crate::controlflow::Instruction;
use crate::controlflow::Reference;
use crate::genetics::Chromosome;
use crate::hashing::{MinHash32, SSDeep, SHA256, TLSH};
use crate::irs::lir::LirBlock as PyLirBlock;
use crate::irs::llvm::LlvmModule as PyLlvmModule;
use crate::irs::mir::PyMirBlock;
#[cfg(not(target_os = "windows"))]
use crate::irs::vex::VexModule as PyVexModule;
use crate::Architecture;
use binlex::controlflow::Block as InnerBlock;
use binlex::controlflow::EntityKind as InnerEntityKind;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::Py;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

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
    pub(crate) fn with_inner_block<F, R>(&self, py: Python, f: F) -> PyResult<R>
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
    /// Return the entity kind for this block.
    pub fn kind(&self) -> EntityKind {
        EntityKind::from_inner(InnerEntityKind::Block)
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
    /// - `PyResult<Chromosome>`: The chromosome associated with this block.
    pub fn chromosome(&self, py: Python) -> PyResult<Chromosome> {
        self.with_inner_block(py, |block| {
            let binding = self.cfg.borrow(py);
            let inner_config = binding.inner.lock().unwrap().config.clone();
            let inner_chromosome = block.chromosome();
            Ok(Chromosome {
                inner: Arc::new(Mutex::new(inner_chromosome)),
                minhash_num_hashes: inner_config.chromosomes.minhash.number_of_hashes,
                minhash_shingle_size: inner_config.chromosomes.minhash.shingle_size,
                minhash_seed: inner_config.chromosomes.minhash.seed,
                tlsh_minimum_byte_size: inner_config.chromosomes.tlsh.minimum_byte_size,
            })
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
    pub fn lir(&self, py: Python<'_>) -> PyResult<Py<PyLirBlock>> {
        self.with_inner_block(py, |block| {
            Py::new(py, PyLirBlock::from_inner(block.lir()?))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn mir(&self, py: Python<'_>) -> PyResult<Py<PyMirBlock>> {
        self.with_inner_block(py, |block| {
            Py::new(py, PyMirBlock::from_inner(block.mir()?))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn llvm(&self, py: Python<'_>) -> PyResult<Py<PyLlvmModule>> {
        self.with_inner_block(py, |block| {
            let inner = block.llvm()?;
            let cpu = binlex::irs::lir::LirCpu::from_architecture(block.architecture())
                .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
            Py::new(
                py,
                PyLlvmModule::from_inner(inner, block.cfg.config.clone(), cpu, None, None),
            )
        })
    }

    #[cfg(not(target_os = "windows"))]
    #[pyo3(text_signature = "($self)")]
    pub fn vex(&self, py: Python<'_>) -> PyResult<Py<PyVexModule>> {
        self.with_inner_block(py, |block| {
            let inner = block.vex()?;
            Py::new(py, PyVexModule::from_inner(inner, block.cfg.config.clone()))
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the raw bytes of the block.
    pub fn bytes(&self, py: Python) -> PyResult<Py<PyBytes>> {
        self.with_inner_block(py, |block| Ok(PyBytes::new(py, &block.bytes()).unbind()))
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
    /// Retrieves the sequential fallthrough address in the block.
    pub fn fallthrough(&self, py: Python) -> PyResult<Option<u64>> {
        self.with_inner_block(py, |block| Ok(block.fallthrough()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the set of explicit branch target addresses for this block.
    pub fn branches(&self, py: Python) -> PyResult<BTreeSet<u64>> {
        self.with_inner_block(py, |block| Ok(block.branches()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return whether the block ends in a conditional transfer of control.
    pub fn is_conditional(&self, py: Python) -> PyResult<bool> {
        self.with_inner_block(py, |block| Ok(block.is_conditional()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Calculates the entropy of the block.
    pub fn entropy(&self, py: Python) -> PyResult<f64> {
        self.with_inner_block(py, |block| {
            block.entropy().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("failed to compute block entropy")
            })
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the direct successor blocks.
    pub fn successors(&self, py: Python) -> PyResult<Vec<Block>> {
        self.with_inner_block(py, |block| {
            Ok(block
                .successors()
                .into_iter()
                .map(|successor| {
                    Block::new(successor.address(), self.cfg.clone_ref(py))
                        .expect("failed to get successor")
                })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the direct predecessor blocks.
    pub fn predecessors(&self, py: Python) -> PyResult<Vec<Block>> {
        self.with_inner_block(py, |block| {
            Ok(block
                .predecessors()
                .into_iter()
                .map(|predecessor| {
                    Block::new(predecessor.address(), self.cfg.clone_ref(py))
                        .expect("failed to get predecessor")
                })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the direct outgoing control-flow references.
    pub fn successor_references(&self, py: Python) -> PyResult<Vec<Reference>> {
        self.with_inner_block(py, |block| {
            Ok(block
                .successor_references()
                .into_iter()
                .map(|reference| Reference { inner: reference })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the direct incoming control-flow references.
    pub fn predecessor_references(&self, py: Python) -> PyResult<Vec<Reference>> {
        self.with_inner_block(py, |block| {
            Ok(block
                .predecessor_references()
                .into_iter()
                .map(|reference| Reference { inner: reference })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the number of instructions in the block.
    pub fn number_of_instructions(&self, py: Python) -> PyResult<usize> {
        self.with_inner_block(py, |block| Ok(block.number_of_instructions()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the directly called functions.
    pub fn callees(&self, py: Python) -> PyResult<Vec<Function>> {
        self.with_inner_block(py, |block| {
            Ok(block
                .callees()
                .into_iter()
                .map(|callee| {
                    Function::new(callee.address(), self.cfg.clone_ref(py))
                        .expect("failed to get callee")
                })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the direct outgoing call references.
    pub fn callee_references(&self, py: Python) -> PyResult<Vec<Reference>> {
        self.with_inner_block(py, |block| {
            Ok(block
                .callee_references()
                .into_iter()
                .map(|reference| Reference { inner: reference })
                .collect())
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the TLSH (Trend Micro Locality Sensitive Hash) of the block.
    pub fn tlsh(&self, py: Python) -> PyResult<TLSH> {
        self.with_inner_block(py, |block| {
            let hash = block.tlsh().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("failed to compute block tlsh")
            })?;
            Ok(TLSH {
                bytes: hash.bytes.into_owned(),
            })
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Retrieves the SHA-256 hash of the block.
    pub fn sha256(&self, py: Python) -> PyResult<SHA256> {
        self.with_inner_block(py, |block| {
            let hash = block.sha256().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("failed to compute block sha256")
            })?;
            Ok(SHA256 {
                bytes: hash.bytes.into_owned(),
            })
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
    /// Returns the ssdeep helper for this block.
    pub fn ssdeep(&self, py: Python) -> PyResult<SSDeep> {
        self.with_inner_block(py, |block| {
            let hash = block.ssdeep().ok_or_else(|| {
                PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("failed to compute block ssdeep")
            })?;
            Ok(SSDeep {
                bytes: hash.bytes.into_owned(),
            })
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

    pub fn __str__(&self) -> String {
        format!("Block(address=0x{:x})", self.address)
    }
}

#[pymodule]
#[pyo3(name = "block")]
pub fn block_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Block>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.block", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.block")?;
    Ok(())
}
