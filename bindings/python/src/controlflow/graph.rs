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
use crate::controlflow::Function;
use crate::controlflow::Instruction;
use crate::Architecture;
use crate::Config;
use binlex::controlflow::Graph as InnerGraph;
use binlex::controlflow::GraphQueue as InnerGraphQueue;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

/// Manage the discovery state for instructions, blocks, or functions in a graph.
#[pyclass]
pub struct GraphQueue {
    inner_graph: Arc<Mutex<InnerGraph>>,
    kind: QueueKind,
}

#[derive(Clone, Copy)]
enum QueueKind {
    Instructions,
    Blocks,
    Functions,
}

impl GraphQueue {
    fn get_queue<'a>(&self, inner: &'a InnerGraph) -> &'a InnerGraphQueue {
        match self.kind {
            QueueKind::Instructions => &inner.instructions,
            QueueKind::Blocks => &inner.blocks,
            QueueKind::Functions => &inner.functions,
        }
    }

    fn get_queue_mut<'a>(&self, inner: &'a mut InnerGraph) -> &'a mut InnerGraphQueue {
        match self.kind {
            QueueKind::Instructions => &mut inner.instructions,
            QueueKind::Blocks => &mut inner.blocks,
            QueueKind::Functions => &mut inner.functions,
        }
    }
}

#[pymethods]
impl GraphQueue {
    #[pyo3(text_signature = "($self, address)")]
    /// Mark an address as invalid for this queue.
    pub fn insert_invalid(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_invalid(address);
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Return whether an address is marked invalid.
    pub fn is_invalid(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_invalid(address)
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all addresses currently marked valid.
    pub fn valid_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).valid_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all addresses currently marked invalid.
    pub fn invalid_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).invalid_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all addresses already processed by this queue.
    pub fn processed_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).processed_addresses()
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Return whether an address is marked valid.
    pub fn is_valid(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_valid(address)
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Mark an address as valid for future processing.
    pub fn insert_valid(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_valid(address);
    }

    #[pyo3(text_signature = "($self, addresses)")]
    /// Mark a set of addresses as processed.
    pub fn insert_processed_extend(&self, addresses: BTreeSet<u64>) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner)
            .insert_processed_extend(addresses);
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Mark a single address as processed.
    pub fn insert_processed(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_processed(address);
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Return whether an address has already been processed.
    pub fn is_processed(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_processed(address)
    }

    #[pyo3(text_signature = "($self, addresses)")]
    /// Enqueue a set of addresses for later processing.
    pub fn enqueue_extend(&self, addresses: BTreeSet<u64>) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).enqueue_extend(addresses);
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Enqueue a single address for later processing.
    pub fn enqueue(&self, address: u64) -> bool {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).enqueue(address)
    }

    #[pyo3(text_signature = "($self)")]
    /// Dequeue the next pending address, if one exists.
    pub fn dequeue(&self) -> Option<u64> {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).dequeue()
    }

    #[pyo3(text_signature = "($self)")]
    /// Dequeue and return all pending addresses.
    pub fn dequeue_all(&self) -> BTreeSet<u64> {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).dequeue_all()
    }
}

/// Represent a mutable control-flow graph used during analysis.
#[pyclass]
pub struct Graph {
    pub inner: Arc<Mutex<InnerGraph>>,
}

impl Graph {
    pub fn from_inner(inner: InnerGraph) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl Graph {
    #[new]
    #[pyo3(text_signature = "(architecture, config)")]
    /// Create a new graph for the supplied architecture and configuration.
    pub fn new(py: Python, architecture: Py<Architecture>, config: Py<Config>) -> Self {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerGraph::new(architecture.borrow(py).inner, inner_config);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all instructions currently materialized in the graph.
    pub fn instructions(&self, py: Python) -> Vec<Instruction> {
        let mut result = Vec::<Instruction>::new();
        for inner_instruction in self.inner.lock().unwrap().instructions() {
            let cfg = Graph {
                inner: Arc::clone(&self.inner),
            };
            let pycfg = Py::new(py, cfg).ok();
            if pycfg.is_none() {
                continue;
            }
            let instruction = Instruction::new(inner_instruction.address, pycfg.unwrap()).ok();
            if instruction.is_none() {
                continue;
            }
            result.push(instruction.unwrap());
        }
        result
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all blocks currently materialized in the graph.
    pub fn blocks(&self, py: Python) -> Vec<Block> {
        let mut result = Vec::<Block>::new();
        for inner_block in self.inner.lock().unwrap().blocks() {
            let cfg = Graph {
                inner: Arc::clone(&self.inner),
            };
            let pycfg = Py::new(py, cfg).ok();
            if pycfg.is_none() {
                continue;
            }
            let block = Block::new(inner_block.address, pycfg.unwrap()).ok();
            if block.is_none() {
                continue;
            }
            result.push(block.unwrap());
        }
        result
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all functions currently materialized in the graph.
    pub fn functions(&self, py: Python) -> Vec<Function> {
        let mut result = Vec::<Function>::new();
        for inner_function in self.inner.lock().unwrap().functions() {
            let cfg = Graph {
                inner: Arc::clone(&self.inner),
            };
            let pycfg = Py::new(py, cfg).ok();
            if pycfg.is_none() {
                continue;
            }
            let function = Function::new(inner_function.address, pycfg.unwrap()).ok();
            if function.is_none() {
                continue;
            }
            result.push(function.unwrap());
        }
        result
    }

    #[pyo3(text_signature = "($self)")]
    /// Process queued graph state for instructions, blocks, and functions.
    pub fn process(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .process()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Process only queued block state.
    pub fn process_blocks(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .process_blocks()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Process only queued function state.
    pub fn process_functions(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .process_functions()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the number of graph mutations that have occurred.
    pub fn mutations(&self) -> u64 {
        self.inner.lock().unwrap().mutations()
    }

    #[getter]
    /// Return the queue that tracks instruction discovery.
    pub fn get_queue_instructions(&self, py: Python) -> Py<GraphQueue> {
        Py::new(
            py,
            GraphQueue {
                inner_graph: Arc::clone(&self.inner),
                kind: QueueKind::Instructions,
            },
        )
        .expect("failed to get instructions graph queue")
    }

    #[getter]
    /// Return the queue that tracks block discovery.
    pub fn get_queue_blocks(&self, py: Python) -> Py<GraphQueue> {
        Py::new(
            py,
            GraphQueue {
                inner_graph: Arc::clone(&self.inner),
                kind: QueueKind::Blocks,
            },
        )
        .expect("failed to get blocks graph queue")
    }

    #[getter]
    /// Return the queue that tracks function discovery.
    pub fn get_queue_functions(&self, py: Python) -> Py<GraphQueue> {
        Py::new(
            py,
            GraphQueue {
                inner_graph: Arc::clone(&self.inner),
                kind: QueueKind::Functions,
            },
        )
        .expect("failed to get functions graph queue")
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Mark an address as a block entrypoint.
    pub fn set_block(&self, address: u64) -> bool {
        self.inner.lock().unwrap().set_block(address)
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Mark an address as a function entrypoint.
    pub fn set_function(&self, address: u64) -> bool {
        self.inner.lock().unwrap().set_function(address)
    }

    #[pyo3(text_signature = "($self, address, addresses)")]
    /// Attach successor addresses to an instruction in the graph.
    pub fn extend_instruction_edges(&self, address: u64, addresses: BTreeSet<u64>) -> bool {
        self.inner
            .lock()
            .unwrap()
            .extend_instruction_edges(address, addresses)
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Return the instruction at `address`, if it exists in the graph.
    pub fn get_instruction(&self, py: Python, address: u64) -> Option<Instruction> {
        let cfg = Graph {
            inner: Arc::clone(&self.inner),
        };
        let pycfg = Py::new(py, cfg).ok();
        pycfg.as_ref()?;
        Instruction::new(address, pycfg.unwrap()).ok()
    }

    #[pyo3(text_signature = "($self, cfg)")]
    /// Merge another graph into this graph in place.
    pub fn merge(&mut self, py: Python, cfg: Py<Self>) {
        self.inner
            .lock()
            .unwrap()
            .merge(&mut cfg.borrow_mut(py).inner.lock().unwrap());
    }
}

#[pymodule]
#[pyo3(name = "graph")]
pub fn graph_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<GraphQueue>()?;
    m.add_class::<Graph>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.graph", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.graph")?;
    Ok(())
}
