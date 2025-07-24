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
use pyo3::prelude::*;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

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
    pub fn insert_invalid(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_invalid(address);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn is_invalid(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_invalid(address)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn valid_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).valid_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn invalid_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).invalid_addresses()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn processed_addresses(&self) -> BTreeSet<u64> {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).processed_addresses()
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn is_valid(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_valid(address)
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn insert_valid(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_valid(address);
    }

    #[pyo3(text_signature = "($self, addresses)")]
    pub fn insert_processed_extend(&self, addresses: BTreeSet<u64>) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner)
            .insert_processed_extend(addresses);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn insert_processed(&self, address: u64) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).insert_processed(address);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn is_processed(&self, address: u64) -> bool {
        let inner = self.inner_graph.lock().unwrap();
        self.get_queue(&inner).is_processed(address)
    }

    #[pyo3(text_signature = "($self, addresses)")]
    pub fn enqueue_extend(&self, addresses: BTreeSet<u64>) {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).enqueue_extend(addresses);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn enqueue(&self, address: u64) -> bool {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).enqueue(address)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dequeue(&self) -> Option<u64> {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).dequeue()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dequeue_all(&self) -> BTreeSet<u64> {
        let mut inner = self.inner_graph.lock().unwrap();
        self.get_queue_mut(&mut inner).dequeue_all()
    }
}

#[pyclass]
pub struct Graph {
    pub inner: Arc<Mutex<InnerGraph>>,
}

#[pymethods]
impl Graph {
    #[new]
    #[pyo3(text_signature = "(architecture, config)")]
    pub fn new(py: Python, architecture: Py<Architecture>, config: Py<Config>) -> Self {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerGraph::new(architecture.borrow(py).inner, inner_config);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    #[pyo3(text_signature = "($self)")]
    pub fn instructions(&self, py: Python) -> Vec<Instruction> {
        let mut result = Vec::<Instruction>::new();
        for inner_instruction in self.inner.lock().unwrap().blocks() {
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

    #[getter]
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
    pub fn set_block(&self, address: u64) -> bool {
        self.inner.lock().unwrap().set_block(address)
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn set_function(&self, address: u64) -> bool {
        self.inner.lock().unwrap().set_function(address)
    }

    #[pyo3(text_signature = "($self, address, addresses)")]
    pub fn extend_instruction_edges(&self, address: u64, addresses: BTreeSet<u64>) -> bool {
        self.inner
            .lock()
            .unwrap()
            .extend_instruction_edges(address, addresses)
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn get_instruction(&self, py: Python, address: u64) -> Option<Instruction> {
        let cfg = Graph {
            inner: Arc::clone(&self.inner),
        };
        let pycfg = Py::new(py, cfg).ok();
        pycfg.as_ref()?;
        Instruction::new(address, pycfg.unwrap()).ok()
    }

    #[pyo3(text_signature = "($self, cfg)")]
    pub fn absorb(&mut self, py: Python, cfg: Py<Self>) {
        self.inner
            .lock()
            .unwrap()
            .absorb(&mut cfg.borrow_mut(py).inner.lock().unwrap());
    }
}

#[pymodule]
#[pyo3(name = "graph")]
pub fn graph_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<GraphQueue>()?;
    m.add_class::<Graph>()?;
    py.import_bound("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.graph", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.graph")?;
    Ok(())
}
