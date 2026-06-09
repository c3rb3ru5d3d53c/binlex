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
use crate::formats::Image;
use crate::Architecture;
use crate::Configuration;
use binlex::controlflow::Graph as InnerGraph;
use binlex::controlflow::GraphQueue as InnerGraphQueue;
use binlex::controlflow::GraphState as InnerGraphState;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyType};
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;

fn json_value_to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json_str =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let json_module = py.import("json")?;
    Ok(json_module.call_method1("loads", (json_str,))?.into())
}

fn py_to_json_value(py: Python<'_>, value: Py<PyAny>) -> PyResult<Value> {
    let json_module = py.import("json")?;
    let json_str = json_module
        .call_method1("dumps", (value,))?
        .extract::<String>()?;
    serde_json::from_str(&json_str).map_err(|error| PyValueError::new_err(error.to_string()))
}

fn py_to_metadata(py: Python<'_>, value: Option<Py<PyAny>>) -> PyResult<BTreeMap<String, Value>> {
    let Some(value) = value else {
        return Ok(BTreeMap::new());
    };
    match py_to_json_value(py, value)? {
        Value::Object(object) => Ok(object.into_iter().collect()),
        _ => Err(PyValueError::new_err("graph metadata must be a dict")),
    }
}

/// Manage the discovery state for instructions, blocks, or functions in a graph.
#[pyclass]
pub struct GraphQueue {
    inner_graph: Arc<Mutex<InnerGraph>>,
    kind: QueueKind,
}

#[pyclass(module = "binlex_bindings.binlex.controlflow", skip_from_py_object)]
#[derive(Clone)]
pub struct GraphState {
    pub inner: InnerGraphState,
}

impl GraphState {
    pub fn from_inner(inner: InnerGraphState) -> Self {
        Self { inner }
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let encoded = serde_json::to_vec(&self.inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        lz4::block::compress(&encoded, None, true)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    fn from_bytes(bytes: &[u8]) -> PyResult<Self> {
        let encoded = lz4::block::decompress(bytes, None)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        let inner = serde_json::from_slice(&encoded)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }
}

#[pymethods]
impl GraphState {
    #[new]
    pub fn new(py: Python<'_>, state: Py<PyAny>) -> PyResult<Self> {
        let bytes = state.extract::<Vec<u8>>(py)?;
        Self::from_bytes(&bytes)
    }

    pub fn __getstate__(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let bytes = self.to_bytes()?;
        Ok(PyBytes::new(py, &bytes).unbind())
    }

    pub fn __reduce__(&self, py: Python<'_>) -> PyResult<(Py<PyType>, (Py<PyBytes>,))> {
        Ok((py.get_type::<Self>().unbind(), (self.__getstate__(py)?,)))
    }

    pub fn __setstate__(&mut self, py: Python<'_>, state: Py<PyAny>) -> PyResult<()> {
        let bytes = state.extract::<Vec<u8>>(py)?;
        self.inner = Self::from_bytes(&bytes)?.inner;
        Ok(())
    }
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
    pub image: Arc<Mutex<Option<Py<Image>>>>,
}

impl Graph {
    pub fn from_inner(inner: InnerGraph) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            image: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn clone_handle(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            image: Arc::clone(&self.image),
        }
    }
}

#[pymethods]
impl Graph {
    #[new]
    #[pyo3(text_signature = "(architecture, image, config, metadata=None)")]
    /// Create a new graph for the supplied architecture, image, and configuration.
    pub fn new(
        py: Python,
        architecture: Py<Architecture>,
        image: Py<Image>,
        config: Py<Configuration>,
        metadata: Option<Py<PyAny>>,
    ) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner_image = image.borrow(py).inner.clone();
        let inner = InnerGraph::new_with_image_metadata(
            architecture.borrow(py).inner,
            inner_image,
            inner_config,
            py_to_metadata(py, metadata)?,
        );
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            image: Arc::new(Mutex::new(Some(image))),
        })
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the graph architecture.
    pub fn architecture(&self) -> crate::Architecture {
        crate::Architecture {
            inner: self.inner.lock().unwrap().architecture,
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the graph-owned image.
    pub fn image(&self, py: Python<'_>) -> Option<Py<Image>> {
        self.image
            .lock()
            .unwrap()
            .as_ref()
            .map(|image| image.clone_ref(py))
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the graph configuration.
    pub fn configuration(&self) -> Configuration {
        Configuration {
            inner: Arc::new(Mutex::new(self.inner.lock().unwrap().config.clone())),
        }
    }

    #[pyo3(text_signature = "($self)")]
    /// Return executable virtual address ranges derived from the graph image.
    pub fn executable_virtual_address_ranges(&self) -> BTreeMap<u64, u64> {
        self.inner
            .lock()
            .unwrap()
            .executable_virtual_address_ranges()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return a complete serializable graph state.
    pub fn state(&self) -> GraphState {
        GraphState::from_inner(self.inner.lock().unwrap().state())
    }

    #[staticmethod]
    #[pyo3(text_signature = "(state)")]
    /// Restore a graph from a complete serializable graph state.
    pub fn from_state(py: Python<'_>, state: PyRef<'_, GraphState>) -> PyResult<Self> {
        let inner = InnerGraph::from_state(state.inner.clone())
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        let image = Py::new(py, Image::from_inner(inner.image.clone()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            image: Arc::new(Mutex::new(Some(image))),
        })
    }

    pub fn __getstate__(&self) -> GraphState {
        self.state()
    }

    pub fn __setstate__(&mut self, py: Python<'_>, state: PyRef<'_, GraphState>) -> PyResult<()> {
        let restored = Self::from_state(py, state)?;
        self.inner = restored.inner;
        self.image = restored.image;
        Ok(())
    }

    #[pyo3(text_signature = "($self)")]
    /// Return all instructions currently materialized in the graph.
    pub fn instructions(&self, py: Python) -> Vec<Instruction> {
        let mut result = Vec::<Instruction>::new();
        for inner_instruction in self.inner.lock().unwrap().instructions() {
            let cfg = self.clone_handle();
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
            let cfg = self.clone_handle();
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
        let binding = self.inner.lock().unwrap();
        let inner_ref: &'static binlex::controlflow::Graph = unsafe {
            std::mem::transmute::<&binlex::controlflow::Graph, &'static binlex::controlflow::Graph>(
                &*binding,
            )
        };
        for inner_function in inner_ref.functions() {
            let cfg = self.clone_handle();
            let pycfg = Py::new(py, cfg).ok();
            if pycfg.is_none() {
                continue;
            }
            result.push(Function::from_inner(
                inner_function.address,
                pycfg.unwrap(),
                unsafe { std::mem::transmute(inner_function) },
            ));
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

    #[pyo3(text_signature = "($self)")]
    /// Return the graph-owned metadata.
    pub fn metadata(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(self.inner.lock().unwrap().metadata()).unwrap(),
        )
    }

    #[pyo3(text_signature = "($self, metadata)")]
    /// Replace the graph-owned metadata.
    pub fn replace_metadata(&self, py: Python<'_>, metadata: Py<PyAny>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .replace_metadata(py_to_metadata(py, Some(metadata))?);
        Ok(())
    }

    #[pyo3(text_signature = "($self, metadata)")]
    /// Merge metadata into the graph-owned metadata.
    pub fn extend_metadata(&self, py: Python<'_>, metadata: Py<PyAny>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .extend_metadata(py_to_metadata(py, Some(metadata))?);
        Ok(())
    }

    #[pyo3(text_signature = "($self, key)")]
    /// Return one graph metadata value by key, if present.
    pub fn metadata_value(&self, py: Python<'_>, key: String) -> PyResult<Option<Py<PyAny>>> {
        self.inner
            .lock()
            .unwrap()
            .metadata_value(&key)
            .map(|value| json_value_to_py(py, &value))
            .transpose()
    }

    #[pyo3(text_signature = "($self)")]
    /// Return the symbol-name view derived from graph metadata.
    pub fn symbols(&self) -> BTreeMap<u64, String> {
        self.inner.lock().unwrap().symbols()
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Return the symbol name registered for `address`, if present.
    pub fn symbol(&self, address: u64) -> Option<String> {
        self.inner.lock().unwrap().symbol(address)
    }

    #[pyo3(text_signature = "($self, address, name)")]
    /// Insert or replace a single graph-owned symbol.
    pub fn insert_symbol(&self, address: u64, name: String) -> Option<String> {
        self.inner.lock().unwrap().insert_symbol(address, name)
    }

    #[pyo3(text_signature = "($self, symbols)")]
    /// Replace metadata symbols with the provided map.
    pub fn replace_symbols(&self, symbols: BTreeMap<u64, String>) {
        self.inner.lock().unwrap().replace_symbols(symbols);
    }

    #[pyo3(text_signature = "($self, symbols)")]
    /// Merge symbols into graph metadata.
    pub fn extend_symbols(&self, symbols: BTreeMap<u64, String>) {
        self.inner.lock().unwrap().extend_symbols(symbols);
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
    pub fn instruction(&self, py: Python, address: u64) -> Option<Instruction> {
        if self.inner.lock().unwrap().instruction(address).is_none() {
            return None;
        }
        let cfg = self.clone_handle();
        let pycfg = Py::new(py, cfg).ok();
        pycfg.as_ref()?;
        Instruction::new(address, pycfg.unwrap()).ok()
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Return the block at `address`, if it exists in the graph.
    pub fn block(&self, py: Python, address: u64) -> Option<Block> {
        if self.inner.lock().unwrap().block(address).is_none() {
            return None;
        }
        let cfg = self.clone_handle();
        let pycfg = Py::new(py, cfg).ok();
        pycfg.as_ref()?;
        Block::new(address, pycfg.unwrap()).ok()
    }

    #[pyo3(text_signature = "($self, address)")]
    /// Return the function at `address`, if it exists in the graph.
    pub fn function(&self, py: Python, address: u64) -> Option<Function> {
        if self.inner.lock().unwrap().function(address).is_none() {
            return None;
        }
        let cfg = self.clone_handle();
        let pycfg = Py::new(py, cfg).ok();
        pycfg.as_ref()?;
        Function::new(address, pycfg.unwrap()).ok()
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
    m.add_class::<GraphState>()?;
    m.add_class::<Graph>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.controlflow.graph", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.controlflow.graph")?;
    Ok(())
}
