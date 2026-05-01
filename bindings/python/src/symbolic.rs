use crate::core::Architecture as PyArchitecture;
use crate::semantics::InstructionSemantics as PyInstructionSemantics;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct SliceInstructionData {
    architecture: String,
    mnemonic: String,
    disassembly: String,
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct SliceItemData {
    instruction: Option<SliceInstructionData>,
    location: String,
    value: String,
    parents: Vec<usize>,
}

#[pyclass(unsendable)]
pub struct Executor {
    inner: Arc<Mutex<::binlex::symbolic::Executor>>,
}

#[pyclass(unsendable)]
pub struct State {
    inner: Arc<Mutex<::binlex::symbolic::State>>,
}

#[pyclass(unsendable)]
pub struct SliceInstruction {
    inner: SliceInstructionData,
}

#[pyclass(unsendable)]
pub struct SliceNode {
    nodes: Arc<Vec<SliceItemData>>,
    index: usize,
}

#[pyclass(unsendable)]
pub struct Slice {
    nodes: Arc<Vec<SliceItemData>>,
}

fn wrap_slice(slice: ::binlex::symbolic::Slice) -> Slice {
    let id_to_index = slice
        .nodes()
        .iter()
        .enumerate()
        .map(|(index, node)| (node.id, index))
        .collect::<HashMap<_, _>>();
    let nodes = slice
        .nodes()
        .iter()
        .map(|node| SliceItemData {
            instruction: node.instruction.as_ref().map(|instruction| SliceInstructionData {
                architecture: instruction.architecture.clone(),
                mnemonic: instruction.mnemonic.clone(),
                disassembly: instruction.disassembly.clone(),
                address: instruction.address,
                bytes: instruction.bytes.clone(),
            }),
            location: node.location.clone(),
            value: node.value.clone(),
            parents: node
                .parents
                .iter()
                .filter_map(|id| id_to_index.get(id).copied())
                .collect(),
        })
        .collect::<Vec<_>>();
    Slice {
        nodes: Arc::new(nodes),
    }
}

fn wrap_state(py: Python<'_>, state: ::binlex::symbolic::State) -> PyResult<Py<State>> {
    Py::new(
        py,
        State {
            inner: Arc::new(Mutex::new(state)),
        },
    )
}

#[pymethods]
impl Executor {
    #[new]
    #[pyo3(text_signature = "(architecture)")]
    pub fn new(architecture: PyRef<'_, PyArchitecture>) -> PyResult<Self> {
        let inner = ::binlex::symbolic::Executor::new(architecture.inner)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn state(&self) -> State {
        State {
            inner: Arc::new(Mutex::new(self.inner.lock().unwrap().state())),
        }
    }

    #[pyo3(text_signature = "($self, semantics, state)")]
    pub fn step(
        &self,
        py: Python<'_>,
        semantics: PyRef<'_, PyInstructionSemantics>,
        state: PyRef<'_, State>,
    ) -> PyResult<Vec<Py<State>>> {
        let semantics = semantics.inner.lock().unwrap().clone();
        let state_guard = state.inner.lock().unwrap();
        let states = self
            .inner
            .lock()
            .unwrap()
            .step(&semantics, &state_guard)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        states
            .into_iter()
            .map(|state| wrap_state(py, state))
            .collect()
    }

    #[pyo3(text_signature = "($self, semantics, state)")]
    pub fn run(
        &self,
        py: Python<'_>,
        semantics: Vec<Py<PyInstructionSemantics>>,
        state: PyRef<'_, State>,
    ) -> PyResult<Vec<Py<State>>> {
        let owned = semantics
            .into_iter()
            .map(|item| item.borrow(py).inner.lock().unwrap().clone())
            .collect::<Vec<_>>();
        let refs = owned.iter().collect::<Vec<_>>();
        let state_guard = state.inner.lock().unwrap();
        let states = self
            .inner
            .lock()
            .unwrap()
            .run(refs, &state_guard)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        states
            .into_iter()
            .map(|state| wrap_state(py, state))
            .collect()
    }
}

#[pymethods]
impl State {
    #[pyo3(text_signature = "($self, name, bits, symbol=None)")]
    #[pyo3(signature = (name, bits, symbol=None))]
    pub fn symbolize_register(
        &self,
        name: String,
        bits: u16,
        symbol: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .symbolize_register(&name, bits, symbol.as_deref())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, name, bits, value)")]
    pub fn set_register(&self, name: String, bits: u16, value: u64) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .set_register(&name, bits, value)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, name, bits)")]
    pub fn symbolic_register(&self, name: String, bits: u16) -> PyResult<Option<String>> {
        self.inner
            .lock()
            .unwrap()
            .symbolic_register(&name, bits)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, name, bits)")]
    pub fn evaluate_register(&self, name: String, bits: u16) -> PyResult<Option<u64>> {
        self.inner
            .lock()
            .unwrap()
            .evaluate_register(&name, bits)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, size)")]
    pub fn map_memory(&self, address: u64, size: u64) {
        self.inner.lock().unwrap().map_memory(address, size);
    }

    #[pyo3(text_signature = "($self, address, data)")]
    pub fn write_memory(&self, address: u64, data: Vec<u8>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .write_memory(address, &data)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, size, name=None)")]
    #[pyo3(signature = (address, size, name=None))]
    pub fn symbolize_memory(
        &self,
        address: u64,
        size: usize,
        name: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .symbolize_memory(address, size, name.as_deref())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, size)")]
    pub fn symbolic_memory(&self, address: u64, size: usize) -> PyResult<String> {
        self.inner
            .lock()
            .unwrap()
            .symbolic_memory(address, size)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, size)")]
    pub fn evaluate_memory(&self, address: u64, size: usize) -> PyResult<Option<u64>> {
        self.inner
            .lock()
            .unwrap()
            .evaluate_memory(address, size)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, name, bits)")]
    pub fn slice_from_register(&self, name: String, bits: u16) -> PyResult<Slice> {
        self.inner
            .lock()
            .unwrap()
            .slice_from_register(&name, bits)
            .map(wrap_slice)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, size)")]
    pub fn slice_from_memory(&self, address: u64, size: usize) -> PyResult<Slice> {
        self.inner
            .lock()
            .unwrap()
            .slice_from_memory(address, size)
            .map(wrap_slice)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn constraints(&self) -> Vec<String> {
        self.inner.lock().unwrap().constraints()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn satisfiable(&self) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .satisfiable()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn model(&self) -> PyResult<std::collections::HashMap<String, String>> {
        self.inner
            .lock()
            .unwrap()
            .model()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }
}

#[pymethods]
impl SliceInstruction {
    pub fn architecture(&self) -> String {
        self.inner.architecture.clone()
    }

    pub fn mnemonic(&self) -> String {
        self.inner.mnemonic.clone()
    }

    pub fn disassembly(&self) -> String {
        self.inner.disassembly.clone()
    }

    pub fn address(&self) -> u64 {
        self.inner.address
    }

    pub fn bytes(&self) -> Vec<u8> {
        self.inner.bytes.clone()
    }
}

#[pymethods]
impl SliceNode {
    pub fn instruction(&self, py: Python<'_>) -> PyResult<Option<Py<SliceInstruction>>> {
        self.nodes[self.index]
            .instruction
            .clone()
            .map(|inner| Py::new(py, SliceInstruction { inner }))
            .transpose()
    }

    pub fn location(&self) -> String {
        self.nodes[self.index].location.clone()
    }

    pub fn value(&self) -> String {
        self.nodes[self.index].value.clone()
    }

    pub fn parents(&self, py: Python<'_>) -> PyResult<Vec<Py<SliceNode>>> {
        self.nodes[self.index]
            .parents
            .iter()
            .map(|index| {
                Py::new(
                    py,
                    SliceNode {
                        nodes: self.nodes.clone(),
                        index: *index,
                    },
                )
            })
            .collect()
    }
}

#[pymethods]
impl Slice {
    #[pyo3(text_signature = "($self)")]
    pub fn nodes(&self, py: Python<'_>) -> PyResult<Vec<Py<SliceNode>>> {
        (0..self.nodes.len())
            .map(|index| {
                Py::new(
                    py,
                    SliceNode {
                        nodes: self.nodes.clone(),
                        index,
                    },
                )
            })
            .collect()
    }

    pub fn number_of_nodes(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

#[pymodule]
#[pyo3(name = "symbolic")]
pub fn symbolic_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Executor>()?;
    m.add_class::<State>()?;
    m.add_class::<SliceInstruction>()?;
    m.add_class::<SliceNode>()?;
    m.add_class::<Slice>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.symbolic", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.symbolic")?;
    Ok(())
}
