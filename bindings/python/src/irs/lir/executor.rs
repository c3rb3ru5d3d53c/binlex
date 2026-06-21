use crate::formats::Image as PyImage;
use crate::irs::lir::{LirCpu as PyLirCpu, LirModule as PyLirModule};
use pyo3::exceptions::{PyRuntimeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct SliceInstructionData {
    address: u64,
}

#[derive(Clone)]
struct SliceItemData {
    instruction: Option<SliceInstructionData>,
    location: String,
    value: String,
    parents: Vec<usize>,
}

#[pyclass(name = "LirExecutor", unsendable)]
pub struct LirExecutor {
    inner: Arc<Mutex<::binlex::irs::lir::executor::LirExecutor>>,
    hooks: Arc<Mutex<BTreeMap<u64, Py<PyAny>>>>,
}

#[pyclass(name = "LirExecutorState", unsendable)]
pub struct LirExecutorState {
    inner: Arc<Mutex<::binlex::irs::lir::executor::LirExecutorState>>,
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

fn wrap_slice(slice: ::binlex::irs::lir::executor::Slice) -> Slice {
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
            instruction: node
                .instruction
                .as_ref()
                .map(|instruction| SliceInstructionData {
                    address: instruction.address,
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

fn wrap_state(
    py: Python<'_>,
    state: ::binlex::irs::lir::executor::LirExecutorState,
) -> PyResult<Py<LirExecutorState>> {
    Py::new(
        py,
        LirExecutorState {
            inner: Arc::new(Mutex::new(state)),
        },
    )
}

fn collect_lir(py: Python<'_>, lir: Py<PyLirModule>) -> ::binlex::irs::lir::LirModule {
    lir.borrow(py).inner.lock().unwrap().clone()
}

#[pymethods]
impl LirExecutor {
    #[new]
    #[pyo3(text_signature = "()")]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(::binlex::irs::lir::executor::LirExecutor::new())),
            hooks: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[pyo3(text_signature = "($self, lir, state)")]
    pub fn step(
        &self,
        py: Python<'_>,
        lir: Py<PyLirModule>,
        state: PyRef<'_, LirExecutorState>,
    ) -> PyResult<Vec<Py<LirExecutorState>>> {
        let lir = collect_lir(py, lir);
        let state_guard = state.inner.lock().unwrap();
        let states = self
            .inner
            .lock()
            .unwrap()
            .step(&lir, &state_guard)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        states
            .into_iter()
            .map(|state| wrap_state(py, state))
            .collect()
    }

    #[pyo3(text_signature = "($self, lir, state, steps=None)")]
    #[pyo3(signature = (lir, state, steps=None))]
    pub fn run(
        &self,
        py: Python<'_>,
        lir: Py<PyLirModule>,
        state: PyRef<'_, LirExecutorState>,
        steps: Option<usize>,
    ) -> PyResult<Vec<Py<LirExecutorState>>> {
        let owned = collect_lir(py, lir);
        let hooks = self
            .hooks
            .lock()
            .unwrap()
            .iter()
            .map(|(address, hook)| (*address, hook.clone_ref(py)))
            .collect::<BTreeMap<_, _>>();

        if hooks.is_empty() {
            let state_guard = state.inner.lock().unwrap();
            let states = self
                .inner
                .lock()
                .unwrap()
                .run(&owned, &state_guard, steps)
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
            return states
                .into_iter()
                .map(|state| wrap_state(py, state))
                .collect();
        }

        if steps.is_some() {
            return Err(PyRuntimeError::new_err(
                "hooked execution does not support step budgets",
            ));
        }

        let mut pending = vec![state.inner.lock().unwrap().clone()];
        let mut final_states = Vec::<Py<LirExecutorState>>::new();

        while let Some(current) = pending.pop() {
            let states = self
                .inner
                .lock()
                .unwrap()
                .run(&owned, &current, None)
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;

            for candidate in states {
                let Some(address) = candidate
                    .program_counter()
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?
                else {
                    final_states.push(wrap_state(py, candidate)?);
                    continue;
                };

                let Some(hook) = hooks.get(&address) else {
                    final_states.push(wrap_state(py, candidate)?);
                    continue;
                };

                let state = wrap_state(py, candidate)?;
                let returned = hook.call1(py, (address, state.clone_ref(py)))?;
                let returned_states =
                    returned
                        .extract::<Vec<Py<LirExecutorState>>>(py)
                        .map_err(|_| {
                            PyTypeError::new_err(
                                "hook must return a list of LirExecutorState objects",
                            )
                        })?;
                for returned_state in returned_states {
                    let returned_state_ref: PyRef<'_, LirExecutorState> = returned_state.borrow(py);
                    pending.push(returned_state_ref.inner.lock().unwrap().clone());
                }
            }
        }

        Ok(final_states)
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn set_breakpoint(&self, address: u64) {
        self.inner.lock().unwrap().set_breakpoint(address);
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn remove_breakpoint(&self, address: u64) {
        self.inner.lock().unwrap().remove_breakpoint(address);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn clear_breakpoints(&self) {
        self.inner.lock().unwrap().clear_breakpoints();
    }

    #[pyo3(text_signature = "($self)")]
    pub fn breakpoints(&self) -> Vec<u64> {
        self.inner.lock().unwrap().breakpoints()
    }

    #[pyo3(text_signature = "($self, address, hook)")]
    pub fn add_hook(&self, py: Python<'_>, address: u64, hook: Py<PyAny>) -> PyResult<()> {
        if !hook.bind(py).is_callable() {
            return Err(PyTypeError::new_err("hook must be callable"));
        }
        self.inner.lock().unwrap().add_hook(address);
        self.hooks.lock().unwrap().insert(address, hook);
        Ok(())
    }

    #[pyo3(text_signature = "($self, address)")]
    pub fn remove_hook(&self, address: u64) {
        self.inner.lock().unwrap().remove_hook(address);
        self.hooks.lock().unwrap().remove(&address);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn clear_hooks(&self) {
        self.inner.lock().unwrap().clear_hooks();
        self.hooks.lock().unwrap().clear();
    }

    #[pyo3(text_signature = "($self)")]
    pub fn hooks(&self) -> Vec<u64> {
        self.inner.lock().unwrap().hooks()
    }
}

#[pymethods]
impl LirExecutorState {
    #[new]
    #[pyo3(text_signature = "(cpu)")]
    pub fn new(cpu: PyRef<'_, PyLirCpu>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(
                ::binlex::irs::lir::executor::LirExecutorState::new(cpu.inner.clone()),
            )),
        }
    }

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

    #[pyo3(text_signature = "($self)")]
    pub fn program_counter(&self) -> PyResult<Option<u64>> {
        self.inner
            .lock()
            .unwrap()
            .program_counter()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, address, size)")]
    pub fn map_memory(&self, address: u64, size: u64) {
        self.inner.lock().unwrap().map_memory(address, size);
    }

    #[pyo3(text_signature = "($self, image)")]
    pub fn map_image(&self, image: PyRef<'_, PyImage>) {
        self.inner.lock().unwrap().map_image(&image.inner);
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

    #[pyo3(text_signature = "($self, address, size)")]
    pub fn read_memory(
        &self,
        py: Python<'_>,
        address: u64,
        size: usize,
    ) -> PyResult<Option<Py<PyBytes>>> {
        self.inner
            .lock()
            .unwrap()
            .read_memory(address, size)
            .map(|bytes| bytes.map(|bytes| PyBytes::new(py, &bytes).unbind()))
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
    pub fn address(&self) -> u64 {
        self.inner.address
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

pub fn register_executor_classes(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LirExecutor>()?;
    m.add_class::<LirExecutorState>()?;
    m.add_class::<SliceInstruction>()?;
    m.add_class::<SliceNode>()?;
    m.add_class::<Slice>()?;
    Ok(())
}
