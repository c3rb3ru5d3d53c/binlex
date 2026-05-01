use crate::core::Architecture as PyArchitecture;
use crate::semantics::InstructionSemantics as PyInstructionSemantics;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyModule;
use std::sync::{Arc, Mutex};

#[pyclass(unsendable)]
pub struct Executor {
    inner: Arc<Mutex<::binlex::symbolic::Executor>>,
}

#[pyclass(unsendable)]
pub struct State {
    inner: Arc<Mutex<::binlex::symbolic::State>>,
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
            .map(|state| {
                Py::new(
                    py,
                    State {
                        inner: Arc::new(Mutex::new(state)),
                    },
                )
            })
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
            .map(|state| {
                Py::new(
                    py,
                    State {
                        inner: Arc::new(Mutex::new(state)),
                    },
                )
            })
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

#[pymodule]
#[pyo3(name = "symbolic")]
pub fn symbolic_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Executor>()?;
    m.add_class::<State>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.symbolic", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.symbolic")?;
    Ok(())
}
