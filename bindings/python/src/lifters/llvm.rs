use crate::controlflow::{Block, Function, Instruction};
use crate::Config;
use binlex::lifters::llvm::Lifter as InnerLifter;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

#[pyclass(unsendable)]
pub struct Lifter {
    pub inner: Arc<Mutex<InnerLifter>>,
}

#[pymethods]
impl Lifter {
    #[new]
    #[pyo3(text_signature = "(config)")]
    pub fn new(py: Python<'_>, config: Py<Config>) -> Self {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerLifter::new(inner_config);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    #[pyo3(text_signature = "($self, instruction)")]
    pub fn lift_instruction(&self, py: Python<'_>, instruction: &Instruction) -> PyResult<()> {
        instruction.with_inner_instruction(py, |inner| {
            self.inner
                .lock()
                .unwrap()
                .lift_instruction(inner)
                .map_err(|err| PyRuntimeError::new_err(err.to_string()))
        })
    }

    #[pyo3(text_signature = "($self, block)")]
    pub fn lift_block(&self, py: Python<'_>, block: &Block) -> PyResult<()> {
        block.with_inner_block(py, |inner| {
            self.inner
                .lock()
                .unwrap()
                .lift_block(inner)
                .map_err(|err| PyRuntimeError::new_err(err.to_string()))
        })
    }

    #[pyo3(text_signature = "($self, function)")]
    pub fn lift_function(&self, py: Python<'_>, function: &Function) -> PyResult<()> {
        function.with_inner_function(py, |inner| {
            self.inner
                .lock()
                .unwrap()
                .lift_function(inner)
                .map_err(|err| PyRuntimeError::new_err(err.to_string()))
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    #[pyo3(text_signature = "($self)")]
    pub fn bitcode(&self) -> Vec<u8> {
        self.inner.lock().unwrap().bitcode()
    }

    #[pyo3(text_signature = "($self)")]
    pub fn normalized(&self) -> PyResult<Self> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .normalized()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn mem2reg(&self) -> PyResult<Self> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .mem2reg()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn instcombine(&self) -> PyResult<Self> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .instcombine()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn cfg(&self) -> PyResult<Self> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .cfg()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn gvn(&self) -> PyResult<Self> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .gvn()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn sroa(&self) -> PyResult<Self> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .sroa()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn dce(&self) -> PyResult<Self> {
        let inner = self
            .inner
            .lock()
            .unwrap()
            .dce()
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self)")]
    pub fn verify(&self) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .verify()
            .map(|_| true)
            .map_err(|err| PyRuntimeError::new_err(err.to_string()))
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymodule]
#[pyo3(name = "llvm")]
pub fn llvm_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Lifter>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.lifters.llvm", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.lifters.llvm")?;
    Ok(())
}
