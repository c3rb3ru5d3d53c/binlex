use crate::irs::lir::LirModule as PyLirModule;
use crate::Configuration;
use binlex::io::Stderr;
use binlex::irs::vex::{
    VexBlock as InnerVexBlock, VexFunction as InnerVexFunction, VexModule as InnerVexModule,
    VexStatement as InnerVexStatement,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

#[pyclass(unsendable)]
pub struct VexModule {
    pub config: binlex::Configuration,
    pub inner: Arc<Mutex<InnerVexModule>>,
}

#[pyclass(unsendable)]
pub struct VexFunction {
    pub inner: Arc<Mutex<InnerVexFunction>>,
}

#[pyclass(unsendable)]
pub struct VexBlock {
    pub inner: Arc<Mutex<InnerVexBlock>>,
}

#[pyclass(unsendable)]
pub struct VexStatement {
    pub inner: Arc<Mutex<InnerVexStatement>>,
}

impl VexModule {
    pub(crate) fn from_inner(inner: InnerVexModule, config: binlex::Configuration) -> Self {
        Self {
            config,
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl VexFunction {
    fn from_inner(inner: InnerVexFunction) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl VexBlock {
    fn from_inner(inner: InnerVexBlock) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

impl VexStatement {
    fn from_inner(inner: InnerVexStatement) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl VexModule {
    #[new]
    #[pyo3(signature = (name=None), text_signature = "(name=None)")]
    pub fn new(name: Option<String>) -> Self {
        let inner_config = binlex::Configuration::default();
        let inner = InnerVexModule::new(name);
        Self {
            config: inner_config,
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    #[classmethod]
    #[pyo3(signature = (name, config), text_signature = "(name, config)")]
    pub fn with_config(
        _cls: &Bound<'_, pyo3::types::PyType>,
        py: Python<'_>,
        name: Option<String>,
        config: Py<Configuration>,
    ) -> Self {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerVexModule::with_config(name, inner_config.clone());
        Self {
            config: inner_config,
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name().map(str::to_string)
    }

    #[pyo3(signature = (module, config), text_signature = "($self, module, config)")]
    pub fn from_lir(
        &mut self,
        py: Python<'_>,
        module: Py<PyLirModule>,
        config: Py<Configuration>,
    ) -> PyResult<bool> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner_module = module.borrow(py).inner.lock().unwrap().clone();
        self.inner
            .lock()
            .unwrap()
            .from_lir(&inner_module, inner_config.clone())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.config = inner_config;
        Ok(true)
    }

    #[pyo3(text_signature = "($self)")]
    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn functions(&self, py: Python<'_>) -> PyResult<Vec<Py<VexFunction>>> {
        self.inner
            .lock()
            .unwrap()
            .functions()
            .iter()
            .cloned()
            .map(|function| Py::new(py, VexFunction::from_inner(function)))
            .collect()
    }

    pub fn append_function(&mut self, py: Python<'_>, function: Py<VexFunction>) {
        let function = function.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().append_function(function);
    }

    #[pyo3(text_signature = "($self)")]
    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    #[pyo3(text_signature = "($self)")]
    pub fn clear(&self) -> bool {
        match self.inner.lock().unwrap().clear() {
            Ok(()) => true,
            Err(err) => {
                Stderr::print_debug(&self.config, format!("vex clear failed: {}", err));
                false
            }
        }
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymethods]
impl VexFunction {
    #[new]
    #[pyo3(signature = (name=None), text_signature = "(name=None)")]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(InnerVexFunction::new(name))
    }

    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name().map(str::to_string)
    }

    pub fn blocks(&self, py: Python<'_>) -> PyResult<Vec<Py<VexBlock>>> {
        self.inner
            .lock()
            .unwrap()
            .blocks()
            .iter()
            .cloned()
            .map(|block| Py::new(py, VexBlock::from_inner(block)))
            .collect()
    }

    pub fn append_block(&mut self, py: Python<'_>, block: Py<VexBlock>) {
        let block = block.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().append_block(block);
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymethods]
impl VexBlock {
    #[new]
    #[pyo3(signature = (name=None), text_signature = "(name=None)")]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(InnerVexBlock::new(name))
    }

    pub fn name(&self) -> Option<String> {
        self.inner.lock().unwrap().name().map(str::to_string)
    }

    pub fn statements(&self, py: Python<'_>) -> PyResult<Vec<Py<VexStatement>>> {
        self.inner
            .lock()
            .unwrap()
            .statements()
            .iter()
            .cloned()
            .map(|statement| Py::new(py, VexStatement::from_inner(statement)))
            .collect()
    }

    pub fn append_statement(&mut self, py: Python<'_>, statement: Py<VexStatement>) {
        let statement = statement.borrow(py).inner.lock().unwrap().clone();
        self.inner.lock().unwrap().append_statement(statement);
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymethods]
impl VexStatement {
    #[new]
    #[pyo3(signature = (text), text_signature = "(text)")]
    pub fn new(text: String) -> Self {
        Self::from_inner(InnerVexStatement::new(text))
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text().to_string()
    }

    pub fn print(&self) {
        self.inner.lock().unwrap().print();
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymodule]
#[pyo3(name = "vex")]
pub fn vex_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VexModule>()?;
    m.add_class::<VexFunction>()?;
    m.add_class::<VexBlock>()?;
    m.add_class::<VexStatement>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.irs.vex", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.irs.vex")?;
    Ok(())
}
