use crate::formats::Image;
use binlex::ir::ast::{AstFunction, AstModule};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyModule, PyType};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

fn json_value_to_py(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let json_str =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    let json_module = py.import("json")?;
    Ok(json_module.call_method1("loads", (json_str,))?.into())
}

fn py_to_json_value(py: Python<'_>, value: Py<PyAny>) -> PyResult<serde_json::Value> {
    let json_module = py.import("json")?;
    let json_str = json_module
        .call_method1("dumps", (value,))?
        .extract::<String>()?;
    serde_json::from_str(&json_str).map_err(|error| PyValueError::new_err(error.to_string()))
}

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

fn extract_hir_function(
    py: Python<'_>,
    value: Py<PyAny>,
) -> PyResult<binlex::ir::hir::HirFunction> {
    let bound = value.bind(py);
    if let Ok(function) = bound.extract::<PyRef<'_, crate::ir::hir::PyHirFunction>>() {
        return Ok(function.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let function = inner.extract::<PyRef<'_, crate::ir::hir::PyHirFunction>>()?;
    let result = function.inner.lock().unwrap().clone();
    Ok(result)
}

fn extract_hir_module(py: Python<'_>, value: Py<PyAny>) -> PyResult<binlex::ir::hir::HirModule> {
    let bound = value.bind(py);
    if let Ok(module) = bound.extract::<PyRef<'_, crate::ir::hir::PyHirModule>>() {
        return Ok(module.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let module = inner.extract::<PyRef<'_, crate::ir::hir::PyHirModule>>()?;
    let result = module.inner.lock().unwrap().clone();
    Ok(result)
}

#[pyclass(name = "AstFunction", skip_from_py_object)]
#[derive(Clone)]
pub struct PyAstFunction {
    pub inner: Arc<Mutex<AstFunction>>,
}

impl PyAstFunction {
    pub fn from_inner(inner: AstFunction) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pyclass(name = "AstModule", skip_from_py_object)]
#[derive(Clone)]
pub struct PyAstModule {
    pub inner: Arc<Mutex<AstModule>>,
}

impl PyAstModule {
    pub fn from_inner(inner: AstModule) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}

#[pymethods]
impl PyAstFunction {
    #[new]
    pub fn new() -> Self {
        Self::from_inner(AstFunction::default())
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn from_hir(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        hir_function: Py<PyAny>,
    ) -> PyResult<Self> {
        let hir = extract_hir_function(py, hir_function)?;
        Ok(Self::from_inner(AstFunction::from_hir(&hir)))
    }

    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn c(&self) -> String {
        self.inner.lock().unwrap().c()
    }

    pub fn c_with_image(&self, py: Python<'_>, image: Py<Image>) -> String {
        let image = image.borrow(py);
        self.inner.lock().unwrap().c_with_image(&image.inner)
    }

    pub fn print_c(&self) -> PyResult<()> {
        self.inner.lock().unwrap().print_c();
        Ok(())
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn print(&self) -> PyResult<()> {
        self.inner.lock().unwrap().print();
        Ok(())
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        )
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&*self.inner.lock().unwrap())
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymethods]
impl PyAstModule {
    #[new]
    pub fn new() -> Self {
        Self::from_inner(AstModule::default())
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn from_hir(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        hir_module: Py<PyAny>,
    ) -> PyResult<Self> {
        let hir = extract_hir_module(py, hir_module)?;
        Ok(Self::from_inner(AstModule::from_hir(&hir)))
    }

    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn c(&self) -> String {
        self.inner.lock().unwrap().c()
    }

    pub fn print_c(&self) -> PyResult<()> {
        self.inner.lock().unwrap().print_c();
        Ok(())
    }

    pub fn text(&self) -> String {
        self.inner.lock().unwrap().text()
    }

    pub fn print(&self) -> PyResult<()> {
        self.inner.lock().unwrap().print();
        Ok(())
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        )
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&*self.inner.lock().unwrap())
    }

    pub fn __str__(&self) -> String {
        self.text()
    }
}

#[pymodule]
#[pyo3(name = "ast")]
pub fn ast_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyAstFunction>()?;
    m.add_class::<PyAstModule>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.ir.ast", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.ir.ast")?;
    Ok(())
}
