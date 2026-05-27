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

use binlex::ir::hir::{
    format_hir_function, format_hir_module, verify_hir_function, verify_hir_module, HirBlock,
    HirExpression, HirFunction, HirModule, HirStatement, HirValue,
};
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

fn extract_lir_function(
    py: Python<'_>,
    value: Py<PyAny>,
) -> PyResult<binlex::ir::lir::LirFunction> {
    let bound = value.bind(py);
    if let Ok(function) = bound.extract::<PyRef<'_, crate::ir::lir::LirFunction>>() {
        return Ok(function.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let function = inner.extract::<PyRef<'_, crate::ir::lir::LirFunction>>()?;
    let result = function.inner.lock().unwrap().clone();
    Ok(result)
}

fn extract_lir_module(py: Python<'_>, value: Py<PyAny>) -> PyResult<binlex::ir::lir::LirModule> {
    let bound = value.bind(py);
    if let Ok(module) = bound.extract::<PyRef<'_, crate::ir::lir::LirModule>>() {
        return Ok(module.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let module = inner.extract::<PyRef<'_, crate::ir::lir::LirModule>>()?;
    let result = module.inner.lock().unwrap().clone();
    Ok(result)
}

fn extract_mir_function(
    py: Python<'_>,
    value: Py<PyAny>,
) -> PyResult<binlex::ir::mir::MirFunction> {
    let bound = value.bind(py);
    if let Ok(function) = bound.extract::<PyRef<'_, crate::ir::mir::PyMirFunction>>() {
        return Ok(function.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let function = inner.extract::<PyRef<'_, crate::ir::mir::PyMirFunction>>()?;
    let result = function.inner.lock().unwrap().clone();
    Ok(result)
}

fn extract_mir_module(py: Python<'_>, value: Py<PyAny>) -> PyResult<binlex::ir::mir::MirModule> {
    let bound = value.bind(py);
    if let Ok(module) = bound.extract::<PyRef<'_, crate::ir::mir::PyMirModule>>() {
        return Ok(module.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let module = inner.extract::<PyRef<'_, crate::ir::mir::PyMirModule>>()?;
    let result = module.inner.lock().unwrap().clone();
    Ok(result)
}

macro_rules! value_wrapper {
    ($name:ident, $py_name:literal, $inner:ty) => {
        #[pyclass(name = $py_name, skip_from_py_object)]
        #[derive(Clone)]
        pub struct $name {
            pub inner: Arc<Mutex<$inner>>,
        }

        impl $name {
            pub fn from_inner(inner: $inner) -> Self {
                Self {
                    inner: Arc::new(Mutex::new(inner)),
                }
            }
        }
    };
}

value_wrapper!(PyHirValue, "HirValue", HirValue);
value_wrapper!(PyHirExpression, "HirExpression", HirExpression);
value_wrapper!(PyHirStatement, "HirStatement", HirStatement);
value_wrapper!(PyHirBlock, "HirBlock", HirBlock);
value_wrapper!(PyHirFunction, "HirFunction", HirFunction);
value_wrapper!(PyHirModule, "HirModule", HirModule);

macro_rules! dict_methods {
    ($name:ident) => {
        #[pymethods]
        impl $name {
            #[classmethod]
            pub fn from_dict(
                _cls: &Bound<'_, PyType>,
                py: Python<'_>,
                data: Py<PyAny>,
            ) -> PyResult<Self> {
                let value = py_to_json_value(py, data)?;
                let inner = serde_json::from_value(value)
                    .map_err(|error| PyValueError::new_err(error.to_string()))?;
                Ok(Self::from_inner(inner))
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

            pub fn __str__(&self) -> PyResult<String> {
                self.json()
            }
        }
    };
}

dict_methods!(PyHirValue);
dict_methods!(PyHirExpression);
dict_methods!(PyHirStatement);

#[pymethods]
impl PyHirBlock {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn statements(&self, py: Python<'_>) -> PyResult<Vec<Py<PyHirStatement>>> {
        self.inner
            .lock()
            .unwrap()
            .statements
            .iter()
            .cloned()
            .map(|statement| Py::new(py, PyHirStatement::from_inner(statement)))
            .collect()
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

    pub fn __str__(&self) -> PyResult<String> {
        self.json()
    }
}

#[pymethods]
impl PyHirFunction {
    #[new]
    #[pyo3(signature = (name=None))]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(HirFunction::new(name))
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    #[pyo3(signature = (mir_function, name=None))]
    pub fn from_mir(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        mir_function: Py<PyAny>,
        name: Option<String>,
    ) -> PyResult<Self> {
        let mir = extract_mir_function(py, mir_function)?;
        let hir = HirFunction::from_mir(name, &mir)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(hir))
    }

    #[classmethod]
    #[pyo3(signature = (lir_function, name=None))]
    pub fn from_lir(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        lir_function: Py<PyAny>,
        name: Option<String>,
    ) -> PyResult<Self> {
        let lir = extract_lir_function(py, lir_function)?;
        let hir = HirFunction::from_lir(name, &lir)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(hir))
    }

    pub fn append_block(&mut self, block: PyRef<'_, PyHirBlock>) {
        self.inner
            .lock()
            .unwrap()
            .append_block(block.inner.lock().unwrap().clone());
    }

    pub fn blocks(&self, py: Python<'_>) -> PyResult<Vec<Py<PyHirBlock>>> {
        self.inner
            .lock()
            .unwrap()
            .blocks()
            .iter()
            .cloned()
            .map(|block| Py::new(py, PyHirBlock::from_inner(block)))
            .collect()
    }

    pub fn verify(&self) -> PyResult<()> {
        verify_hir_function(&self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn optimize_inline_temps(&mut self) {
        self.inner.lock().unwrap().optimize_inline_temps();
    }

    pub fn optimize_algebraic(&mut self) {
        self.inner.lock().unwrap().optimize_algebraic();
    }

    pub fn optimize_condition_idioms(&mut self) {
        self.inner.lock().unwrap().optimize_condition_idioms();
    }

    pub fn optimize_boolean(&mut self) {
        self.inner.lock().unwrap().optimize_boolean();
    }

    pub fn optimize_load_hoisting(&mut self) {
        self.inner.lock().unwrap().optimize_load_hoisting();
    }

    pub fn optimize_call_arguments(&mut self) {
        self.inner.lock().unwrap().optimize_call_arguments();
    }

    pub fn optimize_memory_forms(&mut self) {
        self.inner.lock().unwrap().optimize_memory_forms();
    }

    pub fn optimize_pointer_reads(&mut self) {
        self.inner.lock().unwrap().optimize_pointer_reads();
    }

    pub fn optimize_cfg(&mut self) {
        self.inner.lock().unwrap().optimize_cfg();
    }

    pub fn optimize_locals(&mut self) {
        self.inner.lock().unwrap().optimize_locals();
    }

    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn text(&self) -> String {
        format_hir_function(&self.inner.lock().unwrap())
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
impl PyHirModule {
    #[new]
    #[pyo3(signature = (name=None))]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(HirModule::new(name))
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    #[pyo3(signature = (mir_module, name=None))]
    pub fn from_mir(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        mir_module: Py<PyAny>,
        name: Option<String>,
    ) -> PyResult<Self> {
        let mir = extract_mir_module(py, mir_module)?;
        let hir = HirModule::from_mir(name, &mir)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(hir))
    }

    #[classmethod]
    #[pyo3(signature = (lir_module, name=None))]
    pub fn from_lir(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        lir_module: Py<PyAny>,
        name: Option<String>,
    ) -> PyResult<Self> {
        let lir = extract_lir_module(py, lir_module)?;
        let hir = HirModule::from_lir(name, &lir)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(hir))
    }

    pub fn append_function(&mut self, function: PyRef<'_, PyHirFunction>) {
        self.inner
            .lock()
            .unwrap()
            .append_function(function.inner.lock().unwrap().clone());
    }

    pub fn functions(&self, py: Python<'_>) -> PyResult<Vec<Py<PyHirFunction>>> {
        self.inner
            .lock()
            .unwrap()
            .functions()
            .iter()
            .cloned()
            .map(|function| Py::new(py, PyHirFunction::from_inner(function)))
            .collect()
    }

    pub fn verify(&self) -> PyResult<()> {
        verify_hir_module(&self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn optimize_inline_temps(&mut self) {
        self.inner.lock().unwrap().optimize_inline_temps();
    }

    pub fn optimize_algebraic(&mut self) {
        self.inner.lock().unwrap().optimize_algebraic();
    }

    pub fn optimize_condition_idioms(&mut self) {
        self.inner.lock().unwrap().optimize_condition_idioms();
    }

    pub fn optimize_boolean(&mut self) {
        self.inner.lock().unwrap().optimize_boolean();
    }

    pub fn optimize_load_hoisting(&mut self) {
        self.inner.lock().unwrap().optimize_load_hoisting();
    }

    pub fn optimize_call_arguments(&mut self) {
        self.inner.lock().unwrap().optimize_call_arguments();
    }

    pub fn optimize_memory_forms(&mut self) {
        self.inner.lock().unwrap().optimize_memory_forms();
    }

    pub fn optimize_pointer_reads(&mut self) {
        self.inner.lock().unwrap().optimize_pointer_reads();
    }

    pub fn optimize_cfg(&mut self) {
        self.inner.lock().unwrap().optimize_cfg();
    }

    pub fn optimize_locals(&mut self) {
        self.inner.lock().unwrap().optimize_locals();
    }

    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn text(&self) -> String {
        format_hir_module(&self.inner.lock().unwrap())
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
#[pyo3(name = "hir")]
pub fn hir_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHirValue>()?;
    m.add_class::<PyHirExpression>()?;
    m.add_class::<PyHirStatement>()?;
    m.add_class::<PyHirBlock>()?;
    m.add_class::<PyHirFunction>()?;
    m.add_class::<PyHirModule>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.ir.hir", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.ir.hir")?;
    Ok(())
}
