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
    HirExpression, HirFunction, HirLocal, HirMlirModule, HirModule, HirParameter, HirPlace,
    HirStatement, HirTarget, HirValue,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes, PyModule, PyType};
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
value_wrapper!(PyHirPlace, "HirPlace", HirPlace);
value_wrapper!(PyHirTarget, "HirTarget", HirTarget);
value_wrapper!(PyHirStatement, "HirStatement", HirStatement);
value_wrapper!(PyHirBlock, "HirBlock", HirBlock);
value_wrapper!(PyHirParameter, "HirParameter", HirParameter);
value_wrapper!(PyHirLocal, "HirLocal", HirLocal);
value_wrapper!(PyHirFunction, "HirFunction", HirFunction);
value_wrapper!(PyHirModule, "HirModule", HirModule);

#[pyclass(name = "HirMlirModule", unsendable, skip_from_py_object)]
pub struct PyHirMlirModule {
    inner: HirMlirModule,
}

impl PyHirMlirModule {
    pub fn from_inner(inner: HirMlirModule) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyHirMlirModule {
    #[classmethod]
    pub fn from_text(_cls: &Bound<'_, PyType>, text: &str) -> PyResult<Self> {
        let inner = HirMlirModule::from_text(text)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn from_bytecode(
        _cls: &Bound<'_, PyType>,
        bytecode: &Bound<'_, PyBytes>,
    ) -> PyResult<Self> {
        let inner = HirMlirModule::from_bytecode(bytecode.as_bytes())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn optimize_assignments(&self) {
        self.inner.optimize_assignments();
    }

    pub fn optimize(&self) {
        self.inner.optimize();
    }

    pub fn text(&self) -> String {
        self.inner.text()
    }

    pub fn bytecode(&self, py: Python<'_>) -> Py<PyBytes> {
        PyBytes::new(py, &self.inner.bytecode()).unbind()
    }

    pub fn operation_names(&self) -> Vec<String> {
        self.inner.operation_names()
    }

    pub fn operation_count(&self) -> usize {
        self.inner.operation_count()
    }

    pub fn operation_records(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(self.inner.operation_records())
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        )
    }

    pub fn print(&self) {
        println!("{}", self.text());
    }
}

#[pymethods]
impl PyHirValue {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn named(
        _cls: &Bound<'_, PyType>,
        name: String,
        ty: PyRef<'_, crate::ir::mir::PyMirType>,
    ) -> Self {
        Self::from_inner(HirValue::Named {
            name,
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn integer(_cls: &Bound<'_, PyType>, value: i128, bits: u16) -> Self {
        Self::from_inner(HirValue::Integer { value, bits })
    }

    #[classmethod]
    pub fn boolean(_cls: &Bound<'_, PyType>, value: bool) -> Self {
        Self::from_inner(HirValue::Boolean(value))
    }

    #[classmethod]
    pub fn null(_cls: &Bound<'_, PyType>, ty: PyRef<'_, crate::ir::mir::PyMirType>) -> Self {
        Self::from_inner(HirValue::Null {
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn undef(_cls: &Bound<'_, PyType>, ty: PyRef<'_, crate::ir::mir::PyMirType>) -> Self {
        Self::from_inner(HirValue::Undef {
            ty: ty.inner.lock().unwrap().clone(),
        })
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
}

#[pymethods]
impl PyHirExpression {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn value(_cls: &Bound<'_, PyType>, value: PyRef<'_, PyHirValue>) -> Self {
        Self::from_inner(HirExpression::Value(value.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn call(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        target: PyRef<'_, PyHirTarget>,
        arguments: Option<Vec<Py<PyHirExpression>>>,
        return_types: Option<Vec<Py<crate::ir::mir::PyMirType>>>,
    ) -> Self {
        let arguments = arguments
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let return_types = return_types
            .unwrap_or_default()
            .into_iter()
            .map(|ty| ty.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(HirExpression::Call {
            target: target.inner.lock().unwrap().clone(),
            abi: None,
            arguments,
            return_types,
        })
    }

    #[classmethod]
    pub fn intrinsic(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        arguments: Option<Vec<Py<PyHirExpression>>>,
        return_types: Option<Vec<Py<crate::ir::mir::PyMirType>>>,
    ) -> Self {
        let arguments = arguments
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let return_types = return_types
            .unwrap_or_default()
            .into_iter()
            .map(|ty| ty.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(HirExpression::Intrinsic {
            name,
            arguments,
            return_types,
        })
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
}

#[pymethods]
impl PyHirPlace {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn named(
        _cls: &Bound<'_, PyType>,
        name: String,
        ty: PyRef<'_, crate::ir::mir::PyMirType>,
    ) -> Self {
        Self::from_inner(HirPlace::Named {
            name,
            ty: ty.inner.lock().unwrap().clone(),
        })
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
}

#[pymethods]
impl PyHirTarget {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn direct(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(HirTarget::Direct(name))
    }

    #[classmethod]
    pub fn indirect(_cls: &Bound<'_, PyType>, expression: PyRef<'_, PyHirExpression>) -> Self {
        Self::from_inner(HirTarget::Indirect(Box::new(
            expression.inner.lock().unwrap().clone(),
        )))
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
}

#[pymethods]
impl PyHirStatement {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[classmethod]
    pub fn assign(
        _cls: &Bound<'_, PyType>,
        target: PyRef<'_, PyHirPlace>,
        value: PyRef<'_, PyHirExpression>,
    ) -> Self {
        Self::from_inner(HirStatement::Assign {
            target: target.inner.lock().unwrap().clone(),
            value: value.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn expr(_cls: &Bound<'_, PyType>, value: PyRef<'_, PyHirExpression>) -> Self {
        Self::from_inner(HirStatement::Expr(value.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    #[pyo3(name = "return_")]
    pub fn return_values(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        values: Option<Vec<Py<PyHirExpression>>>,
    ) -> Self {
        let values = values
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(HirStatement::Return { values })
    }

    #[classmethod]
    pub fn label(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(HirStatement::Label(name))
    }

    #[classmethod]
    pub fn goto(_cls: &Bound<'_, PyType>, target: PyRef<'_, PyHirTarget>) -> Self {
        Self::from_inner(HirStatement::Goto(target.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    #[pyo3(name = "break_")]
    pub fn break_statement(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(HirStatement::Break)
    }

    #[classmethod]
    #[pyo3(name = "continue_")]
    pub fn continue_statement(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(HirStatement::Continue)
    }

    #[classmethod]
    pub fn trap(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(HirStatement::Trap)
    }

    #[classmethod]
    pub fn unreachable(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(HirStatement::Unreachable)
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
}

#[pymethods]
impl PyHirParameter {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[new]
    pub fn new(name: String, ty: PyRef<'_, crate::ir::mir::PyMirType>) -> Self {
        Self::from_inner(HirParameter {
            name,
            ty: ty.inner.lock().unwrap().clone(),
        })
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
}

#[pymethods]
impl PyHirLocal {
    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    #[new]
    #[pyo3(signature = (name, ty, init=None))]
    pub fn new(
        name: String,
        ty: PyRef<'_, crate::ir::mir::PyMirType>,
        init: Option<PyRef<'_, PyHirExpression>>,
    ) -> Self {
        Self::from_inner(HirLocal {
            name,
            ty: ty.inner.lock().unwrap().clone(),
            init: init.map(|value| value.inner.lock().unwrap().clone()),
            storage: None,
        })
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
}

#[pymethods]
impl PyHirBlock {
    #[new]
    pub fn new() -> Self {
        Self::from_inner(HirBlock::new())
    }

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

    pub fn append_statement(&mut self, statement: PyRef<'_, PyHirStatement>) {
        self.inner
            .lock()
            .unwrap()
            .append_statement(statement.inner.lock().unwrap().clone());
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

    pub fn append_parameter(&mut self, parameter: PyRef<'_, PyHirParameter>) {
        self.inner
            .lock()
            .unwrap()
            .parameters
            .push(parameter.inner.lock().unwrap().clone());
    }

    pub fn append_local(&mut self, local: PyRef<'_, PyHirLocal>) {
        self.inner
            .lock()
            .unwrap()
            .locals
            .push(local.inner.lock().unwrap().clone());
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

    pub fn ast(&self, py: Python<'_>) -> PyResult<Py<crate::ir::ast::PyAstFunction>> {
        let inner = self.inner.lock().unwrap().ast();
        Py::new(py, crate::ir::ast::PyAstFunction::from_inner(inner))
    }

    pub fn c(&self) -> String {
        self.inner.lock().unwrap().c()
    }

    pub fn print_c(&self) -> PyResult<()> {
        self.inner.lock().unwrap().print_c();
        Ok(())
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

    #[classmethod]
    pub fn from_text(_cls: &Bound<'_, PyType>, text: &str) -> PyResult<PyHirMlirModule> {
        let inner = HirModule::from_text(text)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(PyHirMlirModule::from_inner(inner))
    }

    #[classmethod]
    pub fn from_bytecode(
        _cls: &Bound<'_, PyType>,
        bytecode: &Bound<'_, PyBytes>,
    ) -> PyResult<PyHirMlirModule> {
        let inner = HirModule::from_bytecode(bytecode.as_bytes())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(PyHirMlirModule::from_inner(inner))
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

    pub fn ast(&self, py: Python<'_>) -> PyResult<Py<crate::ir::ast::PyAstModule>> {
        let inner = self.inner.lock().unwrap().ast();
        Py::new(py, crate::ir::ast::PyAstModule::from_inner(inner))
    }

    pub fn c(&self) -> String {
        self.inner.lock().unwrap().c()
    }

    pub fn print_c(&self) -> PyResult<()> {
        self.inner.lock().unwrap().print_c();
        Ok(())
    }

    pub fn text(&self) -> String {
        format_hir_module(&self.inner.lock().unwrap())
    }

    pub fn bytecode(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let bytecode = self
            .inner
            .lock()
            .unwrap()
            .bytecode()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(PyBytes::new(py, &bytecode).unbind())
    }

    pub fn mlir(&self) -> PyResult<PyHirMlirModule> {
        let module = self
            .inner
            .lock()
            .unwrap()
            .mlir()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(PyHirMlirModule::from_inner(module))
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
    m.add_class::<PyHirPlace>()?;
    m.add_class::<PyHirTarget>()?;
    m.add_class::<PyHirStatement>()?;
    m.add_class::<PyHirBlock>()?;
    m.add_class::<PyHirParameter>()?;
    m.add_class::<PyHirLocal>()?;
    m.add_class::<PyHirFunction>()?;
    m.add_class::<PyHirModule>()?;
    m.add_class::<PyHirMlirModule>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.ir.hir", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.ir.hir")?;
    Ok(())
}
