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

use binlex::ir::mir::{
    format_mir_function, format_mir_module, verify_mir_function, verify_mir_module,
    MirAddressSpace, MirBlock, MirBlockParameter, MirCastOperation, MirCompareOperation,
    MirControlTarget, MirFunction, MirModule, MirOperation, MirOperationKind, MirTerminator,
    MirTerminatorKind, MirType, MirTypeKind, MirValue,
};
use pyo3::class::basic::CompareOp;
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

fn extract_lir_block(py: Python<'_>, value: Py<PyAny>) -> PyResult<binlex::ir::lir::LirBlock> {
    let bound = value.bind(py);
    if let Ok(block) = bound.extract::<PyRef<'_, crate::ir::lir::LirBlock>>() {
        return Ok(block.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let block = inner.extract::<PyRef<'_, crate::ir::lir::LirBlock>>()?;
    let result = block.inner.lock().unwrap().clone();
    Ok(result)
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

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

macro_rules! simple_enum_binding {
    ($name:ident, $py_name:literal, $inner:ty, { $($variant:ident),+ $(,)? }) => {
        #[pyclass(name = $py_name, skip_from_py_object)]
        #[derive(Clone)]
        pub struct $name {
            pub inner: $inner,
        }

        impl $name {
            pub fn from_inner(inner: $inner) -> Self {
                Self { inner }
            }
        }

        #[pymethods]
        impl $name {
            $(
                #[allow(non_upper_case_globals)]
                #[classattr]
                pub const $variant: Self = Self { inner: <$inner>::$variant };
            )+

            pub fn __str__(&self) -> String {
                format!("{:?}", self.inner)
            }
        }
    };
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

simple_enum_binding!(MirCompareOp, "MirCompareOp", MirCompareOperation, {
    Eq, Ne, Ult, Ule, Ugt, Uge, Slt, Sle, Sgt, Sge
});
simple_enum_binding!(MirCastOp, "MirCastOp", MirCastOperation, {
    ZeroExtend, SignExtend, Truncate, Bitcast, IntToFloat, UIntToFloat, FloatToInt, FloatToUInt,
    FloatExtend, FloatTruncate
});
simple_enum_binding!(MirTypeKindPy, "MirTypeKind", MirTypeKind, {
    Void, Integer, Float, Pointer, Memory, Custom
});
simple_enum_binding!(MirTerminatorKindPy, "MirTerminatorKind", MirTerminatorKind, {
    Jump, CondBr, Return, Trap, Unreachable
});

value_wrapper!(PyMirType, "MirType", MirType);
value_wrapper!(PyMirValue, "MirValue", MirValue);
value_wrapper!(PyMirAddressSpace, "MirAddressSpace", MirAddressSpace);
value_wrapper!(PyMirBlockParameter, "MirBlockParameter", MirBlockParameter);
value_wrapper!(PyMirOperation, "MirOperation", MirOperation);
value_wrapper!(PyMirTerminator, "MirTerminator", MirTerminator);
value_wrapper!(PyMirBlock, "MirBlock", MirBlock);
value_wrapper!(PyMirFunction, "MirFunction", MirFunction);
value_wrapper!(PyMirModule, "MirModule", MirModule);

impl PyMirBlock {
    fn value_eq(&self, other: &Self) -> bool {
        *self.inner.lock().unwrap() == *other.inner.lock().unwrap()
    }

    fn value_hash(&self) -> isize {
        hash_value(&*self.inner.lock().unwrap())
    }
}

#[pymethods]
impl PyMirType {
    #[classmethod]
    pub fn void(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirType::void())
    }

    #[classmethod]
    pub fn integer(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(MirType::integer(bits))
    }

    #[classmethod]
    pub fn float(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(MirType::float(bits))
    }

    #[classmethod]
    pub fn pointer(_cls: &Bound<'_, PyType>, pointee: PyRef<'_, PyMirType>) -> Self {
        Self::from_inner(MirType::pointer(pointee.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn memory(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirType::memory())
    }

    #[classmethod]
    pub fn custom(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirType::custom(name))
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        )
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn kind(&self) -> MirTypeKindPy {
        MirTypeKindPy::from_inner(self.inner.lock().unwrap().kind())
    }
}

#[pymethods]
impl PyMirValue {
    #[classmethod]
    pub fn named(_cls: &Bound<'_, PyType>, name: String, ty: PyRef<'_, PyMirType>) -> Self {
        Self::from_inner(MirValue::named(name, ty.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn integer(_cls: &Bound<'_, PyType>, value: i128, bits: u16) -> Self {
        Self::from_inner(MirValue::integer(value, bits))
    }

    #[classmethod]
    pub fn boolean(_cls: &Bound<'_, PyType>, value: bool) -> Self {
        Self::from_inner(MirValue::boolean(value))
    }

    #[classmethod]
    pub fn null(_cls: &Bound<'_, PyType>, ty: PyRef<'_, PyMirType>) -> Self {
        Self::from_inner(MirValue::null(ty.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn undef(_cls: &Bound<'_, PyType>, ty: PyRef<'_, PyMirType>) -> Self {
        Self::from_inner(MirValue::undef(ty.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        json_value_to_py(
            py,
            &serde_json::to_value(&*self.inner.lock().unwrap())
                .map_err(|error| PyRuntimeError::new_err(error.to_string()))?,
        )
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }
}

#[pymethods]
impl PyMirAddressSpace {
    #[classmethod]
    pub fn default_space(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirAddressSpace::default_space())
    }

    #[classmethod]
    pub fn stack(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirAddressSpace::stack())
    }

    #[classmethod]
    pub fn heap(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirAddressSpace::heap())
    }

    #[classmethod]
    #[pyo3(name = "global_space")]
    pub fn global_space(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirAddressSpace::global())
    }

    #[classmethod]
    pub fn heap_object(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::heap_object(name))
    }

    #[classmethod]
    pub fn global_object(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::global_object(name))
    }

    #[classmethod]
    pub fn io(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirAddressSpace::io())
    }

    #[classmethod]
    pub fn local(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::local(name))
    }

    #[classmethod]
    pub fn argument(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::argument(name))
    }

    #[classmethod]
    pub fn spill(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::spill(name))
    }

    #[classmethod]
    pub fn incoming(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::incoming(name))
    }

    #[classmethod]
    pub fn saved_frame(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::saved_frame(name))
    }

    #[classmethod]
    pub fn return_address(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::return_address(name))
    }

    #[classmethod]
    pub fn named(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(MirAddressSpace::named(name))
    }
}

#[pymethods]
impl PyMirBlockParameter {
    #[new]
    #[pyo3(signature = (ty, name=None))]
    pub fn new(ty: PyRef<'_, PyMirType>, name: Option<String>) -> Self {
        Self::from_inner(MirBlockParameter::new(
            name,
            ty.inner.lock().unwrap().clone(),
        ))
    }
}

#[pymethods]
impl PyMirOperation {
    #[classmethod]
    #[pyo3(signature = (lhs, rhs, ty, result=None))]
    pub fn add(
        _cls: &Bound<'_, PyType>,
        lhs: PyRef<'_, PyMirValue>,
        rhs: PyRef<'_, PyMirValue>,
        ty: PyRef<'_, PyMirType>,
        result: Option<String>,
    ) -> Self {
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Add {
                lhs: lhs.inner.lock().unwrap().clone(),
                rhs: rhs.inner.lock().unwrap().clone(),
                ty: ty.inner.lock().unwrap().clone(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (lhs, rhs, ty, result=None))]
    pub fn sub(
        _cls: &Bound<'_, PyType>,
        lhs: PyRef<'_, PyMirValue>,
        rhs: PyRef<'_, PyMirValue>,
        ty: PyRef<'_, PyMirType>,
        result: Option<String>,
    ) -> Self {
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Sub {
                lhs: lhs.inner.lock().unwrap().clone(),
                rhs: rhs.inner.lock().unwrap().clone(),
                ty: ty.inner.lock().unwrap().clone(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (lhs, rhs, ty, result=None))]
    pub fn mul(
        _cls: &Bound<'_, PyType>,
        lhs: PyRef<'_, PyMirValue>,
        rhs: PyRef<'_, PyMirValue>,
        ty: PyRef<'_, PyMirType>,
        result: Option<String>,
    ) -> Self {
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Mul {
                lhs: lhs.inner.lock().unwrap().clone(),
                rhs: rhs.inner.lock().unwrap().clone(),
                ty: ty.inner.lock().unwrap().clone(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (address_space, address, ty, result=None))]
    pub fn load(
        _cls: &Bound<'_, PyType>,
        address_space: PyRef<'_, PyMirAddressSpace>,
        address: PyRef<'_, PyMirValue>,
        ty: PyRef<'_, PyMirType>,
        result: Option<String>,
    ) -> Self {
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Load {
                address_space: address_space.inner.lock().unwrap().clone(),
                address: address.inner.lock().unwrap().clone(),
                ty: ty.inner.lock().unwrap().clone(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (address_space, address, value, ty, result=None))]
    pub fn store(
        _cls: &Bound<'_, PyType>,
        address_space: PyRef<'_, PyMirAddressSpace>,
        address: PyRef<'_, PyMirValue>,
        value: PyRef<'_, PyMirValue>,
        ty: PyRef<'_, PyMirType>,
        result: Option<String>,
    ) -> Self {
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Store {
                address_space: address_space.inner.lock().unwrap().clone(),
                address: address.inner.lock().unwrap().clone(),
                value: value.inner.lock().unwrap().clone(),
                ty: ty.inner.lock().unwrap().clone(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (op, lhs, rhs, ty, result=None))]
    pub fn icmp(
        _cls: &Bound<'_, PyType>,
        op: PyRef<'_, MirCompareOp>,
        lhs: PyRef<'_, PyMirValue>,
        rhs: PyRef<'_, PyMirValue>,
        ty: PyRef<'_, PyMirType>,
        result: Option<String>,
    ) -> Self {
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Icmp {
                op: op.inner.clone(),
                lhs: lhs.inner.lock().unwrap().clone(),
                rhs: rhs.inner.lock().unwrap().clone(),
                ty: ty.inner.lock().unwrap().clone(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (op, value, ty, result=None))]
    pub fn cast(
        _cls: &Bound<'_, PyType>,
        op: PyRef<'_, MirCastOp>,
        value: PyRef<'_, PyMirValue>,
        ty: PyRef<'_, PyMirType>,
        result: Option<String>,
    ) -> Self {
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Cast {
                op: op.inner.clone(),
                value: value.inner.lock().unwrap().clone(),
                ty: ty.inner.lock().unwrap().clone(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (target, arguments=None, result_types=None, result=None))]
    pub fn call(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        target: String,
        arguments: Option<Vec<Py<PyMirValue>>>,
        result_types: Option<Vec<Py<PyMirType>>>,
        result: Option<String>,
    ) -> Self {
        let arguments = arguments
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let result_types = result_types
            .unwrap_or_default()
            .into_iter()
            .map(|ty| ty.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Call {
                target: MirControlTarget::direct(target),
                arguments,
                result_types,
                clobbers: Vec::new(),
                memory_effects: Vec::new(),
            },
        ))
    }

    #[classmethod]
    #[pyo3(signature = (name, arguments=None, result_types=None, result=None))]
    pub fn intrinsic(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        arguments: Option<Vec<Py<PyMirValue>>>,
        result_types: Option<Vec<Py<PyMirType>>>,
        result: Option<String>,
    ) -> Self {
        let arguments = arguments
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let result_types = result_types
            .unwrap_or_default()
            .into_iter()
            .map(|ty| ty.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(MirOperation::new(
            result,
            MirOperationKind::Intrinsic {
                name,
                arguments,
                result_types,
            },
        ))
    }
}

#[pymethods]
impl PyMirTerminator {
    #[classmethod]
    #[pyo3(signature = (target, arguments=None))]
    pub fn jump(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        target: String,
        arguments: Option<Vec<Py<PyMirValue>>>,
    ) -> Self {
        let arguments = arguments
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(MirTerminator::Jump {
            target: MirControlTarget::direct(target),
            arguments,
        })
    }

    #[classmethod]
    #[pyo3(signature = (condition, then_target, else_target, then_arguments=None, else_arguments=None))]
    pub fn cond_br(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        condition: PyRef<'_, PyMirValue>,
        then_target: String,
        else_target: String,
        then_arguments: Option<Vec<Py<PyMirValue>>>,
        else_arguments: Option<Vec<Py<PyMirValue>>>,
    ) -> Self {
        let then_arguments = then_arguments
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let else_arguments = else_arguments
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(MirTerminator::CondBr {
            condition: condition.inner.lock().unwrap().clone(),
            then_target: MirControlTarget::direct(then_target),
            then_arguments,
            else_target: MirControlTarget::direct(else_target),
            else_arguments,
        })
    }

    #[classmethod]
    #[pyo3(signature = (values=None))]
    pub fn return_(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        values: Option<Vec<Py<PyMirValue>>>,
    ) -> Self {
        let values = values
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(MirTerminator::Return { values })
    }

    #[classmethod]
    pub fn trap(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirTerminator::Trap)
    }

    #[classmethod]
    pub fn unreachable(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(MirTerminator::Unreachable)
    }

    pub fn kind(&self) -> MirTerminatorKindPy {
        MirTerminatorKindPy::from_inner(self.inner.lock().unwrap().kind())
    }
}

#[pymethods]
impl PyMirBlock {
    #[new]
    pub fn new(name: String) -> Self {
        Self::from_inner(MirBlock::new(name))
    }

    #[classmethod]
    #[pyo3(signature = (lir_block, name=None))]
    pub fn from_lir(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        lir_block: Py<PyAny>,
        name: Option<String>,
    ) -> PyResult<Self> {
        let lir = extract_lir_block(py, lir_block)?;
        let mir = MirBlock::from_lir(name, &lir)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(mir))
    }

    pub fn append_parameter(&mut self, parameter: PyRef<'_, PyMirBlockParameter>) {
        self.inner
            .lock()
            .unwrap()
            .append_parameter(parameter.inner.lock().unwrap().clone());
    }

    pub fn append_operation(&mut self, operation: PyRef<'_, PyMirOperation>) {
        self.inner
            .lock()
            .unwrap()
            .append_operation(operation.inner.lock().unwrap().clone());
    }

    pub fn set_terminator(&mut self, terminator: PyRef<'_, PyMirTerminator>) {
        self.inner
            .lock()
            .unwrap()
            .set_terminator(terminator.inner.lock().unwrap().clone());
    }

    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name.clone()
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&*self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn __hash__(&self) -> isize {
        self.value_hash()
    }

    pub fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.value_eq(&other),
            CompareOp::Ne => !self.value_eq(&other),
            _ => false,
        }
    }
}

#[pymethods]
impl PyMirFunction {
    #[new]
    #[pyo3(signature = (name=None))]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(MirFunction::new(name))
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
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
        let mir = MirFunction::from_lir(name, &lir)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(mir))
    }

    pub fn append_block(&mut self, block: PyRef<'_, PyMirBlock>) {
        self.inner
            .lock()
            .unwrap()
            .append_block(block.inner.lock().unwrap().clone());
    }

    pub fn blocks(&self, py: Python<'_>) -> PyResult<Vec<Py<PyMirBlock>>> {
        self.inner
            .lock()
            .unwrap()
            .blocks()
            .iter()
            .cloned()
            .map(|block| Py::new(py, PyMirBlock::from_inner(block)))
            .collect()
    }

    pub fn verify(&self) -> PyResult<()> {
        verify_mir_function(&self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn optimize_register_state(&mut self) {
        self.inner.lock().unwrap().optimize_register_state();
    }

    pub fn optimize_returns(&mut self) {
        self.inner.lock().unwrap().optimize_returns();
    }

    pub fn optimize_blocks(&mut self) {
        self.inner.lock().unwrap().optimize_blocks();
    }

    pub fn optimize_abi(&mut self) {
        self.inner.lock().unwrap().optimize_abi();
    }

    pub fn optimize_subexpressions(&mut self) {
        self.inner.lock().unwrap().optimize_subexpressions();
    }

    pub fn optimize_flags(&mut self) {
        self.inner.lock().unwrap().optimize_flags();
    }

    pub fn optimize_liveness(&mut self) {
        self.inner.lock().unwrap().optimize_liveness();
    }

    pub fn optimize_undefs(&mut self) {
        self.inner.lock().unwrap().optimize_undefs();
    }

    pub fn optimize_intrinsics(&mut self) {
        self.inner.lock().unwrap().optimize_intrinsics();
    }

    pub fn optimize_cse(&mut self) {
        self.inner.lock().unwrap().optimize_cse();
    }

    pub fn optimize_stack(&mut self) {
        self.inner.lock().unwrap().optimize_stack();
    }

    pub fn optimize_stack_pointers(&mut self) {
        self.inner.lock().unwrap().optimize_stack_pointers();
    }

    pub fn optimize_stack_slots(&mut self) {
        self.inner.lock().unwrap().optimize_stack_slots();
    }

    pub fn optimize_calls(&mut self) {
        self.inner.lock().unwrap().optimize_calls();
    }

    pub fn optimize_call_clobbers(&mut self) {
        self.inner.lock().unwrap().optimize_call_clobbers();
    }

    pub fn optimize_memory_aliases(&mut self) {
        self.inner.lock().unwrap().optimize_memory_aliases();
    }

    pub fn optimize_branches(&mut self) {
        self.inner.lock().unwrap().optimize_branches();
    }

    pub fn optimize_memory_state(&mut self) {
        self.inner.lock().unwrap().optimize_memory_state();
    }

    pub fn optimize_constants(&mut self) {
        self.inner.lock().unwrap().optimize_constants();
    }

    pub fn optimize_dead_effects(&mut self) {
        self.inner.lock().unwrap().optimize_dead_effects();
    }

    pub fn optimize_copy_propagation(&mut self) {
        self.inner.lock().unwrap().optimize_copy_propagation();
    }

    pub fn optimize_targets(&mut self) {
        self.inner.lock().unwrap().optimize_targets();
    }

    pub fn optimize_ssa(&mut self) {
        self.inner.lock().unwrap().optimize_ssa();
    }

    pub fn optimize_ssa_liveness(&mut self) {
        self.inner.lock().unwrap().optimize_ssa_liveness();
    }

    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn text(&self) -> String {
        format_mir_function(&self.inner.lock().unwrap())
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
impl PyMirModule {
    #[new]
    #[pyo3(signature = (name=None))]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(MirModule::new(name))
    }

    #[classmethod]
    pub fn from_dict(_cls: &Bound<'_, PyType>, py: Python<'_>, data: Py<PyAny>) -> PyResult<Self> {
        let value = py_to_json_value(py, data)?;
        let inner = serde_json::from_value(value)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self::from_inner(inner))
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
        let mir = MirModule::from_lir(name, &lir)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self::from_inner(mir))
    }

    pub fn append_function(&mut self, function: PyRef<'_, PyMirFunction>) {
        self.inner
            .lock()
            .unwrap()
            .append_function(function.inner.lock().unwrap().clone());
    }

    pub fn functions(&self, py: Python<'_>) -> PyResult<Vec<Py<PyMirFunction>>> {
        self.inner
            .lock()
            .unwrap()
            .functions()
            .iter()
            .cloned()
            .map(|function| Py::new(py, PyMirFunction::from_inner(function)))
            .collect()
    }

    pub fn verify(&self) -> PyResult<()> {
        verify_mir_module(&self.inner.lock().unwrap())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn optimize_register_state(&mut self) {
        self.inner.lock().unwrap().optimize_register_state();
    }

    pub fn optimize_returns(&mut self) {
        self.inner.lock().unwrap().optimize_returns();
    }

    pub fn optimize_blocks(&mut self) {
        self.inner.lock().unwrap().optimize_blocks();
    }

    pub fn optimize_abi(&mut self) {
        self.inner.lock().unwrap().optimize_abi();
    }

    pub fn optimize_subexpressions(&mut self) {
        self.inner.lock().unwrap().optimize_subexpressions();
    }

    pub fn optimize_flags(&mut self) {
        self.inner.lock().unwrap().optimize_flags();
    }

    pub fn optimize_liveness(&mut self) {
        self.inner.lock().unwrap().optimize_liveness();
    }

    pub fn optimize_undefs(&mut self) {
        self.inner.lock().unwrap().optimize_undefs();
    }

    pub fn optimize_intrinsics(&mut self) {
        self.inner.lock().unwrap().optimize_intrinsics();
    }

    pub fn optimize_cse(&mut self) {
        self.inner.lock().unwrap().optimize_cse();
    }

    pub fn optimize_stack(&mut self) {
        self.inner.lock().unwrap().optimize_stack();
    }

    pub fn optimize_stack_pointers(&mut self) {
        self.inner.lock().unwrap().optimize_stack_pointers();
    }

    pub fn optimize_stack_slots(&mut self) {
        self.inner.lock().unwrap().optimize_stack_slots();
    }

    pub fn optimize_calls(&mut self) {
        self.inner.lock().unwrap().optimize_calls();
    }

    pub fn optimize_call_clobbers(&mut self) {
        self.inner.lock().unwrap().optimize_call_clobbers();
    }

    pub fn optimize_memory_aliases(&mut self) {
        self.inner.lock().unwrap().optimize_memory_aliases();
    }

    pub fn optimize_branches(&mut self) {
        self.inner.lock().unwrap().optimize_branches();
    }

    pub fn optimize_memory_state(&mut self) {
        self.inner.lock().unwrap().optimize_memory_state();
    }

    pub fn optimize_constants(&mut self) {
        self.inner.lock().unwrap().optimize_constants();
    }

    pub fn optimize_dead_effects(&mut self) {
        self.inner.lock().unwrap().optimize_dead_effects();
    }

    pub fn optimize_copy_propagation(&mut self) {
        self.inner.lock().unwrap().optimize_copy_propagation();
    }

    pub fn optimize_targets(&mut self) {
        self.inner.lock().unwrap().optimize_targets();
    }

    pub fn optimize_ssa(&mut self) {
        self.inner.lock().unwrap().optimize_ssa();
    }

    pub fn optimize_ssa_liveness(&mut self) {
        self.inner.lock().unwrap().optimize_ssa_liveness();
    }

    pub fn optimize(&mut self) {
        self.inner.lock().unwrap().optimize();
    }

    pub fn text(&self) -> String {
        format_mir_module(&self.inner.lock().unwrap())
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

#[pymodule(name = "mir")]
pub fn mir_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<MirCompareOp>()?;
    m.add_class::<MirCastOp>()?;
    m.add_class::<MirTypeKindPy>()?;
    m.add_class::<MirTerminatorKindPy>()?;
    m.add_class::<PyMirType>()?;
    m.add_class::<PyMirValue>()?;
    m.add_class::<PyMirAddressSpace>()?;
    m.add_class::<PyMirBlockParameter>()?;
    m.add_class::<PyMirOperation>()?;
    m.add_class::<PyMirTerminator>()?;
    m.add_class::<PyMirBlock>()?;
    m.add_class::<PyMirFunction>()?;
    m.add_class::<PyMirModule>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.ir.mir", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.ir.mir")?;
    Ok(())
}
