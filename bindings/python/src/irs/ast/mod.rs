use crate::formats::Image;
use binlex::irs::ast::{
    AstBinaryOperation, AstBlock, AstCastOperation, AstCompareOperation, AstExpression,
    AstFunction, AstLocal, AstModule, AstParameter, AstPlace, AstStatement, AstStructureMember,
    AstTarget, AstType, AstUnaryOperation, AstUnionMember, AstValue,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyModule, PyType};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};

fn hash_value<T: Hash>(value: &T) -> isize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish() as isize
}

fn extract_hir_function(
    py: Python<'_>,
    value: Py<PyAny>,
) -> PyResult<binlex::irs::hir::HirFunction> {
    let bound = value.bind(py);
    if let Ok(function) = bound.extract::<PyRef<'_, crate::irs::hir::PyHirFunction>>() {
        return Ok(function.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let function = inner.extract::<PyRef<'_, crate::irs::hir::PyHirFunction>>()?;
    let result = function.inner.lock().unwrap().clone();
    Ok(result)
}

fn extract_hir_module(py: Python<'_>, value: Py<PyAny>) -> PyResult<binlex::irs::hir::HirModule> {
    let bound = value.bind(py);
    if let Ok(module) = bound.extract::<PyRef<'_, crate::irs::hir::PyHirModule>>() {
        return Ok(module.inner.lock().unwrap().clone());
    }
    let inner = bound.getattr("_inner")?;
    let module = inner.extract::<PyRef<'_, crate::irs::hir::PyHirModule>>()?;
    let result = module.inner.lock().unwrap().clone();
    Ok(result)
}

fn parse_ast_unary_operation(value: String) -> PyResult<AstUnaryOperation> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

fn parse_ast_binary_operation(value: String) -> PyResult<AstBinaryOperation> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

fn parse_ast_cast_operation(value: String) -> PyResult<AstCastOperation> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|error| PyValueError::new_err(error.to_string()))
}

fn parse_ast_compare_operation(value: String) -> PyResult<AstCompareOperation> {
    serde_json::from_value(serde_json::Value::String(value))
        .map_err(|error| PyValueError::new_err(error.to_string()))
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

value_wrapper!(PyAstValue, "AstValue", AstValue);
value_wrapper!(PyAstType, "AstType", AstType);
value_wrapper!(
    PyAstStructureMember,
    "AstStructureMember",
    AstStructureMember
);
value_wrapper!(PyAstUnionMember, "AstUnionMember", AstUnionMember);
value_wrapper!(PyAstExpression, "AstExpression", AstExpression);
value_wrapper!(PyAstPlace, "AstPlace", AstPlace);
value_wrapper!(PyAstTarget, "AstTarget", AstTarget);
value_wrapper!(PyAstStatement, "AstStatement", AstStatement);
value_wrapper!(PyAstBlock, "AstBlock", AstBlock);
value_wrapper!(PyAstParameter, "AstParameter", AstParameter);
value_wrapper!(PyAstLocal, "AstLocal", AstLocal);

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
impl PyAstType {
    #[classmethod]
    pub fn void(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(AstType::void())
    }

    #[classmethod]
    pub fn integer(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(AstType::integer(bits))
    }

    #[classmethod]
    pub fn float(_cls: &Bound<'_, PyType>, bits: u16) -> Self {
        Self::from_inner(AstType::float(bits))
    }

    #[classmethod]
    pub fn pointer(_cls: &Bound<'_, PyType>, pointee: PyRef<'_, PyAstType>) -> Self {
        Self::from_inner(AstType::pointer(pointee.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn function(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        parameters: Option<Vec<Py<PyAstType>>>,
        returns: Option<Vec<Py<PyAstType>>>,
    ) -> Self {
        let parameters = parameters
            .unwrap_or_default()
            .into_iter()
            .map(|ty| ty.borrow(py).inner.lock().unwrap().clone())
            .collect();
        let returns = returns
            .unwrap_or_default()
            .into_iter()
            .map(|ty| ty.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(AstType::function(parameters, returns))
    }

    #[classmethod]
    pub fn memory(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(AstType::memory())
    }

    #[classmethod]
    pub fn type_definition(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(AstType::type_definition(name))
    }

    #[classmethod]
    #[pyo3(signature = (name, members=None))]
    pub fn structure(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        members: Option<Vec<Py<PyAstStructureMember>>>,
    ) -> Self {
        let members = members
            .unwrap_or_default()
            .into_iter()
            .map(|member| member.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(AstType::structure(name, members))
    }

    #[classmethod]
    #[pyo3(signature = (name, members=None))]
    pub fn union(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        name: String,
        members: Option<Vec<Py<PyAstUnionMember>>>,
    ) -> Self {
        let members = members
            .unwrap_or_default()
            .into_iter()
            .map(|member| member.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(AstType::union(name, members))
    }
}

#[pymethods]
impl PyAstStructureMember {
    #[new]
    pub fn new(name: String, ty: PyRef<'_, PyAstType>) -> Self {
        Self::from_inner(AstStructureMember::new(
            name,
            ty.inner.lock().unwrap().clone(),
        ))
    }

    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name.clone()
    }
}

#[pymethods]
impl PyAstUnionMember {
    #[new]
    pub fn new(name: String, ty: PyRef<'_, PyAstType>) -> Self {
        Self::from_inner(AstUnionMember::new(name, ty.inner.lock().unwrap().clone()))
    }

    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name.clone()
    }
}

#[pymethods]
impl PyAstValue {
    #[classmethod]
    pub fn named(_cls: &Bound<'_, PyType>, name: String, ty: PyRef<'_, PyAstType>) -> Self {
        Self::from_inner(AstValue::Named {
            name,
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn integer(_cls: &Bound<'_, PyType>, value: i128, bits: u16) -> Self {
        Self::from_inner(AstValue::Integer { value, bits })
    }

    #[classmethod]
    pub fn boolean(_cls: &Bound<'_, PyType>, value: bool) -> Self {
        Self::from_inner(AstValue::Boolean(value))
    }

    #[classmethod]
    pub fn null(_cls: &Bound<'_, PyType>, ty: PyRef<'_, PyAstType>) -> Self {
        Self::from_inner(AstValue::Null {
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn undef(_cls: &Bound<'_, PyType>, ty: PyRef<'_, PyAstType>) -> Self {
        Self::from_inner(AstValue::Undef {
            ty: ty.inner.lock().unwrap().clone(),
        })
    }
}

#[pymethods]
impl PyAstExpression {
    #[classmethod]
    pub fn value(_cls: &Bound<'_, PyType>, value: PyRef<'_, PyAstValue>) -> Self {
        Self::from_inner(AstExpression::Value(value.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn call(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        target: PyRef<'_, PyAstTarget>,
        arguments: Option<Vec<Py<PyAstExpression>>>,
        return_types: Option<Vec<Py<PyAstType>>>,
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
        Self::from_inner(AstExpression::Call {
            target: target.inner.lock().unwrap().clone(),
            abi: None,
            arguments,
            return_types,
        })
    }

    #[classmethod]
    pub fn member(
        _cls: &Bound<'_, PyType>,
        base: PyRef<'_, PyAstExpression>,
        name: String,
        ty: PyRef<'_, PyAstType>,
    ) -> Self {
        Self::from_inner(AstExpression::Member {
            base: Box::new(base.inner.lock().unwrap().clone()),
            name,
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn unary(
        _cls: &Bound<'_, PyType>,
        op: String,
        value: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> PyResult<Self> {
        Ok(Self::from_inner(AstExpression::Unary {
            op: parse_ast_unary_operation(op)?,
            value: Box::new(value.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        }))
    }

    #[classmethod]
    pub fn binary(
        _cls: &Bound<'_, PyType>,
        op: String,
        lhs: PyRef<'_, PyAstExpression>,
        rhs: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> PyResult<Self> {
        Ok(Self::from_inner(AstExpression::Binary {
            op: parse_ast_binary_operation(op)?,
            lhs: Box::new(lhs.inner.lock().unwrap().clone()),
            rhs: Box::new(rhs.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        }))
    }

    #[classmethod]
    pub fn cast(
        _cls: &Bound<'_, PyType>,
        op: String,
        value: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> PyResult<Self> {
        Ok(Self::from_inner(AstExpression::Cast {
            op: parse_ast_cast_operation(op)?,
            value: Box::new(value.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        }))
    }

    #[classmethod]
    pub fn load(
        _cls: &Bound<'_, PyType>,
        address_space: PyRef<'_, crate::irs::mir::PyMirAddressSpace>,
        address: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> PyResult<Self> {
        Ok(Self::from_inner(AstExpression::Load {
            address_space: address_space.inner.lock().unwrap().clone(),
            address: Box::new(address.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        }))
    }

    #[classmethod]
    pub fn address_of(
        _cls: &Bound<'_, PyType>,
        place: PyRef<'_, PyAstPlace>,
        ty: PyRef<'_, PyAstType>,
    ) -> Self {
        Self::from_inner(AstExpression::AddressOf {
            place: Box::new(place.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn dereference(
        _cls: &Bound<'_, PyType>,
        pointer: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> Self {
        Self::from_inner(AstExpression::Dereference {
            pointer: Box::new(pointer.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn index(
        _cls: &Bound<'_, PyType>,
        base: PyRef<'_, PyAstExpression>,
        index: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> Self {
        Self::from_inner(AstExpression::Index {
            base: Box::new(base.inner.lock().unwrap().clone()),
            index: Box::new(index.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn compare(
        _cls: &Bound<'_, PyType>,
        op: String,
        lhs: PyRef<'_, PyAstExpression>,
        rhs: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> PyResult<Self> {
        Ok(Self::from_inner(AstExpression::Compare {
            op: parse_ast_compare_operation(op)?,
            lhs: Box::new(lhs.inner.lock().unwrap().clone()),
            rhs: Box::new(rhs.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        }))
    }

    #[classmethod]
    pub fn select(
        _cls: &Bound<'_, PyType>,
        condition: PyRef<'_, PyAstExpression>,
        when_true: PyRef<'_, PyAstExpression>,
        when_false: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> Self {
        Self::from_inner(AstExpression::Select {
            condition: Box::new(condition.inner.lock().unwrap().clone()),
            when_true: Box::new(when_true.inner.lock().unwrap().clone()),
            when_false: Box::new(when_false.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        })
    }
}

#[pymethods]
impl PyAstPlace {
    #[classmethod]
    pub fn named(_cls: &Bound<'_, PyType>, name: String, ty: PyRef<'_, PyAstType>) -> Self {
        Self::from_inner(AstPlace::Named {
            name,
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn dereference(
        _cls: &Bound<'_, PyType>,
        pointer: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> Self {
        Self::from_inner(AstPlace::Dereference {
            pointer: Box::new(pointer.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn index(
        _cls: &Bound<'_, PyType>,
        base: PyRef<'_, PyAstExpression>,
        index: PyRef<'_, PyAstExpression>,
        ty: PyRef<'_, PyAstType>,
    ) -> Self {
        Self::from_inner(AstPlace::Index {
            base: Box::new(base.inner.lock().unwrap().clone()),
            index: Box::new(index.inner.lock().unwrap().clone()),
            ty: ty.inner.lock().unwrap().clone(),
        })
    }
}

#[pymethods]
impl PyAstTarget {
    #[classmethod]
    pub fn direct(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(AstTarget::Direct(name))
    }

    #[classmethod]
    pub fn indirect(_cls: &Bound<'_, PyType>, expression: PyRef<'_, PyAstExpression>) -> Self {
        Self::from_inner(AstTarget::Indirect(Box::new(
            expression.inner.lock().unwrap().clone(),
        )))
    }
}

#[pymethods]
impl PyAstStatement {
    #[classmethod]
    pub fn assign(
        _cls: &Bound<'_, PyType>,
        target: PyRef<'_, PyAstPlace>,
        value: PyRef<'_, PyAstExpression>,
    ) -> Self {
        Self::from_inner(AstStatement::Assign {
            target: target.inner.lock().unwrap().clone(),
            value: value.inner.lock().unwrap().clone(),
        })
    }

    #[classmethod]
    pub fn expr(_cls: &Bound<'_, PyType>, value: PyRef<'_, PyAstExpression>) -> Self {
        Self::from_inner(AstStatement::Expr(value.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    pub fn comment(_cls: &Bound<'_, PyType>, comment: String) -> Self {
        Self::from_inner(AstStatement::Comment(comment))
    }

    #[classmethod]
    #[pyo3(name = "return_")]
    pub fn return_values(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        values: Option<Vec<Py<PyAstExpression>>>,
    ) -> Self {
        let values = values
            .unwrap_or_default()
            .into_iter()
            .map(|value| value.borrow(py).inner.lock().unwrap().clone())
            .collect();
        Self::from_inner(AstStatement::Return { values })
    }

    #[classmethod]
    pub fn label(_cls: &Bound<'_, PyType>, name: String) -> Self {
        Self::from_inner(AstStatement::Label(name))
    }

    #[classmethod]
    pub fn goto(_cls: &Bound<'_, PyType>, target: PyRef<'_, PyAstTarget>) -> Self {
        Self::from_inner(AstStatement::Goto(target.inner.lock().unwrap().clone()))
    }

    #[classmethod]
    #[pyo3(name = "break_")]
    pub fn break_statement(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(AstStatement::Break)
    }

    #[classmethod]
    #[pyo3(name = "continue_")]
    pub fn continue_statement(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(AstStatement::Continue)
    }

    #[classmethod]
    pub fn trap(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(AstStatement::Trap)
    }

    #[classmethod]
    pub fn unreachable(_cls: &Bound<'_, PyType>) -> Self {
        Self::from_inner(AstStatement::Unreachable)
    }
}

#[pymethods]
impl PyAstBlock {
    #[new]
    pub fn new() -> Self {
        Self::from_inner(AstBlock::default())
    }

    pub fn statements(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAstStatement>>> {
        self.inner
            .lock()
            .unwrap()
            .statements
            .iter()
            .cloned()
            .map(|statement| Py::new(py, PyAstStatement::from_inner(statement)))
            .collect()
    }

    pub fn append_statement(&mut self, statement: PyRef<'_, PyAstStatement>) {
        self.inner
            .lock()
            .unwrap()
            .statements
            .push(statement.inner.lock().unwrap().clone());
    }

    pub fn append_comment(&mut self, comment: String) {
        self.inner
            .lock()
            .unwrap()
            .statements
            .push(AstStatement::Comment(comment));
    }

    pub fn __hash__(&self) -> isize {
        hash_value(&*self.inner.lock().unwrap())
    }
}

#[pymethods]
impl PyAstParameter {
    #[new]
    #[pyo3(signature = (name, ty, comment=None))]
    pub fn new(name: String, ty: PyRef<'_, PyAstType>, comment: Option<String>) -> Self {
        Self::from_inner(AstParameter {
            name,
            ty: ty.inner.lock().unwrap().clone(),
            comment,
        })
    }

    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name.clone()
    }

    pub fn set_name(&mut self, name: String) {
        self.inner.lock().unwrap().name = name;
    }

    pub fn comment(&self) -> Option<String> {
        self.inner.lock().unwrap().comment.clone()
    }

    pub fn set_comment(&mut self, comment: Option<String>) {
        self.inner.lock().unwrap().comment = comment;
    }
}

#[pymethods]
impl PyAstLocal {
    #[new]
    #[pyo3(signature = (name, ty, init=None, display_name=None, comment=None))]
    pub fn new(
        name: String,
        ty: PyRef<'_, PyAstType>,
        init: Option<PyRef<'_, PyAstExpression>>,
        display_name: Option<String>,
        comment: Option<String>,
    ) -> Self {
        Self::from_inner(AstLocal {
            name,
            ty: ty.inner.lock().unwrap().clone(),
            init: init.map(|value| value.inner.lock().unwrap().clone()),
            storage: None,
            display_name,
            comment,
        })
    }

    pub fn name(&self) -> String {
        self.inner.lock().unwrap().name.clone()
    }

    pub fn set_name(&mut self, name: String) {
        self.inner.lock().unwrap().name = name;
    }

    pub fn display_name(&self) -> Option<String> {
        self.inner.lock().unwrap().display_name.clone()
    }

    pub fn set_display_name(&mut self, display_name: Option<String>) {
        self.inner.lock().unwrap().display_name = display_name;
    }

    pub fn rename(&mut self, display_name: String) {
        self.inner.lock().unwrap().display_name = Some(display_name);
    }

    pub fn comment(&self) -> Option<String> {
        self.inner.lock().unwrap().comment.clone()
    }

    pub fn set_comment(&mut self, comment: Option<String>) {
        self.inner.lock().unwrap().comment = comment;
    }
}

#[pymethods]
impl PyAstFunction {
    #[new]
    #[pyo3(signature = (name=None))]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(AstFunction::new(name))
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

    pub fn comment(&self) -> Option<String> {
        self.inner.lock().unwrap().comment.clone()
    }

    pub fn set_comment(&mut self, comment: Option<String>) {
        self.inner.lock().unwrap().set_comment(comment);
    }

    pub fn set_returns(&mut self, py: Python<'_>, returns: Vec<Py<PyAstType>>) {
        let returns = returns
            .into_iter()
            .map(|ty| ty.borrow(py).inner.lock().unwrap().clone())
            .collect();
        self.inner.lock().unwrap().set_returns(returns);
    }

    pub fn append_return(&mut self, ty: PyRef<'_, PyAstType>) {
        self.inner
            .lock()
            .unwrap()
            .append_return(ty.inner.lock().unwrap().clone());
    }

    pub fn parameters(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAstParameter>>> {
        self.inner
            .lock()
            .unwrap()
            .parameters
            .iter()
            .cloned()
            .map(|parameter| Py::new(py, PyAstParameter::from_inner(parameter)))
            .collect()
    }

    pub fn locals(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAstLocal>>> {
        self.inner
            .lock()
            .unwrap()
            .locals
            .iter()
            .cloned()
            .map(|local| Py::new(py, PyAstLocal::from_inner(local)))
            .collect()
    }

    pub fn blocks(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAstBlock>>> {
        self.inner
            .lock()
            .unwrap()
            .blocks
            .iter()
            .cloned()
            .map(|block| Py::new(py, PyAstBlock::from_inner(block)))
            .collect()
    }

    pub fn append_parameter(&mut self, parameter: PyRef<'_, PyAstParameter>) {
        self.inner
            .lock()
            .unwrap()
            .parameters
            .push(parameter.inner.lock().unwrap().clone());
    }

    pub fn append_local(&mut self, local: PyRef<'_, PyAstLocal>) {
        self.inner
            .lock()
            .unwrap()
            .locals
            .push(local.inner.lock().unwrap().clone());
    }

    pub fn append_block(&mut self, block: PyRef<'_, PyAstBlock>) {
        self.inner
            .lock()
            .unwrap()
            .blocks
            .push(block.inner.lock().unwrap().clone());
    }

    pub fn rename_local(&mut self, name: String, display_name: String) -> bool {
        self.inner.lock().unwrap().rename_local(&name, display_name)
    }

    pub fn set_local_comment(&mut self, name: String, comment: Option<String>) -> bool {
        self.inner.lock().unwrap().set_local_comment(&name, comment)
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
    #[pyo3(signature = (name=None))]
    pub fn new(name: Option<String>) -> Self {
        Self::from_inner(AstModule::new(name))
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

    pub fn functions(&self, py: Python<'_>) -> PyResult<Vec<Py<PyAstFunction>>> {
        self.inner
            .lock()
            .unwrap()
            .functions
            .iter()
            .cloned()
            .map(|function| Py::new(py, PyAstFunction::from_inner(function)))
            .collect()
    }

    pub fn append_function(&mut self, function: PyRef<'_, PyAstFunction>) {
        self.inner
            .lock()
            .unwrap()
            .functions
            .push(function.inner.lock().unwrap().clone());
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
    m.add_class::<PyAstValue>()?;
    m.add_class::<PyAstType>()?;
    m.add_class::<PyAstStructureMember>()?;
    m.add_class::<PyAstUnionMember>()?;
    m.add_class::<PyAstExpression>()?;
    m.add_class::<PyAstPlace>()?;
    m.add_class::<PyAstTarget>()?;
    m.add_class::<PyAstStatement>()?;
    m.add_class::<PyAstBlock>()?;
    m.add_class::<PyAstParameter>()?;
    m.add_class::<PyAstLocal>()?;
    m.add_class::<PyAstFunction>()?;
    m.add_class::<PyAstModule>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.irs.ast", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.irs.ast")?;
    Ok(())
}
