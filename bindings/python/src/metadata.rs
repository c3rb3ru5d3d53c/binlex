use crate::formats::File;
use ::binlex::formats::SymbolJson;
use ::binlex::metadata::{Attribute as InnerAttribute, TagJson};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyType;

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Attribute {
    pub inner: InnerAttribute,
}

#[pymethods]
impl Attribute {
    #[classmethod]
    #[pyo3(text_signature = "(cls, file)")]
    pub fn from_file(_cls: &Bound<'_, PyType>, py: Python, file: Py<File>) -> PyResult<Self> {
        let file = file.borrow(py);
        Ok(Self {
            inner: InnerAttribute::File(file.inner.process()),
        })
    }

    #[classmethod]
    #[pyo3(text_signature = "(cls, value)")]
    pub fn tag(_cls: &Bound<'_, PyType>, value: String) -> PyResult<Self> {
        Ok(Self {
            inner: InnerAttribute::Tag(TagJson {
                type_: "tag".to_string(),
                value,
            }),
        })
    }

    #[classmethod]
    #[pyo3(text_signature = "(cls, name, symbol_type, address)")]
    pub fn symbol(
        _cls: &Bound<'_, PyType>,
        name: String,
        symbol_type: String,
        address: u64,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: InnerAttribute::Symbol(SymbolJson {
                type_: "symbol".to_string(),
                name,
                symbol_type,
                address,
            }),
        })
    }

    pub fn json(&self) -> PyResult<String> {
        serde_json::to_string(&self.inner.to_json_value())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    pub fn to_dict(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_module = py.import("json")?;
        let value = self.json()?;
        Ok(json_module.call_method1("loads", (value,))?.into())
    }
}

#[pymodule]
#[pyo3(name = "metadata")]
pub fn metadata_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Attribute>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.metadata", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.metadata")?;
    Ok(())
}
