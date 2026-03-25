use binlex::databases::{
    FieldSchema as InnerFieldSchema, FieldType as InnerFieldType, Milvus as InnerMilvus,
};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;

#[pyclass(name = "Client")]
pub struct Client {
    inner: InnerMilvus,
}

fn field_type_from_python(field: &Bound<'_, PyDict>) -> PyResult<InnerFieldType> {
    let kind: String = field
        .get_item("kind")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("field is missing kind"))?
        .extract()?;
    match kind.as_str() {
        "varchar" => Ok(InnerFieldType::VarChar),
        "int64" => Ok(InnerFieldType::Int64),
        "bool" => Ok(InnerFieldType::Bool),
        "float_vector" => {
            let dimensions: usize = field
                .get_item("dimensions")?
                .ok_or_else(|| {
                    pyo3::exceptions::PyValueError::new_err(
                        "float_vector field is missing dimensions",
                    )
                })?
                .extract()?;
            Ok(InnerFieldType::FloatVector { dimensions })
        }
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unsupported milvus field kind: {}",
            other
        ))),
    }
}

fn field_schema_from_python(field: &Bound<'_, PyDict>) -> PyResult<InnerFieldSchema> {
    let name: String = field
        .get_item("name")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("field is missing name"))?
        .extract()?;
    let primary_key = field
        .get_item("primary_key")?
        .map(|value| value.extract())
        .transpose()?
        .unwrap_or(false);
    Ok(InnerFieldSchema {
        name,
        kind: field_type_from_python(field)?,
        primary_key,
    })
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (uri, token=None))]
    pub fn new(uri: String, token: Option<String>) -> PyResult<Self> {
        let inner = InnerMilvus::new(uri, token)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[getter]
    pub fn uri(&self) -> String {
        self.inner.uri().to_string()
    }

    #[getter]
    pub fn token(&self) -> Option<String> {
        self.inner.token().map(ToString::to_string)
    }

    pub fn ensure_collection(
        &self,
        database: String,
        collection: String,
        fields: &Bound<'_, PyList>,
    ) -> PyResult<()> {
        let fields = fields
            .iter()
            .map(|field| {
                field
                    .cast::<PyDict>()
                    .map_err(|_| {
                        pyo3::exceptions::PyTypeError::new_err("fields must contain dict entries")
                    })
                    .and_then(|field| field_schema_from_python(&field))
            })
            .collect::<PyResult<Vec<_>>>()?;
        self.inner
            .ensure_collection(&database, &collection, &fields)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn upsert(
        &self,
        py: Python<'_>,
        database: String,
        collection: String,
        row: Py<PyAny>,
    ) -> PyResult<()> {
        let json = py.import("json")?;
        let text: String = json.call_method1("dumps", (row,))?.extract()?;
        let row: Value = serde_json::from_str(&text)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        self.inner
            .upsert(&database, &collection, &row)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }
}

#[pymodule]
#[pyo3(name = "milvus")]
pub fn milvus_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.databases.milvus", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.databases.milvus")?;
    Ok(())
}
