use pyo3::prelude::*;
use serde_json::Value;

#[pyclass(name = "ObjectStore")]
pub struct ObjectStore {
    inner: binlex::storage::ObjectStore,
}

#[pymethods]
impl ObjectStore {
    #[new]
    pub fn new(root: String) -> PyResult<Self> {
        let inner = binlex::storage::ObjectStore::new(root)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[getter]
    pub fn root(&self) -> String {
        self.inner.root().display().to_string()
    }

    pub fn put_bytes(&self, key: String, payload: Vec<u8>) -> PyResult<()> {
        self.inner
            .put_bytes(&key, &payload)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn get_bytes(&self, key: String) -> PyResult<Vec<u8>> {
        self.inner
            .get_bytes(&key)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn exists(&self, key: String) -> PyResult<bool> {
        self.inner
            .exists(&key)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn put_json(&self, py: Python<'_>, key: String, value: Py<PyAny>) -> PyResult<()> {
        let json = py.import("json")?;
        let text: String = json.call_method1("dumps", (value,))?.extract()?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        self.inner
            .put_json(&key, &value)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn get_json(&self, py: Python<'_>, key: String) -> PyResult<Py<PyAny>> {
        let value: Value = self
            .inner
            .get_json(&key)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        json_value_to_python(py, &value)
    }

    pub fn list_json_prefix(&self, py: Python<'_>, prefix: String) -> PyResult<Vec<Py<PyAny>>> {
        let values: Vec<Value> = self
            .inner
            .list_json_prefix(&prefix)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        values
            .iter()
            .map(|value| json_value_to_python(py, value))
            .collect()
    }

    pub fn delete_prefix(&self, prefix: String) -> PyResult<()> {
        self.inner
            .delete_prefix(&prefix)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }
}

fn json_value_to_python(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json = py.import("json")?;
    let text = serde_json::to_string(value)
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    json.call_method1("loads", (text,))
        .map(|value| value.unbind())
}

#[pymodule]
#[pyo3(name = "object_store")]
pub fn object_store_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ObjectStore>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.storage.object_store", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.storage.object_store")?;
    Ok(())
}
