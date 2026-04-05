use crate::config::config::Config;
use pyo3::prelude::*;
use pyo3::types::PyAny;

#[pyclass(name = "LocalStore")]
pub struct LocalStore {
    inner: binlex::storage::LocalStore,
}

#[pymethods]
impl LocalStore {
    #[new]
    pub fn new(config: PyRef<'_, Config>) -> PyResult<Self> {
        let config = config
            .inner
            .lock()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?
            .clone();
        let inner = binlex::storage::LocalStore::new(config)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[staticmethod]
    pub fn with_root(root: String) -> PyResult<Self> {
        let inner = binlex::storage::LocalStore::with_root(root)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[getter]
    pub fn root(&self) -> String {
        self.inner.root().display().to_string()
    }

    pub fn object_put(&self, path: String, payload: Vec<u8>) -> PyResult<()> {
        self.inner
            .object_put(&path, &payload)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn object_get(&self, path: String) -> PyResult<Vec<u8>> {
        self.inner
            .object_get(&path)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn object_exists(&self, path: String) -> PyResult<bool> {
        self.inner
            .object_exists(&path)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn object_put_json(
        &self,
        py: Python<'_>,
        path: String,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let json = py.import("json")?;
        let serialized = json
            .getattr("dumps")?
            .call1((value,))?
            .extract::<String>()?;
        let payload = serde_json::from_str::<serde_json::Value>(&serialized)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        self.inner
            .object_put_json(&path, &payload)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn object_get_json(&self, py: Python<'_>, path: String) -> PyResult<Py<PyAny>> {
        let value = self
            .inner
            .object_get_json::<serde_json::Value>(&path)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        let json = py.import("json")?;
        let serialized = serde_json::to_string(&value)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        json.getattr("loads")?
            .call1((serialized,))
            .map(|value| value.unbind())
    }

    pub fn object_list_json(&self, py: Python<'_>, prefix: String) -> PyResult<Py<PyAny>> {
        let values = self
            .inner
            .object_list_json::<serde_json::Value>(&prefix)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        let json = py.import("json")?;
        let serialized = serde_json::to_string(&values)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        json.getattr("loads")?
            .call1((serialized,))
            .map(|value| value.unbind())
    }

    pub fn object_list(&self, prefix: String) -> PyResult<Vec<String>> {
        self.inner
            .object_list(&prefix)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn object_delete(&self, path: String) -> PyResult<()> {
        self.inner
            .object_delete(&path)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn object_delete_prefix(&self, prefix: String) -> PyResult<()> {
        self.inner
            .object_delete_prefix(&prefix)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn sample_put(&self, data: Vec<u8>) -> PyResult<String> {
        self.inner
            .sample_put(&data)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn sample_get(&self, sha256: String) -> PyResult<Vec<u8>> {
        self.inner
            .sample_get(&sha256)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn sample_exists(&self, sha256: String) -> PyResult<bool> {
        self.inner
            .sample_exists(&sha256)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn sample_json_put(
        &self,
        py: Python<'_>,
        sha256: String,
        name: String,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let json = py.import("json")?;
        let serialized = json
            .getattr("dumps")?
            .call1((value,))?
            .extract::<String>()?;
        let payload = serde_json::from_str::<serde_json::Value>(&serialized)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        self.inner
            .sample_json_put(&sha256, &name, &payload)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn sample_json_get(
        &self,
        py: Python<'_>,
        sha256: String,
        name: String,
    ) -> PyResult<Py<PyAny>> {
        let value = self
            .inner
            .sample_json_get::<serde_json::Value>(&sha256, &name)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        let json = py.import("json")?;
        let serialized = serde_json::to_string(&value)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        json.getattr("loads")?
            .call1((serialized,))
            .map(|value| value.unbind())
    }
}

#[pymodule]
#[pyo3(name = "localstore")]
pub fn localstore_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LocalStore>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.storage.localstore", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.storage.localstore")?;
    Ok(())
}
