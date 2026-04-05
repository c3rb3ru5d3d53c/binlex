use pyo3::prelude::*;

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

    pub fn put(&self, path: String, payload: Vec<u8>) -> PyResult<()> {
        self.inner
            .put(&path, &payload)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn get(&self, path: String) -> PyResult<Vec<u8>> {
        self.inner
            .get(&path)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn exists(&self, path: String) -> PyResult<bool> {
        self.inner
            .exists(&path)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn list_prefix(&self, prefix: String) -> PyResult<Vec<String>> {
        self.inner
            .list_prefix(&prefix)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn delete(&self, path: String) -> PyResult<()> {
        self.inner
            .delete(&path)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn delete_prefix(&self, prefix: String) -> PyResult<()> {
        self.inner
            .delete_prefix(&prefix)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }
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
