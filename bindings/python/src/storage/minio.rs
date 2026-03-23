use pyo3::prelude::*;

#[pyclass(name = "Client")]
pub struct Client {
    inner: binlex::storage::MinIO,
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (endpoint, access_key, secret_key, secure=false))]
    pub fn new(
        endpoint: String,
        access_key: String,
        secret_key: String,
        secure: bool,
    ) -> PyResult<Self> {
        let inner = binlex::storage::MinIO::new(endpoint, access_key, secret_key, secure)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[getter]
    pub fn endpoint(&self) -> String {
        self.inner.endpoint().to_string()
    }

    #[getter]
    pub fn access_key(&self) -> String {
        self.inner.access_key().to_string()
    }

    #[getter]
    pub fn secret_key(&self) -> String {
        self.inner.secret_key().to_string()
    }

    #[getter]
    pub fn secure(&self) -> bool {
        self.inner.secure()
    }

    pub fn ensure_bucket(&self, bucket: String) -> PyResult<()> {
        self.inner
            .ensure_bucket(&bucket)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (bucket, key, payload, content_type="application/octet-stream"))]
    pub fn put_object(
        &self,
        bucket: String,
        key: String,
        payload: Vec<u8>,
        content_type: &str,
    ) -> PyResult<()> {
        self.inner
            .put_object(&bucket, &key, &payload, content_type)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }
}

#[pymodule]
#[pyo3(name = "minio")]
pub fn minio_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.storage.minio", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.storage.minio")?;
    Ok(())
}
