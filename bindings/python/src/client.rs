use crate::controlflow::Graph as PyGraph;
use crate::Config;
use pyo3::prelude::*;
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[pyclass(name = "Client")]
pub struct Client {
    inner: binlex::client::Client,
}

#[pymethods]
impl Client {
    #[new]
    #[pyo3(signature = (config, url=None, verify=None, compression=None))]
    pub fn new(
        py: Python<'_>,
        config: Py<Config>,
        url: Option<String>,
        verify: Option<bool>,
        compression: Option<bool>,
    ) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = binlex::client::Client::new(inner_config, url, verify, compression)
            .map_err(map_client_error)?;
        Ok(Self { inner })
    }

    #[getter]
    pub fn url(&self) -> String {
        self.inner.url().to_string()
    }

    #[getter]
    pub fn verify(&self) -> bool {
        self.inner.verify()
    }

    #[getter]
    pub fn compression(&self) -> bool {
        self.inner.compression()
    }

    pub fn health(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = serde_json::to_value(self.inner.health().map_err(map_client_error)?)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        json_value_to_python(py, &value)
    }

    #[pyo3(signature = (path, magic=None, architecture=None))]
    pub fn analyze_file(
        &self,
        py: Python<'_>,
        path: String,
        magic: Option<String>,
        architecture: Option<String>,
    ) -> PyResult<Py<PyGraph>> {
        let magic = parse_magic(magic)?;
        let architecture = parse_architecture(architecture)?;
        let graph = self
            .inner
            .analyze_file(path, magic, architecture)
            .map_err(map_client_error)?;
        Py::new(
            py,
            PyGraph {
                inner: Arc::new(Mutex::new(graph)),
            },
        )
    }

    #[pyo3(signature = (data, magic=None, architecture=None))]
    pub fn analyze_bytes(
        &self,
        py: Python<'_>,
        data: Vec<u8>,
        magic: Option<String>,
        architecture: Option<String>,
    ) -> PyResult<Py<PyGraph>> {
        let magic = parse_magic(magic)?;
        let architecture = parse_architecture(architecture)?;
        let graph = self
            .inner
            .analyze_bytes(&data, magic, architecture)
            .map_err(map_client_error)?;
        Py::new(
            py,
            PyGraph {
                inner: Arc::new(Mutex::new(graph)),
            },
        )
    }
}

fn parse_magic(value: Option<String>) -> PyResult<Option<binlex::Magic>> {
    match value {
        Some(value) if value.eq_ignore_ascii_case("unknown") => Ok(None),
        Some(value) => value
            .parse::<binlex::Magic>()
            .map(Some)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string())),
        None => Ok(None),
    }
}

fn parse_architecture(value: Option<String>) -> PyResult<Option<binlex::Architecture>> {
    match value {
        Some(value) if value.eq_ignore_ascii_case("unknown") => Ok(None),
        Some(value) => binlex::Architecture::from_string(&value)
            .map(Some)
            .map_err(|error| pyo3::exceptions::PyValueError::new_err(error.to_string())),
        None => Ok(None),
    }
}

fn json_value_to_python(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let json = py.import("json")?;
    let text = serde_json::to_string(value)
        .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
    Ok(json.call_method1("loads", (text,))?.unbind())
}

fn map_client_error(error: binlex::client::Error) -> PyErr {
    match error {
        binlex::client::Error::InvalidConfiguration(message) => {
            pyo3::exceptions::PyValueError::new_err(message)
        }
        other => pyo3::exceptions::PyRuntimeError::new_err(other.to_string()),
    }
}

#[pymodule]
#[pyo3(name = "client")]
pub fn client_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Client>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.client", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.client")?;
    Ok(())
}
