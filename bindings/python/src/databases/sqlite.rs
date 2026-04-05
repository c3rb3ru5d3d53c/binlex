use crate::controlflow::json_value_to_py;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::{Arc, Mutex};

#[pyclass]
pub struct SQLite {
    inner: Arc<Mutex<binlex::databases::SQLite>>,
}

#[pymethods]
impl SQLite {
    #[new]
    #[pyo3(text_signature = "(path)")]
    pub fn new(path: String) -> PyResult<Self> {
        let inner = binlex::databases::SQLite::new(std::path::Path::new(&path))
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[getter]
    pub fn get_path(&self) -> PyResult<String> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("sqlite mutex poisoned"))?
            .path()
            .display()
            .to_string())
    }

    #[pyo3(text_signature = "($self, sql)")]
    pub fn execute_batch(&self, sql: String) -> PyResult<()> {
        self.inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("sqlite mutex poisoned"))?
            .execute_batch(&sql)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sql, params=None), text_signature = "($self, sql, params=None)")]
    pub fn execute(
        &self,
        py: Python<'_>,
        sql: String,
        params: Option<Vec<Py<PyAny>>>,
    ) -> PyResult<usize> {
        let params = py_params_to_sqlite_values(py, params)?;
        self.inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("sqlite mutex poisoned"))?
            .execute(&sql, &params)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sql, params=None), text_signature = "($self, sql, params=None)")]
    pub fn query(
        &self,
        py: Python<'_>,
        sql: String,
        params: Option<Vec<Py<PyAny>>>,
    ) -> PyResult<Py<PyAny>> {
        let params = py_params_to_sqlite_values(py, params)?;
        let rows = self
            .inner
            .lock()
            .map_err(|_| PyRuntimeError::new_err("sqlite mutex poisoned"))?
            .query(&sql, &params)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        json_value_to_py(
            py,
            &serde_json::Value::Array(rows.into_iter().map(serde_json::Value::Object).collect()),
        )
    }
}

#[pymodule]
#[pyo3(name = "sqlite")]
pub fn sqlite_init(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<SQLite>()?;
    Ok(())
}

fn py_params_to_sqlite_values(
    py: Python<'_>,
    params: Option<Vec<Py<PyAny>>>,
) -> PyResult<Vec<binlex::databases::SQLiteValue>> {
    let mut values = Vec::new();
    for value in params.unwrap_or_default() {
        let value = value.bind(py);
        if value.is_none() {
            values.push(binlex::databases::SQLiteValue::Null);
        } else if let Ok(text) = value.extract::<String>() {
            values.push(binlex::databases::SQLiteValue::Text(text));
        } else if let Ok(integer) = value.extract::<i64>() {
            values.push(binlex::databases::SQLiteValue::Integer(integer));
        } else if let Ok(real) = value.extract::<f64>() {
            values.push(binlex::databases::SQLiteValue::Real(real));
        } else if let Ok(bytes) = value.cast::<PyBytes>() {
            values.push(binlex::databases::SQLiteValue::Blob(
                bytes.as_bytes().to_vec(),
            ));
        } else {
            return Err(PyValueError::new_err(
                "sqlite params must be None, str, int, float, or bytes",
            ));
        }
    }
    Ok(values)
}
