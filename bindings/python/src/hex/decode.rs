use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
#[pyo3(text_signature = "(value)")]
pub fn decode(py: Python<'_>, value: &str) -> PyResult<Py<PyBytes>> {
    let bytes = binlex::hex::decode(value).map_err(PyValueError::new_err)?;
    Ok(PyBytes::new(py, &bytes).unbind())
}
