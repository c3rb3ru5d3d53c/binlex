use binlex::databases::LanceDB as InnerLanceDb;
use pyo3::prelude::*;

#[pyclass(name = "LanceDB")]
pub struct LanceDB {
    inner: InnerLanceDb,
}

#[pymethods]
impl LanceDB {
    #[new]
    pub fn new(root: String) -> PyResult<Self> {
        let inner = InnerLanceDb::new(root)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        Ok(Self { inner })
    }

    #[getter]
    pub fn root(&self) -> String {
        self.inner.root().display().to_string()
    }

    pub fn table_names(&self) -> PyResult<Vec<String>> {
        self.inner
            .table_names()
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn table_dimensions_by_name(&self, table_name: String) -> PyResult<Option<usize>> {
        self.inner
            .table_dimensions_by_name(&table_name)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }
}

#[pymodule]
#[pyo3(name = "lancedb")]
pub fn lancedb_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LanceDB>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.databases.lancedb", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.databases.lancedb")?;
    Ok(())
}
