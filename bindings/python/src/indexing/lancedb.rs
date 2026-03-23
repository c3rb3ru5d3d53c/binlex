use crate::index::local::Collection;
use crate::Architecture;
use binlex::databases::{LanceDB as InnerLanceDb, LanceRow as InnerLanceRow};
use pyo3::prelude::*;
use pyo3::types::PyDict;

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

    pub fn upsert(
        &self,
        py: Python<'_>,
        corpus: String,
        collection: Py<Collection>,
        architecture: Py<Architecture>,
        object_id: String,
        vector: Vec<f32>,
        occurrences: Py<PyAny>,
    ) -> PyResult<()> {
        let _ = &corpus;
        let collection = collection.borrow(py).inner;
        let architecture = architecture.borrow(py).inner.to_string();
        let occurrences_json = python_to_json_string(py, occurrences)?;
        self.inner
            .upsert(
                collection,
                &architecture,
                &object_id,
                &vector,
                &occurrences_json,
            )
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    pub fn upsert_rows(
        &self,
        py: Python<'_>,
        corpus: String,
        collection: Py<Collection>,
        architecture: Py<Architecture>,
        rows: Vec<Py<PyAny>>,
    ) -> PyResult<()> {
        let _ = &corpus;
        let collection = collection.borrow(py).inner;
        let architecture = architecture.borrow(py).inner.to_string();
        let rows = rows
            .into_iter()
            .map(|row| row_from_python(py, row))
            .collect::<PyResult<Vec<_>>>()?;
        self.inner
            .upsert_rows(collection, &architecture, &rows)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (corpus, collection, architecture, vector, limit=10))]
    pub fn search(
        &self,
        py: Python<'_>,
        corpus: String,
        collection: Py<Collection>,
        architecture: Py<Architecture>,
        vector: Vec<f32>,
        limit: usize,
    ) -> PyResult<Vec<Py<PyDict>>> {
        let _ = &corpus;
        let collection = collection.borrow(py).inner;
        let architecture = architecture.borrow(py).inner.to_string();
        let rows = self
            .inner
            .search(collection, &architecture, &vector, limit)
            .map_err(|error| pyo3::exceptions::PyRuntimeError::new_err(error.to_string()))?;
        rows.iter().map(|row| row_to_python(py, row)).collect()
    }
}

fn python_to_json_string(py: Python<'_>, value: Py<PyAny>) -> PyResult<String> {
    let json = py.import("json")?;
    json.call_method1("dumps", (value,))?.extract()
}

fn row_from_python(py: Python<'_>, row: Py<PyAny>) -> PyResult<InnerLanceRow> {
    let row = row.bind(py);
    let dict = row
        .cast::<PyDict>()
        .map_err(|_| pyo3::exceptions::PyTypeError::new_err("rows must contain dict entries"))?;
    let object_id = dict
        .get_item("object_id")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("row is missing object_id"))?
        .extract()?;
    let vector = dict
        .get_item("vector")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("row is missing vector"))?
        .extract()?;
    let occurrences = dict
        .get_item("occurrences")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("row is missing occurrences"))?;
    let json = python_to_json_string(py, occurrences.unbind())?;
    Ok(InnerLanceRow {
        object_id,
        occurrences_json: json,
        vector,
    })
}

fn row_to_python(py: Python<'_>, row: &InnerLanceRow) -> PyResult<Py<PyDict>> {
    let dict = PyDict::new(py);
    let json = py.import("json")?;
    let occurrences = json.call_method1("loads", (&row.occurrences_json,))?;
    dict.set_item("object_id", &row.object_id)?;
    dict.set_item("occurrences", occurrences)?;
    dict.set_item("vector", &row.vector)?;
    Ok(dict.unbind())
}

#[pymodule]
#[pyo3(name = "lancedb")]
pub fn lancedb_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LanceDB>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.indexing.lancedb", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.indexing.lancedb")?;
    Ok(())
}
