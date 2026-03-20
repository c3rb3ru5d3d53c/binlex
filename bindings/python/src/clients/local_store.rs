use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::Architecture;
use crate::Config;
use binlex::clients::local_store::{
    Client as InnerClient, Collection as InnerCollection, SearchHit as InnerSearchHit,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::{Arc, Mutex};

#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, PartialEq)]
pub struct Collection {
    pub inner: InnerCollection,
}

#[pymethods]
impl Collection {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Instruction: Self = Self {
        inner: InnerCollection::Instruction,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Block: Self = Self {
        inner: InnerCollection::Block,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const Function: Self = Self {
        inner: InnerCollection::Function,
    };

    pub fn __str__(&self) -> String {
        self.inner.to_string()
    }
}

#[pyclass]
pub struct LocalStore {
    pub inner: Arc<Mutex<InnerClient>>,
}

#[pyclass]
pub struct SearchResult {
    store: Py<LocalStore>,
    hit: InnerSearchHit,
}

#[pymethods]
impl LocalStore {
    #[new]
    #[pyo3(text_signature = "(root, config)")]
    pub fn new(root: String, py: Python, config: Py<Config>) -> PyResult<Self> {
        let config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerClient::new(root, config)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self, data)")]
    pub fn put(&self, data: Bound<'_, PyBytes>) -> PyResult<String> {
        let bytes = data.as_bytes();
        self.inner
            .lock()
            .unwrap()
            .put(bytes)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256)")]
    pub fn get<'py>(&self, py: Python<'py>, sha256: String) -> PyResult<Bound<'py, PyBytes>> {
        let data = self
            .inner
            .lock()
            .unwrap()
            .get(&sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (corpus, sha256, graph, attributes=None), text_signature = "($self, corpus, sha256, graph, attributes=None)")]
    pub fn index(
        &self,
        py: Python,
        corpus: String,
        sha256: String,
        graph: Py<Graph>,
        attributes: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        let graph_ref = graph.borrow(py);
        let inner_graph = graph_ref.inner.lock().unwrap();
        let attributes = attributes
            .map(|value| py_to_json_value(py, value))
            .transpose()?;
        self.inner
            .lock()
            .unwrap()
            .index_json_attributes(&corpus, &sha256, &inner_graph, attributes)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, corpus, sha256)")]
    pub fn graph(&self, corpus: String, sha256: String) -> PyResult<Graph> {
        let graph = self
            .inner
            .lock()
            .unwrap()
            .graph(&corpus, &sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Graph::from_inner(graph))
    }

    #[pyo3(signature = (corpus, collection, architecture, vector, limit=10), text_signature = "($self, corpus, collection, architecture, vector, limit=10)")]
    pub fn search(
        slf: Py<Self>,
        py: Python,
        corpus: String,
        collection: Py<Collection>,
        architecture: Py<Architecture>,
        vector: Vec<f32>,
        limit: usize,
    ) -> PyResult<Vec<SearchResult>> {
        let collection = collection.borrow(py).inner;
        let architecture = architecture.borrow(py).inner;
        let hits = slf
            .borrow(py)
            .inner
            .lock()
            .unwrap()
            .search(&corpus, collection, architecture, &vector, limit)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(hits
            .into_iter()
            .map(|hit| SearchResult {
                store: slf.clone_ref(py),
                hit,
            })
            .collect())
    }
}

#[pymethods]
impl SearchResult {
    #[getter]
    pub fn score(&self) -> f32 {
        self.hit.score
    }

    #[getter]
    pub fn sha256(&self) -> String {
        self.hit.sha256.clone()
    }

    #[getter]
    pub fn address(&self) -> u64 {
        self.hit.address
    }

    #[getter]
    pub fn object_id(&self) -> String {
        self.hit.object_id.clone()
    }

    #[getter]
    pub fn architecture(&self) -> String {
        self.hit.architecture.clone()
    }

    #[getter]
    pub fn collection(&self) -> Collection {
        Collection {
            inner: self.hit.collection,
        }
    }

    pub fn graph(&self, py: Python) -> PyResult<Graph> {
        let store = self.store.borrow(py);
        let graph = store
            .inner
            .lock()
            .unwrap()
            .graph(&self.hit.corpus, &self.hit.sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Graph::from_inner(graph))
    }

    pub fn function(&self, py: Python) -> PyResult<Option<Function>> {
        if self.hit.collection != InnerCollection::Function {
            return Ok(None);
        }
        let graph = Py::new(py, self.graph(py)?)?;
        Ok(Function::new(self.hit.address, graph).ok())
    }

    pub fn block(&self, py: Python) -> PyResult<Option<Block>> {
        if self.hit.collection != InnerCollection::Block {
            return Ok(None);
        }
        let graph = Py::new(py, self.graph(py)?)?;
        Ok(Block::new(self.hit.address, graph).ok())
    }

    pub fn instruction(&self, py: Python) -> PyResult<Option<Instruction>> {
        if self.hit.collection != InnerCollection::Instruction {
            return Ok(None);
        }
        let graph = Py::new(py, self.graph(py)?)?;
        Ok(Instruction::new(self.hit.address, graph).ok())
    }
}

fn py_to_json_value(py: Python, value: Py<PyAny>) -> PyResult<serde_json::Value> {
    let json = py.import("json")?;
    let dumped = json.call_method1("dumps", (value,))?;
    let string = dumped.extract::<String>()?;
    serde_json::from_str(&string).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pymodule]
#[pyo3(name = "local_store")]
pub fn local_store_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Collection>()?;
    m.add_class::<LocalStore>()?;
    m.add_class::<SearchResult>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.clients.local_store", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.clients.local_store")?;
    Ok(())
}
