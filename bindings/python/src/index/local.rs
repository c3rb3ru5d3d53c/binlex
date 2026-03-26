use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::metadata::Attribute as PyAttribute;
use crate::Architecture;
use crate::Config;
use binlex::index::{
    Collection as InnerCollection, LocalIndex as InnerClient, SearchResult as InnerSearchResult,
};
use binlex::metadata::Attribute as InnerAttribute;
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
pub struct LocalIndex {
    pub inner: Arc<Mutex<InnerClient>>,
}

#[pyclass]
pub struct SearchResult {
    index: Py<LocalIndex>,
    hit: InnerSearchResult,
}

#[pymethods]
impl LocalIndex {
    #[new]
    #[pyo3(signature = (config, directory=None, dimensions=None), text_signature = "(config, directory=None, dimensions=None)")]
    pub fn new(
        py: Python,
        config: Py<Config>,
        directory: Option<String>,
        dimensions: Option<usize>,
    ) -> PyResult<Self> {
        let config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = match (directory, dimensions) {
            (None, None) => InnerClient::new(config)
                .map_err(|error| PyValueError::new_err(error.to_string()))?,
            (directory, dimensions) => {
                InnerClient::with_options(config, directory.map(Into::into), dimensions)
                    .map_err(|error| PyValueError::new_err(error.to_string()))?
            }
        };
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

    #[pyo3(signature = (sha256, graph, attributes=None, selector=None, collections=None, corpus=None, corpora=None), text_signature = "($self, sha256, graph, attributes=None, selector=None, collections=None, corpus=None, corpora=None)")]
    pub fn graph(
        &self,
        py: Python,
        sha256: String,
        graph: Py<Graph>,
        attributes: Option<Vec<Py<PyAttribute>>>,
        selector: Option<String>,
        collections: Option<Vec<Py<Collection>>>,
        corpus: Option<String>,
        corpora: Option<Vec<String>>,
    ) -> PyResult<()> {
        if corpus.is_some() == corpora.is_some() {
            return Err(PyRuntimeError::new_err(
                "provide exactly one of corpus or corpora",
            ));
        }
        let graph_ref = graph.borrow(py);
        let inner_graph = graph_ref.inner.lock().unwrap();
        let attributes = py_to_attributes(py, attributes);
        let collections = py_to_collections(py, collections);
        let index = self.inner.lock().unwrap();
        match (corpus, corpora) {
            (Some(corpus), None) => index
                .graph(
                    &corpus,
                    &sha256,
                    &inner_graph,
                    &attributes,
                    selector.as_deref(),
                    collections.as_deref(),
                )
                .map_err(|error| PyRuntimeError::new_err(error.to_string())),
            (None, Some(corpora)) => index
                .graph_many(
                    &corpora,
                    &sha256,
                    &inner_graph,
                    &attributes,
                    selector.as_deref(),
                    collections.as_deref(),
                )
                .map_err(|error| PyRuntimeError::new_err(error.to_string())),
            _ => Err(PyRuntimeError::new_err(
                "provide exactly one of corpus or corpora",
            )),
        }
    }

    #[pyo3(signature = (corpus, collection, architecture, vector, sha256, address), text_signature = "($self, corpus, collection, architecture, vector, sha256, address)")]
    pub fn vector(
        &self,
        py: Python,
        corpus: String,
        collection: Py<Collection>,
        architecture: Py<Architecture>,
        vector: Vec<f32>,
        sha256: String,
        address: u64,
    ) -> PyResult<()> {
        let collection = collection.borrow(py).inner;
        let architecture = architecture.borrow(py).inner;
        self.inner
            .lock()
            .unwrap()
            .vector(&corpus, collection, architecture, &vector, &sha256, address)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (corpora, collection, architecture, vector, sha256, address), text_signature = "($self, corpora, collection, architecture, vector, sha256, address)")]
    pub fn vector_many(
        &self,
        py: Python,
        corpora: Vec<String>,
        collection: Py<Collection>,
        architecture: Py<Architecture>,
        vector: Vec<f32>,
        sha256: String,
        address: u64,
    ) -> PyResult<()> {
        let collection = collection.borrow(py).inner;
        let architecture = architecture.borrow(py).inner;
        self.inner
            .lock()
            .unwrap()
            .vector_many(
                &corpora,
                collection,
                architecture,
                &vector,
                &sha256,
                address,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (corpora, architecture, vector, sha256, address, attributes=None), text_signature = "($self, corpora, architecture, vector, sha256, address, attributes=None)")]
    pub fn instruction(
        &self,
        py: Python,
        corpora: Vec<String>,
        architecture: Py<Architecture>,
        vector: Vec<f32>,
        sha256: String,
        address: u64,
        attributes: Option<Vec<Py<PyAttribute>>>,
    ) -> PyResult<()> {
        let architecture = architecture.borrow(py).inner;
        let attributes = py_to_attributes(py, attributes);
        self.inner
            .lock()
            .unwrap()
            .instruction(
                &corpora,
                architecture,
                &vector,
                &sha256,
                address,
                &attributes,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (corpora, architecture, vector, sha256, address, attributes=None), text_signature = "($self, corpora, architecture, vector, sha256, address, attributes=None)")]
    pub fn block(
        &self,
        py: Python,
        corpora: Vec<String>,
        architecture: Py<Architecture>,
        vector: Vec<f32>,
        sha256: String,
        address: u64,
        attributes: Option<Vec<Py<PyAttribute>>>,
    ) -> PyResult<()> {
        let architecture = architecture.borrow(py).inner;
        let attributes = py_to_attributes(py, attributes);
        self.inner
            .lock()
            .unwrap()
            .block(
                &corpora,
                architecture,
                &vector,
                &sha256,
                address,
                &attributes,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (corpora, architecture, vector, sha256, address, attributes=None), text_signature = "($self, corpora, architecture, vector, sha256, address, attributes=None)")]
    pub fn function(
        &self,
        py: Python,
        corpora: Vec<String>,
        architecture: Py<Architecture>,
        vector: Vec<f32>,
        sha256: String,
        address: u64,
        attributes: Option<Vec<Py<PyAttribute>>>,
    ) -> PyResult<()> {
        let architecture = architecture.borrow(py).inner;
        let attributes = py_to_attributes(py, attributes);
        self.inner
            .lock()
            .unwrap()
            .function(
                &corpora,
                architecture,
                &vector,
                &sha256,
                address,
                &attributes,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn commit(&self) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .commit()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn clear(&self) {
        self.inner.lock().unwrap().clear();
    }

    #[pyo3(text_signature = "($self, corpus, sha256)")]
    pub fn load(&self, corpus: String, sha256: String) -> PyResult<Graph> {
        let graph = self
            .inner
            .lock()
            .unwrap()
            .load(&corpus, &sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Graph::from_inner(graph))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn corpora(&self) -> PyResult<Vec<String>> {
        self.inner
            .lock()
            .unwrap()
            .corpora()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, corpus, sha256)")]
    pub fn delete(&self, corpus: String, sha256: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .delete(&corpus, &sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, corpus)")]
    pub fn delete_corpus(&self, corpus: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .delete_corpus(&corpus)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (corpora, vector, collections=None, architectures=None, limit=10), text_signature = "($self, corpora, vector, collections=[Collection.Block, Collection.Function], architectures=None, limit=10)")]
    pub fn search(
        slf: Py<Self>,
        py: Python,
        corpora: Vec<String>,
        vector: Vec<f32>,
        collections: Option<Vec<Py<Collection>>>,
        architectures: Option<Vec<Py<Architecture>>>,
        limit: usize,
    ) -> PyResult<Vec<SearchResult>> {
        let collections = collections.map(|collections| {
            collections
                .into_iter()
                .map(|collection| collection.borrow(py).inner)
                .collect::<Vec<_>>()
        });
        let architectures = architectures
            .unwrap_or_default()
            .into_iter()
            .map(|architecture| architecture.borrow(py).inner)
            .collect::<Vec<_>>();
        let hits = slf
            .borrow(py)
            .inner
            .lock()
            .unwrap()
            .search(
                &corpora,
                &vector,
                collections.as_deref(),
                &architectures,
                limit,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(hits
            .into_iter()
            .map(|hit| SearchResult {
                index: slf.clone_ref(py),
                hit,
            })
            .collect())
    }
}

#[pymethods]
impl SearchResult {
    pub fn corpus(&self) -> String {
        self.hit.corpus().to_string()
    }

    pub fn score(&self) -> f32 {
        self.hit.score()
    }

    pub fn sha256(&self) -> String {
        self.hit.sha256().to_string()
    }

    pub fn address(&self) -> u64 {
        self.hit.address()
    }

    pub fn object_id(&self) -> String {
        self.hit.object_id().to_string()
    }

    pub fn symbol(&self) -> Option<String> {
        self.hit.symbol().map(ToString::to_string)
    }

    pub fn attributes(&self, py: Python) -> PyResult<Py<PyAny>> {
        let json_module = py.import("json")?;
        let value = serde_json::to_string(self.hit.attributes())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(json_module.call_method1("loads", (value,))?.into())
    }

    pub fn architecture(&self) -> String {
        self.hit.architecture().to_string()
    }

    pub fn collection(&self) -> Collection {
        Collection {
            inner: self.hit.collection(),
        }
    }

    pub fn graph(&self, py: Python) -> PyResult<Graph> {
        let index = self.index.borrow(py);
        let graph = index
            .inner
            .lock()
            .unwrap()
            .load(self.hit.corpus(), self.hit.sha256())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Graph::from_inner(graph))
    }

    pub fn function(&self, py: Python) -> PyResult<Option<Function>> {
        if self.hit.collection() != InnerCollection::Function {
            return Ok(None);
        }
        let graph = Py::new(py, self.graph(py)?)?;
        Ok(Function::new(self.hit.address(), graph).ok())
    }

    pub fn block(&self, py: Python) -> PyResult<Option<Block>> {
        if self.hit.collection() != InnerCollection::Block {
            return Ok(None);
        }
        let graph = Py::new(py, self.graph(py)?)?;
        Ok(Block::new(self.hit.address(), graph).ok())
    }

    pub fn instruction(&self, py: Python) -> PyResult<Option<Instruction>> {
        if self.hit.collection() != InnerCollection::Instruction {
            return Ok(None);
        }
        let graph = Py::new(py, self.graph(py)?)?;
        Ok(Instruction::new(self.hit.address(), graph).ok())
    }
}

fn py_to_attributes(py: Python, attributes: Option<Vec<Py<PyAttribute>>>) -> Vec<InnerAttribute> {
    attributes
        .unwrap_or_default()
        .into_iter()
        .map(|item| item.borrow(py).inner.clone())
        .collect()
}

fn py_to_collections(
    py: Python,
    collections: Option<Vec<Py<Collection>>>,
) -> Option<Vec<InnerCollection>> {
    collections.map(|items| {
        items
            .into_iter()
            .map(|item| item.borrow(py).inner)
            .collect::<Vec<_>>()
    })
}

#[pymodule]
#[pyo3(name = "local")]
pub fn local_init(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Collection>()?;
    m.add_class::<LocalIndex>()?;
    m.add_class::<SearchResult>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.index.local", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.index.local")?;
    Ok(())
}
