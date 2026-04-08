use crate::controlflow::Graph;
use crate::indexing::local::Collection;
use crate::Config;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;

use binlex::clients::{
    Server as InnerServer, Web as InnerWeb, WebQueryResult as InnerQueryResult,
    WebResult as InnerResult,
};

#[pyclass(name = "Server")]
pub struct Server {
    inner: InnerServer,
}

#[pyclass(name = "Web")]
pub struct Web {
    inner: InnerWeb,
}

#[pyclass]
pub struct SearchResult {
    hit: InnerResult,
}

#[pyclass]
pub struct QueryResult {
    item: InnerQueryResult,
}

#[pymethods]
impl Server {
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
        let inner =
            InnerServer::new(inner_config, url, verify, compression).map_err(map_server_error)?;
        Ok(Self { inner })
    }

    pub fn url(&self) -> String {
        self.inner.url().to_string()
    }

    pub fn verify(&self) -> bool {
        self.inner.verify()
    }

    pub fn compression(&self) -> bool {
        self.inner.compression()
    }

    pub fn health(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let value = serde_json::to_value(self.inner.health().map_err(map_server_error)?)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        json_value_to_python(py, &value)
    }

    #[pyo3(signature = (path, magic=None, architecture=None))]
    pub fn analyze_file(
        &self,
        py: Python<'_>,
        path: String,
        magic: Option<String>,
        architecture: Option<String>,
    ) -> PyResult<Py<Graph>> {
        let magic = parse_magic(magic)?;
        let architecture = parse_architecture(architecture)?;
        let graph = self
            .inner
            .analyze_file(path, magic, architecture)
            .map_err(map_server_error)?;
        Py::new(
            py,
            Graph {
                inner: std::sync::Arc::new(std::sync::Mutex::new(graph)),
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
    ) -> PyResult<Py<Graph>> {
        let magic = parse_magic(magic)?;
        let architecture = parse_architecture(architecture)?;
        let graph = self
            .inner
            .analyze_bytes(&data, magic, architecture)
            .map_err(map_server_error)?;
        Py::new(
            py,
            Graph {
                inner: std::sync::Arc::new(std::sync::Mutex::new(graph)),
            },
        )
    }
}

#[pymethods]
impl Web {
    #[new]
    #[pyo3(signature = (config, url=None, verify=None, api_key=None))]
    pub fn new(
        py: Python<'_>,
        config: Py<Config>,
        url: Option<String>,
        verify: Option<bool>,
        api_key: Option<String>,
    ) -> PyResult<Self> {
        let inner_config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = InnerWeb::new(inner_config, url, verify, api_key).map_err(map_web_error)?;
        Ok(Self { inner })
    }

    pub fn url(&self) -> String {
        self.inner.url().to_string()
    }

    pub fn verify(&self) -> bool {
        self.inner.verify()
    }

    pub fn api_key(&self) -> Option<String> {
        self.inner.api_key().map(ToString::to_string)
    }

    pub fn set_api_key(&mut self, api_key: Option<String>) {
        self.inner.set_api_key(api_key);
    }

    #[pyo3(signature = (sha256, graph, collections=None, corpora=None))]
    pub fn index_graph(
        &self,
        sha256: String,
        graph: &Graph,
        collections: Option<Vec<Py<Collection>>>,
        corpora: Option<Vec<String>>,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collections = collections
            .unwrap_or_default()
            .into_iter()
            .map(|item| item.borrow(py).inner)
            .collect::<Vec<_>>();
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        Ok(self
            .inner
            .index_graph(
                &sha256,
                &graph.inner.lock().unwrap(),
                &collections,
                &corpora,
            )
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (sha256, function, corpora=None))]
    pub fn index_function(
        &self,
        sha256: String,
        function: &crate::controlflow::Function,
        corpora: Option<Vec<String>>,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        Ok(self
            .inner
            .index_function(
                &sha256,
                &function.with_inner_function(py, |inner| Ok(inner.clone()))?,
                &corpora,
            )
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (sha256, block, corpora=None))]
    pub fn index_block(
        &self,
        sha256: String,
        block: &crate::controlflow::Block,
        corpora: Option<Vec<String>>,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        Ok(self
            .inner
            .index_block(
                &sha256,
                &block.with_inner_block(py, |inner| Ok(inner.clone()))?,
                &corpora,
            )
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (sha256, instruction, corpora=None))]
    pub fn index_instruction(
        &self,
        sha256: String,
        instruction: &crate::controlflow::Instruction,
        corpora: Option<Vec<String>>,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        Ok(self
            .inner
            .index_instruction(
                &sha256,
                &instruction.with_inner_instruction(py, |inner| Ok(inner.clone()))?,
                &corpora,
            )
            .map_err(map_web_error)?
            .ok)
    }

    pub fn commit_index(&self) -> PyResult<bool> {
        Ok(self.inner.commit_index().map_err(map_web_error)?.ok)
    }

    pub fn clear_index(&self) -> PyResult<bool> {
        Ok(self.inner.clear_index().map_err(map_web_error)?.ok)
    }

    pub fn collection_tags(
        &self,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        py: Python<'_>,
    ) -> PyResult<Vec<String>> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .collection_tags(&sha256, collection, address)
            .map_err(map_web_error)?
            .tags)
    }

    pub fn add_collection_tag(
        &self,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tag: String,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .add_collection_tag(&sha256, collection, address, &tag)
            .map_err(map_web_error)?
            .ok)
    }

    pub fn remove_collection_tag(
        &self,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tag: String,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .remove_collection_tag(&sha256, collection, address, &tag)
            .map_err(map_web_error)?
            .ok)
    }

    pub fn replace_collection_tags(
        &self,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tags: Vec<String>,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .replace_collection_tags(&sha256, collection, address, &tags)
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (query, top_k=10, page=1))]
    pub fn search(&self, query: String, top_k: usize, page: usize) -> PyResult<Vec<QueryResult>> {
        Ok(self
            .inner
            .search(&query, top_k, page)
            .map_err(map_web_error)?
            .into_iter()
            .map(|item| QueryResult { item })
            .collect())
    }
}

#[pymethods]
impl SearchResult {
    pub fn corpus(&self) -> String {
        self.hit.corpus().to_string()
    }

    pub fn corpora(&self) -> Vec<String> {
        self.hit.corpora().to_vec()
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

    pub fn size(&self) -> u64 {
        self.hit.size()
    }

    pub fn timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let datetime = py.import("datetime")?;
        let cls = datetime.getattr("datetime")?;
        Ok(cls
            .call_method1("fromisoformat", (self.hit.timestamp().to_rfc3339(),))?
            .into())
    }

    pub fn symbol(&self) -> Option<String> {
        self.hit.symbol().map(ToString::to_string)
    }

    pub fn architecture(&self) -> String {
        self.hit.architecture().to_string()
    }

    pub fn embedding(&self) -> String {
        self.hit.embedding().to_string()
    }

    pub fn embeddings(&self) -> u64 {
        self.hit.embeddings()
    }

    pub fn collection(&self) -> Collection {
        Collection {
            inner: self.hit.collection(),
        }
    }

    pub fn vector(&self) -> Vec<f32> {
        self.hit.vector().to_vec()
    }

    pub fn json(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match self.hit.json() {
            Some(value) => {
                let json_module = py.import("json")?;
                let text = serde_json::to_string(value)
                    .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
                Ok(Some(json_module.call_method1("loads", (text,))?.into()))
            }
            None => Ok(None),
        }
    }
}

#[pymethods]
impl QueryResult {
    pub fn lhs(&self) -> Option<SearchResult> {
        self.item.lhs().cloned().map(|hit| SearchResult { hit })
    }

    pub fn rhs(&self) -> Option<SearchResult> {
        self.item.rhs().cloned().map(|hit| SearchResult { hit })
    }

    pub fn score(&self) -> f32 {
        self.item.score()
    }
}

fn map_web_error(error: binlex::clients::WebError) -> PyErr {
    match error {
        binlex::clients::WebError::InvalidConfiguration(message) => PyValueError::new_err(message),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

fn map_server_error(error: binlex::clients::Error) -> PyErr {
    match error {
        binlex::clients::Error::InvalidConfiguration(message) => PyValueError::new_err(message),
        other => PyRuntimeError::new_err(other.to_string()),
    }
}

fn parse_magic(value: Option<String>) -> PyResult<Option<binlex::Magic>> {
    match value {
        Some(value) if value.eq_ignore_ascii_case("unknown") => Ok(None),
        Some(value) => value
            .parse::<binlex::Magic>()
            .map(Some)
            .map_err(|error| PyValueError::new_err(error.to_string())),
        None => Ok(None),
    }
}

fn parse_architecture(value: Option<String>) -> PyResult<Option<binlex::Architecture>> {
    match value {
        Some(value) if value.eq_ignore_ascii_case("unknown") => Ok(None),
        Some(value) => binlex::Architecture::from_string(&value)
            .map(Some)
            .map_err(|error| PyValueError::new_err(error.to_string())),
        None => Ok(None),
    }
}

fn json_value_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let json = py.import("json")?;
    let text =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(json.call_method1("loads", (text,))?.unbind())
}

#[pymodule]
#[pyo3(name = "clients")]
pub fn clients_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Server>()?;
    m.add_class::<Web>()?;
    m.add_class::<SearchResult>()?;
    m.add_class::<QueryResult>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.clients", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.clients")?;
    Ok(())
}
