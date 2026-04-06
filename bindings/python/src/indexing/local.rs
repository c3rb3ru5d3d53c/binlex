use crate::Architecture;
use crate::Config;
use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::databases::localdb::{
    CollectionCommentRecord as PyCollectionCommentRecord,
    CollectionTagRecord as PyCollectionTagRecord, SampleStatusRecord as PySampleStatusRecord,
};
use crate::metadata::Attribute as PyAttribute;
use binlex::controlflow::{
    Block as InnerBlock, Function as InnerFunction, Instruction as InnerInstruction,
};
use binlex::indexing::{
    Collection as InnerCollection, CollectionCommentSearchPage as InnerCollectionCommentSearchPage,
    CollectionTagSearchPage as InnerCollectionTagSearchPage, CommentRecord as InnerCommentRecord,
    CommentSearchPage as InnerCommentSearchPage, LocalIndex as InnerClient,
    QueryResult as InnerQueryResult, SearchResult as InnerSearchResult,
    TagRecord as InnerTagRecord, TagSearchPage as InnerTagSearchPage,
};
use binlex::metadata::Attribute as InnerAttribute;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyBytes};
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

#[pyclass]
pub struct QueryResult {
    index: Py<LocalIndex>,
    item: InnerQueryResult,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TagRecord {
    inner: InnerTagRecord,
}

#[pymethods]
impl TagRecord {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }

    pub fn tag(&self) -> String {
        self.inner.tag.clone()
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CommentRecord {
    inner: InnerCommentRecord,
}

#[pymethods]
impl CommentRecord {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }

    pub fn comment(&self) -> String {
        self.inner.comment.clone()
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TagSearchPage {
    inner: InnerTagSearchPage,
}

#[pymethods]
impl TagSearchPage {
    pub fn items(&self) -> Vec<TagRecord> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| TagRecord { inner })
            .collect()
    }

    pub fn page(&self) -> usize {
        self.inner.page
    }

    pub fn page_size(&self) -> usize {
        self.inner.page_size
    }

    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CommentSearchPage {
    inner: InnerCommentSearchPage,
}

#[pymethods]
impl CommentSearchPage {
    pub fn items(&self) -> Vec<CommentRecord> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| CommentRecord { inner })
            .collect()
    }

    pub fn page(&self) -> usize {
        self.inner.page
    }

    pub fn page_size(&self) -> usize {
        self.inner.page_size
    }

    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CollectionTagSearchPage {
    inner: InnerCollectionTagSearchPage,
}

#[pymethods]
impl CollectionTagSearchPage {
    pub fn items(&self) -> Vec<PyCollectionTagRecord> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| PyCollectionTagRecord { inner })
            .collect()
    }

    pub fn page(&self) -> usize {
        self.inner.page
    }

    pub fn page_size(&self) -> usize {
        self.inner.page_size
    }

    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CollectionCommentSearchPage {
    inner: InnerCollectionCommentSearchPage,
}

#[pymethods]
impl CollectionCommentSearchPage {
    pub fn items(&self) -> Vec<PyCollectionCommentRecord> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| PyCollectionCommentRecord { inner })
            .collect()
    }

    pub fn page(&self) -> usize {
        self.inner.page
    }

    pub fn page_size(&self) -> usize {
        self.inner.page_size
    }

    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
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
    pub fn sample_put(&self, data: Bound<'_, PyBytes>) -> PyResult<String> {
        let bytes = data.as_bytes();
        self.inner
            .lock()
            .unwrap()
            .sample_put(bytes)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256)")]
    pub fn sample_get<'py>(
        &self,
        py: Python<'py>,
        sha256: String,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = self
            .inner
            .lock()
            .unwrap()
            .sample_get(&sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (sha256, graph, attributes=None, selector=None, collections=None, corpora=None, username=None), text_signature = "($self, sha256, graph, attributes=None, selector=None, collections=None, corpora=None, username=None)")]
    pub fn graph(
        &self,
        py: Python,
        sha256: String,
        graph: Py<Graph>,
        attributes: Option<Vec<Py<PyAttribute>>>,
        selector: Option<String>,
        collections: Option<Vec<Py<Collection>>>,
        corpora: Option<Vec<String>>,
        username: Option<String>,
    ) -> PyResult<()> {
        let graph_ref = graph.borrow(py);
        let inner_graph = graph_ref.inner.lock().unwrap();
        let attributes = py_to_attributes(py, attributes);
        let collections = py_to_collections(py, collections);
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        let username = username.unwrap_or_else(|| "anonymous".to_string());
        let index = self.inner.lock().unwrap();
        index
            .graph_many_as(
                &corpora,
                &sha256,
                &inner_graph,
                &attributes,
                selector.as_deref(),
                collections.as_deref(),
                &username,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (instruction, vector, sha256, attributes=None, corpora=None, username=None), text_signature = "($self, instruction, vector, sha256, attributes=None, corpora=None, username=None)")]
    pub fn instruction(
        &self,
        py: Python,
        instruction: Py<Instruction>,
        vector: Vec<f32>,
        sha256: String,
        attributes: Option<Vec<Py<PyAttribute>>>,
        corpora: Option<Vec<String>>,
        username: Option<String>,
    ) -> PyResult<()> {
        let attributes = py_to_attributes(py, attributes);
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        let username = username.unwrap_or_else(|| "anonymous".to_string());
        let instruction = instruction.borrow(py);
        let binding = instruction.cfg.borrow(py);
        let inner_graph = binding.inner.lock().unwrap();
        #[allow(mutable_transmutes)]
        #[allow(clippy::all)]
        let inner_ref: _ = unsafe { std::mem::transmute(&*inner_graph) };
        let inner_instruction = InnerInstruction::new(instruction.address, inner_ref)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.inner
            .lock()
            .unwrap()
            .instruction_many_as(
                &corpora,
                &inner_instruction,
                &vector,
                &sha256,
                &attributes,
                &username,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (block, vector, sha256, attributes=None, corpora=None, username=None), text_signature = "($self, block, vector, sha256, attributes=None, corpora=None, username=None)")]
    pub fn block(
        &self,
        py: Python,
        block: Py<Block>,
        vector: Vec<f32>,
        sha256: String,
        attributes: Option<Vec<Py<PyAttribute>>>,
        corpora: Option<Vec<String>>,
        username: Option<String>,
    ) -> PyResult<()> {
        let attributes = py_to_attributes(py, attributes);
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        let username = username.unwrap_or_else(|| "anonymous".to_string());
        let block = block.borrow(py);
        let binding = block.cfg.borrow(py);
        let inner_graph = binding.inner.lock().unwrap();
        let inner_ref: &'static _ = unsafe { std::mem::transmute(&*inner_graph) };
        let inner_block = InnerBlock::new(block.address, inner_ref)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.inner
            .lock()
            .unwrap()
            .block_many_as(
                &corpora,
                &inner_block,
                &vector,
                &sha256,
                &attributes,
                &username,
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (function, vector, sha256, attributes=None, corpora=None, username=None), text_signature = "($self, function, vector, sha256, attributes=None, corpora=None, username=None)")]
    pub fn function(
        &self,
        py: Python,
        function: Py<Function>,
        vector: Vec<f32>,
        sha256: String,
        attributes: Option<Vec<Py<PyAttribute>>>,
        corpora: Option<Vec<String>>,
        username: Option<String>,
    ) -> PyResult<()> {
        let attributes = py_to_attributes(py, attributes);
        let corpora = corpora.unwrap_or_else(|| vec!["default".to_string()]);
        let username = username.unwrap_or_else(|| "anonymous".to_string());
        let function = function.borrow(py);
        let binding = function.cfg.borrow(py);
        let inner_graph = binding.inner.lock().unwrap();
        let inner_ref: &'static _ = unsafe { std::mem::transmute(&*inner_graph) };
        let inner_function = InnerFunction::new(function.address, inner_ref)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        self.inner
            .lock()
            .unwrap()
            .function_many_as(
                &corpora,
                &inner_function,
                &vector,
                &sha256,
                &attributes,
                &username,
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
    pub fn sample_load(&self, corpus: String, sha256: String) -> PyResult<Graph> {
        let graph = self
            .inner
            .lock()
            .unwrap()
            .sample_load(&corpus, &sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Graph::from_inner(graph))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn corpus_list(&self) -> PyResult<Vec<String>> {
        self.inner
            .lock()
            .unwrap()
            .corpus_list()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, corpus, sha256)")]
    pub fn sample_delete(&self, corpus: String, sha256: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sample_delete(&corpus, &sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, corpus)")]
    pub fn corpus_delete(&self, corpus: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .corpus_delete(&corpus)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address, name)")]
    pub fn symbol_add(
        &self,
        sha256: String,
        collection: String,
        address: u64,
        name: String,
    ) -> PyResult<()> {
        let collection = match collection.trim().to_ascii_lowercase().as_str() {
            "function" => InnerCollection::Function,
            "block" => InnerCollection::Block,
            "instruction" => InnerCollection::Instruction,
            _ => return Err(PyValueError::new_err("invalid collection")),
        };
        self.inner
            .lock()
            .unwrap()
            .symbol_add(&sha256, collection, address, &name, "")
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address, name)")]
    pub fn symbol_remove(
        &self,
        sha256: String,
        collection: String,
        address: u64,
        name: String,
    ) -> PyResult<()> {
        let collection = match collection.trim().to_ascii_lowercase().as_str() {
            "function" => InnerCollection::Function,
            "block" => InnerCollection::Block,
            "instruction" => InnerCollection::Instruction,
            _ => return Err(PyValueError::new_err("invalid collection")),
        };
        self.inner
            .lock()
            .unwrap()
            .symbol_remove(&sha256, collection, address, &name)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address, name)")]
    pub fn symbol_replace(
        &self,
        sha256: String,
        collection: String,
        address: u64,
        name: String,
    ) -> PyResult<()> {
        let collection = match collection.trim().to_ascii_lowercase().as_str() {
            "function" => InnerCollection::Function,
            "block" => InnerCollection::Block,
            "instruction" => InnerCollection::Instruction,
            _ => return Err(PyValueError::new_err("invalid collection")),
        };
        self.inner
            .lock()
            .unwrap()
            .symbol_replace(&sha256, collection, address, &name, "")
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, architecture, address, corpus)")]
    pub fn collection_corpus_add(
        &self,
        sha256: String,
        collection: String,
        architecture: String,
        address: u64,
        corpus: String,
    ) -> PyResult<()> {
        let collection = match collection.trim().to_ascii_lowercase().as_str() {
            "function" => InnerCollection::Function,
            "block" => InnerCollection::Block,
            "instruction" => InnerCollection::Instruction,
            _ => return Err(PyValueError::new_err("invalid collection")),
        };
        self.inner
            .lock()
            .unwrap()
            .collection_corpus_add(&sha256, collection, &architecture, address, &corpus, "")
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, architecture, address, corpus)")]
    pub fn collection_corpus_remove(
        &self,
        sha256: String,
        collection: String,
        architecture: String,
        address: u64,
        corpus: String,
    ) -> PyResult<()> {
        let collection = match collection.trim().to_ascii_lowercase().as_str() {
            "function" => InnerCollection::Function,
            "block" => InnerCollection::Block,
            "instruction" => InnerCollection::Instruction,
            _ => return Err(PyValueError::new_err("invalid collection")),
        };
        self.inner
            .lock()
            .unwrap()
            .collection_corpus_remove(&sha256, collection, &architecture, address, &corpus)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, old_name, new_name)")]
    pub fn corpus_rename(&self, old_name: String, new_name: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .corpus_rename(&old_name, &new_name)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, tag)")]
    pub fn sample_tag_add(&self, sha256: String, tag: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sample_tag_add(&sha256, &tag)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, tag)")]
    pub fn sample_tag_remove(&self, sha256: String, tag: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sample_tag_remove(&sha256, &tag)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, tags)")]
    pub fn sample_tag_replace(&self, sha256: String, tags: Vec<String>) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sample_tag_replace(&sha256, &tags)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (query, page=1, page_size=50), text_signature = "($self, query, page=1, page_size=50)")]
    pub fn sample_tag_search(
        &self,
        query: String,
        page: usize,
        page_size: usize,
    ) -> PyResult<TagSearchPage> {
        self.inner
            .lock()
            .unwrap()
            .sample_tag_search(&query, page, page_size)
            .map(|inner| TagSearchPage { inner })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256)")]
    pub fn sample_tag_list(&self, sha256: String) -> PyResult<Vec<String>> {
        self.inner
            .lock()
            .unwrap()
            .sample_tag_list(&sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sha256, comment, timestamp=None), text_signature = "($self, sha256, comment, timestamp=None)")]
    pub fn sample_comment_add(
        &self,
        py: Python,
        sha256: String,
        comment: String,
        timestamp: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .sample_comment_add(&sha256, &comment, timestamp.as_deref())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, comment)")]
    pub fn sample_comment_remove(&self, sha256: String, comment: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sample_comment_remove(&sha256, &comment)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (query, page=1, page_size=50), text_signature = "($self, query, page=1, page_size=50)")]
    pub fn sample_comment_search(
        &self,
        query: String,
        page: usize,
        page_size: usize,
    ) -> PyResult<CommentSearchPage> {
        self.inner
            .lock()
            .unwrap()
            .sample_comment_search(&query, page, page_size)
            .map(|inner| CommentSearchPage { inner })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sha256, comments, timestamp=None), text_signature = "($self, sha256, comments, timestamp=None)")]
    pub fn sample_comment_replace(
        &self,
        py: Python,
        sha256: String,
        comments: Vec<String>,
        timestamp: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .sample_comment_replace(&sha256, &comments, timestamp.as_deref())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256)")]
    pub fn sample_status_get(&self, sha256: String) -> PyResult<Option<PySampleStatusRecord>> {
        self.inner
            .lock()
            .unwrap()
            .sample_status_get(&sha256)
            .map(|value| value.map(|inner| PySampleStatusRecord { inner }))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sha256, status, timestamp=None, id=None, error_message=None), text_signature = "($self, sha256, status, timestamp=None, id=None, error_message=None)")]
    pub fn sample_status_set(
        &self,
        py: Python,
        sha256: String,
        status: &crate::databases::localdb::SampleStatus,
        timestamp: Option<Py<PyAny>>,
        id: Option<String>,
        error_message: Option<String>,
    ) -> PyResult<()> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .sample_status_set(
                &sha256,
                status.inner,
                timestamp.as_deref(),
                id.as_deref(),
                error_message.as_deref(),
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address, tag)")]
    pub fn collection_tag_add(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tag: String,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .collection_tag_add(&sha256, collection.borrow(py).inner, address, &tag, "")
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address, tag)")]
    pub fn collection_tag_remove(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tag: String,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .collection_tag_remove(&sha256, collection.borrow(py).inner, address, &tag)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address, tags)")]
    pub fn collection_tag_replace(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tags: Vec<String>,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .collection_tag_replace(&sha256, collection.borrow(py).inner, address, &tags, "")
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sha256, collection, address, comment, timestamp=None), text_signature = "($self, sha256, collection, address, comment, timestamp=None)")]
    pub fn collection_comment_add(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        comment: String,
        timestamp: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .collection_comment_add(
                &sha256,
                collection.borrow(py).inner,
                address,
                &comment,
                timestamp.as_deref(),
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address, comment)")]
    pub fn collection_comment_remove(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        comment: String,
    ) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .collection_comment_remove(&sha256, collection.borrow(py).inner, address, &comment)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sha256, collection, address, comments, timestamp=None), text_signature = "($self, sha256, collection, address, comments, timestamp=None)")]
    pub fn collection_comment_replace(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        comments: Vec<String>,
        timestamp: Option<Py<PyAny>>,
    ) -> PyResult<()> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .collection_comment_replace(
                &sha256,
                collection.borrow(py).inner,
                address,
                &comments,
                timestamp.as_deref(),
            )
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256)")]
    pub fn sample_status_delete(&self, sha256: String) -> PyResult<()> {
        self.inner
            .lock()
            .unwrap()
            .sample_status_delete(&sha256)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (query, collection=None, page=1, page_size=50), text_signature = "($self, query, collection=None, page=1, page_size=50)")]
    pub fn collection_tag_search(
        &self,
        py: Python,
        query: String,
        collection: Option<Py<Collection>>,
        page: usize,
        page_size: usize,
    ) -> PyResult<CollectionTagSearchPage> {
        self.inner
            .lock()
            .unwrap()
            .collection_tag_search(
                &query,
                collection.map(|value: Py<Collection>| value.borrow(py).inner),
                page,
                page_size,
            )
            .map(|inner| CollectionTagSearchPage { inner })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (query, collection=None, page=1, page_size=50), text_signature = "($self, query, collection=None, page=1, page_size=50)")]
    pub fn collection_comment_search(
        &self,
        py: Python,
        query: String,
        collection: Option<Py<Collection>>,
        page: usize,
        page_size: usize,
    ) -> PyResult<CollectionCommentSearchPage> {
        self.inner
            .lock()
            .unwrap()
            .collection_comment_search(
                &query,
                collection.map(|value: Py<Collection>| value.borrow(py).inner),
                page,
                page_size,
            )
            .map(|inner| CollectionCommentSearchPage { inner })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, sha256, collection, address)")]
    pub fn collection_tag_list(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
    ) -> PyResult<Vec<String>> {
        self.inner
            .lock()
            .unwrap()
            .collection_tag_list(&sha256, collection.borrow(py).inner, address)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (query, top_k=16, page=1), text_signature = "($self, query, top_k=16, page=1)")]
    pub fn search(
        slf: Py<Self>,
        py: Python,
        query: String,
        top_k: usize,
        page: usize,
    ) -> PyResult<Vec<QueryResult>> {
        let hits = slf
            .borrow(py)
            .inner
            .lock()
            .unwrap()
            .search_stream(&query, top_k, page)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(hits
            .into_iter()
            .map(|item| QueryResult {
                index: slf.clone_ref(py),
                item,
            })
            .collect())
    }

    #[pyo3(signature = (corpora, vector, collections=None, architectures=None, limit=10), text_signature = "($self, corpora, vector, collections=[Collection.Block, Collection.Function], architectures=None, limit=10)")]
    pub fn nearest(
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
            .nearest(
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

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        let datetime = py.import("datetime")?;
        let cls = datetime.getattr("datetime")?;
        Ok(cls
            .call_method1("fromisoformat", (self.hit.timestamp().to_rfc3339(),))?
            .into())
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

    pub fn username(&self) -> String {
        self.hit.username().to_string()
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

    pub fn graph(&self, py: Python) -> PyResult<Graph> {
        let index = self.index.borrow(py);
        let graph = index
            .inner
            .lock()
            .unwrap()
            .sample_load(self.hit.corpus(), self.hit.sha256())
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

#[pymethods]
impl QueryResult {
    pub fn score(&self) -> f32 {
        self.item.score()
    }

    pub fn lhs(&self, py: Python) -> Option<SearchResult> {
        self.item.lhs().cloned().map(|hit| SearchResult {
            index: self.index.clone_ref(py),
            hit,
        })
    }

    pub fn rhs(&self, py: Python) -> Option<SearchResult> {
        self.item.rhs().cloned().map(|hit| SearchResult {
            index: self.index.clone_ref(py),
            hit,
        })
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
    m.add_class::<QueryResult>()?;
    m.add_class::<TagRecord>()?;
    m.add_class::<CommentRecord>()?;
    m.add_class::<TagSearchPage>()?;
    m.add_class::<CollectionTagSearchPage>()?;
    m.add_class::<CollectionCommentSearchPage>()?;
    m.add_class::<CommentSearchPage>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.indexing.local", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.indexing.local")?;
    Ok(())
}

fn python_datetime_to_string(py: Python, value: Py<PyAny>) -> PyResult<String> {
    value
        .bind(py)
        .call_method0("isoformat")?
        .extract::<String>()
}

fn python_datetime_from_string(py: Python, value: &str) -> PyResult<Py<PyAny>> {
    let datetime = py.import("datetime")?;
    let cls = datetime.getattr("datetime")?;
    Ok(cls.call_method1("fromisoformat", (value,))?.into())
}

fn option_python_datetime_to_string(
    py: Python,
    value: Option<Py<PyAny>>,
) -> PyResult<Option<String>> {
    value
        .map(|value| python_datetime_to_string(py, value))
        .transpose()
}
