use crate::indexing::local::Collection;
use crate::Config;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;
use std::sync::{Arc, Mutex};

#[pyclass(eq, skip_from_py_object)]
#[derive(Clone, PartialEq)]
pub struct SampleStatus {
    pub inner: binlex::databases::SampleStatus,
}

#[pymethods]
impl SampleStatus {
    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PENDING: Self = Self {
        inner: binlex::databases::SampleStatus::Pending,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const PROCESSING: Self = Self {
        inner: binlex::databases::SampleStatus::Processing,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const COMPLETE: Self = Self {
        inner: binlex::databases::SampleStatus::Complete,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const FAILED: Self = Self {
        inner: binlex::databases::SampleStatus::Failed,
    };

    #[allow(non_upper_case_globals)]
    #[classattr]
    pub const CANCELED: Self = Self {
        inner: binlex::databases::SampleStatus::Canceled,
    };

    pub fn __str__(&self) -> &'static str {
        match self.inner {
            binlex::databases::SampleStatus::Pending => "pending",
            binlex::databases::SampleStatus::Processing => "processing",
            binlex::databases::SampleStatus::Complete => "complete",
            binlex::databases::SampleStatus::Failed => "failed",
            binlex::databases::SampleStatus::Canceled => "canceled",
        }
    }
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SampleStatusRecord {
    pub inner: binlex::databases::SampleStatusRecord,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CollectionTagRecord {
    pub inner: binlex::databases::CollectionTagRecord,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SampleCommentRecord {
    pub inner: binlex::databases::SampleCommentRecord,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CollectionCommentRecord {
    pub inner: binlex::databases::CollectionCommentRecord,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct RoleRecord {
    pub inner: binlex::databases::RoleRecord,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct UserRecord {
    pub inner: binlex::databases::UserRecord,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TokenRecord {
    pub inner: binlex::databases::TokenRecord,
}

#[pymethods]
impl CollectionTagRecord {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }

    pub fn collection(&self) -> Collection {
        Collection {
            inner: self.inner.collection,
        }
    }

    pub fn address(&self) -> u64 {
        self.inner.address
    }

    pub fn tag(&self) -> String {
        self.inner.tag.clone()
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pymethods]
impl SampleCommentRecord {
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

#[pymethods]
impl CollectionCommentRecord {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }

    pub fn collection(&self) -> Collection {
        Collection {
            inner: self.inner.collection,
        }
    }

    pub fn address(&self) -> u64 {
        self.inner.address
    }

    pub fn comment(&self) -> String {
        self.inner.comment.clone()
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pymethods]
impl RoleRecord {
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pymethods]
impl UserRecord {
    pub fn username(&self) -> String {
        self.inner.username.clone()
    }

    pub fn role(&self) -> String {
        self.inner.role.clone()
    }

    pub fn enabled(&self) -> bool {
        self.inner.enabled
    }

    pub fn reserved(&self) -> bool {
        self.inner.reserved
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pymethods]
impl TokenRecord {
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }

    pub fn token(&self) -> String {
        self.inner.token.clone()
    }

    pub fn enabled(&self) -> bool {
        self.inner.enabled
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }

    pub fn expires(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.expires)
    }
}

#[pymethods]
impl SampleStatusRecord {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }

    pub fn status(&self) -> SampleStatus {
        SampleStatus {
            inner: self.inner.status,
        }
    }

    pub fn timestamp(&self, py: Python) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }

    pub fn error_message(&self) -> Option<String> {
        self.inner.error_message.clone()
    }

    pub fn id(&self) -> Option<String> {
        self.inner.id.clone()
    }
}

#[pyclass]
pub struct LocalDB {
    inner: Arc<Mutex<binlex::databases::LocalDB>>,
}

#[pymethods]
impl LocalDB {
    #[new]
    #[pyo3(signature = (config, path=None), text_signature = "(config, path=None)")]
    pub fn new(py: Python, config: Py<Config>, path: Option<String>) -> PyResult<Self> {
        let config = config.borrow(py).inner.lock().unwrap().clone();
        let inner = binlex::databases::LocalDB::with_path(&config, path.as_deref())
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    #[pyo3(text_signature = "($self, sha256)")]
    pub fn sample_status_get(&self, sha256: String) -> PyResult<Option<SampleStatusRecord>> {
        self.inner
            .lock()
            .unwrap()
            .sample_status_get(&sha256)
            .map(|value| value.map(|inner| SampleStatusRecord { inner }))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sha256, status, timestamp, id=None, error_message=None), text_signature = "($self, sha256, status, timestamp, id=None, error_message=None)")]
    pub fn sample_status_set(
        &self,
        py: Python,
        sha256: String,
        status: &SampleStatus,
        timestamp: Py<PyAny>,
        id: Option<String>,
        error_message: Option<String>,
    ) -> PyResult<()> {
        let timestamp = python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .sample_status_set(&binlex::databases::SampleStatusRecord {
                sha256,
                status: status.inner,
                timestamp,
                error_message,
                id,
            })
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

    #[pyo3(signature = (query, page=1, page_size=50), text_signature = "($self, query, page=1, page_size=50)")]
    pub fn sample_comment_search(
        &self,
        query: String,
        page: usize,
        page_size: usize,
    ) -> PyResult<Vec<SampleCommentRecord>> {
        self.inner
            .lock()
            .unwrap()
            .sample_comment_search(&query, page, page_size)
            .map(|page| {
                page.items
                    .into_iter()
                    .map(|inner| SampleCommentRecord { inner })
                    .collect()
            })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (sha256, collection, address, tag, timestamp), text_signature = "($self, sha256, collection, address, tag, timestamp)")]
    pub fn collection_tag_add(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tag: String,
        timestamp: Py<PyAny>,
    ) -> PyResult<()> {
        let timestamp = python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .collection_tag_add(&binlex::databases::CollectionTagRecord {
                sha256,
                collection: collection.borrow(py).inner,
                address,
                tag,
                timestamp,
            })
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

    #[pyo3(signature = (sha256, collection, address, tags, timestamp), text_signature = "($self, sha256, collection, address, tags, timestamp)")]
    pub fn collection_tag_replace(
        &self,
        py: Python,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        tags: Vec<String>,
        timestamp: Py<PyAny>,
    ) -> PyResult<()> {
        let timestamp = python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .collection_tag_replace(
                &sha256,
                collection.borrow(py).inner,
                address,
                &tags,
                &timestamp,
            )
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
    ) -> PyResult<Vec<CollectionTagRecord>> {
        self.inner
            .lock()
            .unwrap()
            .collection_tag_search(
                &query,
                collection.map(|value: Py<Collection>| value.borrow(py).inner),
                page,
                page_size,
            )
            .map(|page| {
                page.items
                    .into_iter()
                    .map(|inner| CollectionTagRecord { inner })
                    .collect()
            })
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

    #[pyo3(signature = (query, collection=None, page=1, page_size=50), text_signature = "($self, query, collection=None, page=1, page_size=50)")]
    pub fn collection_comment_search(
        &self,
        py: Python,
        query: String,
        collection: Option<Py<Collection>>,
        page: usize,
        page_size: usize,
    ) -> PyResult<Vec<CollectionCommentRecord>> {
        self.inner
            .lock()
            .unwrap()
            .collection_comment_search(
                &query,
                collection.map(|value: Py<Collection>| value.borrow(py).inner),
                page,
                page_size,
            )
            .map(|page| {
                page.items
                    .into_iter()
                    .map(|inner| CollectionCommentRecord { inner })
                    .collect()
            })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (name, timestamp=None), text_signature = "($self, name, timestamp=None)")]
    pub fn role_create(
        &self,
        py: Python,
        name: String,
        timestamp: Option<Py<PyAny>>,
    ) -> PyResult<RoleRecord> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .role_create(&name, timestamp.as_deref())
            .map(|inner| RoleRecord { inner })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, name)")]
    pub fn role_get(&self, name: String) -> PyResult<Option<RoleRecord>> {
        self.inner
            .lock()
            .unwrap()
            .role_get(&name)
            .map(|value| value.map(|inner| RoleRecord { inner }))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (query, page=1, limit=50), text_signature = "($self, query, page=1, limit=50)")]
    pub fn role_search(
        &self,
        query: String,
        page: usize,
        limit: usize,
    ) -> PyResult<Vec<RoleRecord>> {
        self.inner
            .lock()
            .unwrap()
            .role_search(&query, page, limit)
            .map(|page| {
                page.items
                    .into_iter()
                    .map(|inner| RoleRecord { inner })
                    .collect::<Vec<_>>()
            })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, name)")]
    pub fn role_delete(&self, name: String) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .role_delete(&name)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (username, role, timestamp=None), text_signature = "($self, username, role, timestamp=None)")]
    pub fn user_create(
        &self,
        py: Python,
        username: String,
        role: String,
        timestamp: Option<Py<PyAny>>,
    ) -> PyResult<(UserRecord, String)> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .user_create(&username, &role, timestamp.as_deref())
            .map(|(inner, plaintext)| (UserRecord { inner }, plaintext))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, username)")]
    pub fn user_disable(&self, username: String) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .user_disable(&username)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, username)")]
    pub fn user_enable(&self, username: String) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .user_enable(&username)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (username, timestamp=None), text_signature = "($self, username, timestamp=None)")]
    pub fn user_reset(
        &self,
        py: Python,
        username: String,
        timestamp: Option<Py<PyAny>>,
    ) -> PyResult<String> {
        let timestamp = option_python_datetime_to_string(py, timestamp)?;
        self.inner
            .lock()
            .unwrap()
            .user_reset(&username, timestamp.as_deref())
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, username)")]
    pub fn user_get(&self, username: String) -> PyResult<Option<UserRecord>> {
        self.inner
            .lock()
            .unwrap()
            .user_get(&username)
            .map(|value| value.map(|inner| UserRecord { inner }))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (query, page=1, limit=50), text_signature = "($self, query, page=1, limit=50)")]
    pub fn user_search(
        &self,
        query: String,
        page: usize,
        limit: usize,
    ) -> PyResult<Vec<UserRecord>> {
        self.inner
            .lock()
            .unwrap()
            .user_search(&query, page, limit)
            .map(|page| {
                page.items
                    .into_iter()
                    .map(|inner| UserRecord { inner })
                    .collect::<Vec<_>>()
            })
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, api_key)")]
    pub fn auth_check(&self, api_key: String) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .auth_check(&api_key)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, api_key)")]
    pub fn auth_user(&self, api_key: String) -> PyResult<Option<UserRecord>> {
        self.inner
            .lock()
            .unwrap()
            .auth_user(&api_key)
            .map(|value| value.map(|inner| UserRecord { inner }))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(signature = (ttl_seconds), text_signature = "($self, ttl_seconds)")]
    pub fn token_create(&self, ttl_seconds: u64) -> PyResult<(TokenRecord, String)> {
        self.inner
            .lock()
            .unwrap()
            .token_create(ttl_seconds)
            .map(|(inner, plaintext)| (TokenRecord { inner }, plaintext))
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, token)")]
    pub fn token_check(&self, token: String) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .token_check(&token)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self, id)")]
    pub fn token_disable(&self, id: String) -> PyResult<bool> {
        self.inner
            .lock()
            .unwrap()
            .token_disable(&id)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }

    #[pyo3(text_signature = "($self)")]
    pub fn token_clear(&self) -> PyResult<usize> {
        self.inner
            .lock()
            .unwrap()
            .token_clear()
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))
    }
}

#[pymodule]
#[pyo3(name = "localdb")]
pub fn localdb_init(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<LocalDB>()?;
    m.add_class::<SampleStatus>()?;
    m.add_class::<SampleStatusRecord>()?;
    m.add_class::<CollectionTagRecord>()?;
    m.add_class::<SampleCommentRecord>()?;
    m.add_class::<CollectionCommentRecord>()?;
    m.add_class::<RoleRecord>()?;
    m.add_class::<UserRecord>()?;
    m.add_class::<TokenRecord>()?;
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
