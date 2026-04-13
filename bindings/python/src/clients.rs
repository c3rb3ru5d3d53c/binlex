use crate::controlflow::{
    BlockJsonDeserializer, FunctionJsonDeserializer, Graph, InstructionJsonDeserializer,
};
use crate::indexing::local::Collection;
use crate::Config;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyAny;
use serde_json::Value;

use binlex::clients::{
    Server as InnerServer, Web as InnerWeb, WebAdminCommentsResponse as InnerAdminCommentsResponse,
    WebAdminPasswordResetResponse as InnerAdminPasswordResetResponse,
    WebAdminUserCreateResponse as InnerAdminUserCreateResponse,
    WebAuthSessionResponse as InnerAuthSessionResponse,
    WebAuthUserResponse as InnerAuthUserResponse, WebCaptchaResponse as InnerCaptchaResponse,
    WebCollectionTagSearchItemResponse as InnerCollectionTagSearchItemResponse,
    WebCollectionTagSearchResponse as InnerCollectionTagSearchResponse,
    WebCorporaCatalogResponse as InnerCorporaCatalogResponse,
    WebCorporaResponse as InnerCorporaResponse,
    WebEntityCommentResponse as InnerEntityCommentResponse,
    WebEntityCommentsResponse as InnerEntityCommentsResponse,
    WebKeyRegenerateResponse as InnerKeyRegenerateResponse,
    WebMetadataItemResponse as InnerMetadataItemResponse,
    WebMetadataUserResponse as InnerMetadataUserResponse, WebQueryResult as InnerQueryResult,
    WebRecoveryCodesResponse as InnerRecoveryCodesResponse, WebResult as InnerResult,
    WebSearchDetailResponse as InnerSearchDetailResponse, WebSearchRequest,
    WebSearchResponse as InnerSearchResponse, WebSearchRowResponse as InnerSearchRowResponse,
    WebSymbolsCatalogResponse as InnerSymbolsCatalogResponse,
    WebSymbolsResponse as InnerSymbolsResponse, WebTagsCatalogResponse as InnerTagsCatalogResponse,
    WebTagsResponse as InnerTagsResponse, WebTwoFactorSetupResponse as InnerTwoFactorSetupResponse,
    WebUploadResponse as InnerUploadResponse, WebUploadStatusResponse as InnerUploadStatusResponse,
    WebUsernameCheckResponse as InnerUsernameCheckResponse,
    WebUsersListResponse as InnerUsersListResponse, WebYaraItemRequest,
};

#[pyclass(name = "Server")]
pub struct Server {
    inner: InnerServer,
}

#[pyclass(name = "Web")]
pub struct Web {
    inner: InnerWeb,
    config: Py<Config>,
}

#[pyclass]
pub struct SearchResult {
    hit: InnerResult,
}

#[pyclass]
pub struct QueryResult {
    item: InnerQueryResult,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct MetadataUser {
    inner: InnerMetadataUserResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct MetadataItem {
    inner: InnerMetadataItemResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct UploadResponse {
    inner: InnerUploadResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct UploadStatusResponse {
    inner: InnerUploadStatusResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SearchRow {
    inner: InnerSearchRowResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SearchResponse {
    inner: InnerSearchResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SearchDetail {
    inner: InnerSearchDetailResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TagsResponse {
    inner: InnerTagsResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TagsCatalog {
    inner: InnerTagsCatalogResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SymbolsResponse {
    inner: InnerSymbolsResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct SymbolsCatalog {
    inner: InnerSymbolsCatalogResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CorporaResponse {
    inner: InnerCorporaResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CorporaCatalog {
    inner: InnerCorporaCatalogResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CollectionTagSearchItem {
    inner: InnerCollectionTagSearchItemResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct CollectionTagSearchResponse {
    inner: InnerCollectionTagSearchResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct EntityComment {
    inner: InnerEntityCommentResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct EntityCommentsResponse {
    inner: InnerEntityCommentsResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct AdminCommentsResponse {
    inner: InnerAdminCommentsResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct Captcha {
    inner: InnerCaptchaResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct AuthUser {
    inner: InnerAuthUserResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct AuthSession {
    inner: InnerAuthSessionResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct TwoFactorSetup {
    inner: InnerTwoFactorSetupResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct UsernameCheck {
    inner: InnerUsernameCheckResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct UsersListResponse {
    inner: InnerUsersListResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct AdminUserCreateResponse {
    inner: InnerAdminUserCreateResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct KeyRegenerateResponse {
    inner: InnerKeyRegenerateResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct RecoveryCodesResponse {
    inner: InnerRecoveryCodesResponse,
}

#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct AdminPasswordResetResponse {
    inner: InnerAdminPasswordResetResponse,
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

    pub fn version(&self) -> PyResult<String> {
        Ok(self.inner.version().map_err(map_server_error)?.version)
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

    pub fn execute_processor(
        &self,
        py: Python<'_>,
        processor: String,
        binlex_version: String,
        requires: String,
        data: Bound<'_, PyAny>,
    ) -> PyResult<Py<PyAny>> {
        let data = python_to_json_value(py, &data)?;
        let value = self
            .inner
            .execute_processor(&processor, &binlex_version, &requires, data)
            .map_err(map_server_error)?;
        json_value_to_python(py, &value)
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
        Ok(Self {
            inner,
            config: config.clone_ref(py),
        })
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

    pub fn version(&self) -> PyResult<String> {
        Ok(self.inner.version().map_err(map_web_error)?.version)
    }

    pub fn graph(&self, py: Python<'_>, sha256: String) -> PyResult<Py<Graph>> {
        let graph = self.inner.graph(&sha256).map_err(map_web_error)?;
        Py::new(py, Graph::from_inner(graph))
    }

    #[pyo3(signature = (data, filename=None, format=None, architecture=None, corpora=None, tags=None))]
    pub fn upload_sample(
        &self,
        data: Vec<u8>,
        filename: Option<String>,
        format: Option<String>,
        architecture: Option<String>,
        corpora: Option<Vec<String>>,
        tags: Option<Vec<String>>,
    ) -> PyResult<UploadResponse> {
        Ok(UploadResponse {
            inner: self
                .inner
                .upload_sample(
                    &data,
                    filename.as_deref(),
                    format.as_deref(),
                    architecture.as_deref(),
                    &corpora.unwrap_or_default(),
                    &tags.unwrap_or_default(),
                )
                .map_err(map_web_error)?,
        })
    }

    pub fn upload_status(&self, sha256: String) -> PyResult<UploadStatusResponse> {
        Ok(UploadStatusResponse {
            inner: self.inner.upload_status(&sha256).map_err(map_web_error)?,
        })
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

    #[pyo3(signature = (sha256, collection, address, page=None, limit=None))]
    pub fn collection_tags(
        &self,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        page: Option<usize>,
        limit: Option<usize>,
        py: Python<'_>,
    ) -> PyResult<TagsResponse> {
        let collection = collection.borrow(py).inner;
        Ok(TagsResponse {
            inner: self
                .inner
                .collection_tags_with_request_id(&sha256, collection, address, page, limit, None)
                .map_err(map_web_error)?,
        })
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

    pub fn search_response(
        &self,
        query: String,
        top_k: Option<usize>,
        page: Option<usize>,
    ) -> PyResult<SearchResponse> {
        Ok(SearchResponse {
            inner: self
                .inner
                .search_response(&WebSearchRequest { query, top_k, page })
                .map_err(map_web_error)?,
        })
    }

    pub fn search_detail(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        symbol: Option<String>,
        py: Python<'_>,
    ) -> PyResult<SearchDetail> {
        let collection = collection.borrow(py).inner;
        Ok(SearchDetail {
            inner: self
                .inner
                .search_detail(
                    &sha256,
                    collection,
                    &architecture,
                    address,
                    symbol.as_deref(),
                )
                .map_err(map_web_error)?,
        })
    }

    pub fn search_tags(&self, query: String, limit: Option<usize>) -> PyResult<TagsCatalog> {
        Ok(TagsCatalog {
            inner: self
                .inner
                .search_tags(&query, limit)
                .map_err(map_web_error)?,
        })
    }

    pub fn add_tag(&self, tag: String) -> PyResult<bool> {
        Ok(self.inner.add_tag(&tag).map_err(map_web_error)?.ok)
    }

    pub fn search_corpora(&self, query: String) -> PyResult<CorporaCatalog> {
        Ok(CorporaCatalog {
            inner: self.inner.search_corpora(&query).map_err(map_web_error)?,
        })
    }

    pub fn add_corpus(&self, corpus: String) -> PyResult<bool> {
        Ok(self.inner.add_corpus(&corpus).map_err(map_web_error)?.ok)
    }

    #[pyo3(signature = (sha256, collection, architecture, address, page=None, limit=None))]
    pub fn collection_symbols(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        page: Option<usize>,
        limit: Option<usize>,
        py: Python<'_>,
    ) -> PyResult<SymbolsResponse> {
        let collection = collection.borrow(py).inner;
        Ok(SymbolsResponse {
            inner: self
                .inner
                .collection_symbols_paginated(
                    &sha256,
                    collection,
                    &architecture,
                    address,
                    page,
                    limit,
                )
                .map_err(map_web_error)?,
        })
    }

    pub fn search_symbols(&self, query: String, limit: Option<usize>) -> PyResult<SymbolsCatalog> {
        Ok(SymbolsCatalog {
            inner: self
                .inner
                .search_symbols(&query, limit)
                .map_err(map_web_error)?,
        })
    }

    pub fn add_symbol(&self, symbol: String) -> PyResult<bool> {
        Ok(self.inner.add_symbol(&symbol).map_err(map_web_error)?.ok)
    }

    pub fn add_collection_symbol(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        symbol: String,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .add_collection_symbol(&sha256, collection, &architecture, address, &symbol)
            .map_err(map_web_error)?
            .ok)
    }

    pub fn remove_collection_symbol(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        symbol: String,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .remove_collection_symbol(&sha256, collection, &architecture, address, &symbol)
            .map_err(map_web_error)?
            .ok)
    }

    pub fn replace_collection_symbols(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        symbols: Vec<String>,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .replace_collection_symbols(&sha256, collection, &architecture, address, &symbols)
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (sha256, collection, architecture, address, page=None, limit=None))]
    pub fn collection_corpora(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        page: Option<usize>,
        limit: Option<usize>,
        py: Python<'_>,
    ) -> PyResult<CorporaResponse> {
        let collection = collection.borrow(py).inner;
        Ok(CorporaResponse {
            inner: self
                .inner
                .collection_corpora_paginated(
                    &sha256,
                    collection,
                    &architecture,
                    address,
                    page,
                    limit,
                )
                .map_err(map_web_error)?,
        })
    }

    pub fn add_collection_corpus(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        corpus: String,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .add_collection_corpus(&sha256, collection, &architecture, address, &corpus)
            .map_err(map_web_error)?
            .ok)
    }

    pub fn remove_collection_corpus(
        &self,
        sha256: String,
        collection: Py<Collection>,
        architecture: String,
        address: u64,
        corpus: String,
        py: Python<'_>,
    ) -> PyResult<bool> {
        let collection = collection.borrow(py).inner;
        Ok(self
            .inner
            .remove_collection_corpus(&sha256, collection, &architecture, address, &corpus)
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (sha256, collection, address, page=None, page_size=None))]
    pub fn entity_comments(
        &self,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        page: Option<usize>,
        page_size: Option<usize>,
        py: Python<'_>,
    ) -> PyResult<EntityCommentsResponse> {
        let collection = collection.borrow(py).inner;
        Ok(EntityCommentsResponse {
            inner: self
                .inner
                .entity_comments(&sha256, collection, address, page, page_size)
                .map_err(map_web_error)?,
        })
    }

    pub fn add_entity_comment(
        &self,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
        body: String,
        py: Python<'_>,
    ) -> PyResult<EntityComment> {
        let collection = collection.borrow(py).inner;
        Ok(EntityComment {
            inner: self
                .inner
                .add_entity_comment(&sha256, collection, address, &body)
                .map_err(map_web_error)?,
        })
    }

    pub fn delete_entity_comment(&self, id: i64) -> PyResult<bool> {
        Ok(self
            .inner
            .delete_entity_comment(id)
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (query="".to_string(), page=None, page_size=None))]
    pub fn admin_comments(
        &self,
        query: String,
        page: Option<usize>,
        page_size: Option<usize>,
    ) -> PyResult<AdminCommentsResponse> {
        Ok(AdminCommentsResponse {
            inner: self
                .inner
                .admin_comments(&query, page, page_size)
                .map_err(map_web_error)?,
        })
    }

    pub fn render_yara(
        &self,
        py: Python<'_>,
        query: String,
        items: Bound<'_, PyAny>,
    ) -> PyResult<String> {
        let items = python_to_json_value(py, &items)?;
        let items = serde_json::from_value::<Vec<WebYaraItemRequest>>(items)
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        self.inner
            .render_yara(&query, &items)
            .map_err(map_web_error)
    }

    pub fn download_sample(&self, sha256: String) -> PyResult<Vec<u8>> {
        self.inner.download_sample(&sha256).map_err(map_web_error)
    }

    pub fn download_samples(&self, sha256: Vec<String>) -> PyResult<Vec<u8>> {
        self.inner.download_samples(&sha256).map_err(map_web_error)
    }

    pub fn download_json(
        &self,
        py: Python<'_>,
        corpus: String,
        sha256: String,
        collection: Py<Collection>,
        address: u64,
    ) -> PyResult<Py<PyAny>> {
        let collection = collection.borrow(py).inner;
        let value = self
            .inner
            .download_json(&corpus, &sha256, collection, address)
            .map_err(map_web_error)?;
        json_value_to_python(py, &value)
    }

    pub fn auth_bootstrap(
        &self,
        username: String,
        password: String,
        password_confirm: String,
    ) -> PyResult<AuthSession> {
        Ok(AuthSession {
            inner: self
                .inner
                .auth_bootstrap(&username, &password, &password_confirm)
                .map_err(map_web_error)?,
        })
    }

    pub fn auth_login(&self, username: String, password: String) -> PyResult<AuthSession> {
        Ok(AuthSession {
            inner: self
                .inner
                .auth_login(&username, &password)
                .map_err(map_web_error)?,
        })
    }

    pub fn auth_login_two_factor(
        &self,
        challenge_token: String,
        code: String,
    ) -> PyResult<AuthSession> {
        Ok(AuthSession {
            inner: self
                .inner
                .auth_login_two_factor(&challenge_token, &code)
                .map_err(map_web_error)?,
        })
    }

    pub fn auth_login_two_factor_setup(&self, challenge_token: String) -> PyResult<TwoFactorSetup> {
        Ok(TwoFactorSetup {
            inner: self
                .inner
                .auth_login_two_factor_setup(&challenge_token)
                .map_err(map_web_error)?,
        })
    }

    pub fn auth_login_two_factor_enable(
        &self,
        challenge_token: String,
        code: String,
    ) -> PyResult<AuthSession> {
        Ok(AuthSession {
            inner: self
                .inner
                .auth_login_two_factor_enable(&challenge_token, &code)
                .map_err(map_web_error)?,
        })
    }

    pub fn auth_captcha(&self) -> PyResult<Captcha> {
        Ok(Captcha {
            inner: self.inner.auth_captcha().map_err(map_web_error)?,
        })
    }

    pub fn auth_register(
        &self,
        username: String,
        password: String,
        password_confirm: String,
        captcha_id: String,
        captcha_answer: String,
    ) -> PyResult<AuthSession> {
        Ok(AuthSession {
            inner: self
                .inner
                .auth_register(
                    &username,
                    &password,
                    &password_confirm,
                    &captcha_id,
                    &captcha_answer,
                )
                .map_err(map_web_error)?,
        })
    }

    pub fn auth_logout(&self) -> PyResult<bool> {
        Ok(self.inner.auth_logout().map_err(map_web_error)?.ok)
    }

    pub fn auth_me(&self) -> PyResult<AuthSession> {
        Ok(AuthSession {
            inner: self.inner.auth_me().map_err(map_web_error)?,
        })
    }

    pub fn auth_username_check(&self, username: String) -> PyResult<UsernameCheck> {
        Ok(UsernameCheck {
            inner: self
                .inner
                .auth_username_check(&username)
                .map_err(map_web_error)?,
        })
    }

    pub fn auth_password_reset(
        &self,
        username: String,
        recovery_code: String,
        new_password: String,
        password_confirm: String,
        captcha_id: String,
        captcha_answer: String,
    ) -> PyResult<bool> {
        Ok(self
            .inner
            .auth_password_reset(
                &username,
                &recovery_code,
                &new_password,
                &password_confirm,
                &captcha_id,
                &captcha_answer,
            )
            .map_err(map_web_error)?
            .ok)
    }

    pub fn profile(&self) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self.inner.profile().map_err(map_web_error)?,
        })
    }

    pub fn profile_password(
        &self,
        current_password: String,
        new_password: String,
        password_confirm: String,
    ) -> PyResult<bool> {
        Ok(self
            .inner
            .profile_password(&current_password, &new_password, &password_confirm)
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (data, filename=None))]
    pub fn profile_picture_upload(
        &self,
        data: Vec<u8>,
        filename: Option<String>,
    ) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .profile_picture_upload(&data, filename.as_deref())
                .map_err(map_web_error)?,
        })
    }

    pub fn profile_picture_delete(&self) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self.inner.profile_picture_delete().map_err(map_web_error)?,
        })
    }

    pub fn profile_picture_get(&self, username: String) -> PyResult<Vec<u8>> {
        self.inner
            .profile_picture_get(&username)
            .map_err(map_web_error)
    }

    pub fn profile_key_regenerate(&self) -> PyResult<KeyRegenerateResponse> {
        Ok(KeyRegenerateResponse {
            inner: self.inner.profile_key_regenerate().map_err(map_web_error)?,
        })
    }

    pub fn profile_recovery_regenerate(&self) -> PyResult<RecoveryCodesResponse> {
        Ok(RecoveryCodesResponse {
            inner: self
                .inner
                .profile_recovery_regenerate()
                .map_err(map_web_error)?,
        })
    }

    pub fn profile_two_factor_setup(&self) -> PyResult<TwoFactorSetup> {
        Ok(TwoFactorSetup {
            inner: self
                .inner
                .profile_two_factor_setup()
                .map_err(map_web_error)?,
        })
    }

    pub fn profile_two_factor_enable(
        &self,
        current_password: String,
        code: String,
    ) -> PyResult<AuthSession> {
        Ok(AuthSession {
            inner: self
                .inner
                .profile_two_factor_enable(&current_password, &code)
                .map_err(map_web_error)?,
        })
    }

    pub fn profile_two_factor_disable(
        &self,
        current_password: String,
        code: String,
    ) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .profile_two_factor_disable(&current_password, &code)
                .map_err(map_web_error)?,
        })
    }

    pub fn profile_delete(&self, password: String) -> PyResult<bool> {
        Ok(self
            .inner
            .profile_delete(&password)
            .map_err(map_web_error)?
            .ok)
    }

    #[pyo3(signature = (query="".to_string(), page=None, limit=None))]
    pub fn admin_users(
        &self,
        query: String,
        page: Option<usize>,
        limit: Option<usize>,
    ) -> PyResult<UsersListResponse> {
        Ok(UsersListResponse {
            inner: self
                .inner
                .admin_users(&query, page, limit)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_create(
        &self,
        username: String,
        password: String,
        password_confirm: String,
        role: String,
    ) -> PyResult<AdminUserCreateResponse> {
        Ok(AdminUserCreateResponse {
            inner: self
                .inner
                .admin_user_create(&username, &password, &password_confirm, &role)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_role(&self, username: String, role: String) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .admin_user_role(&username, &role)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_enabled(&self, username: String, enabled: bool) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .admin_user_enabled(&username, enabled)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_password_reset(
        &self,
        username: String,
    ) -> PyResult<AdminPasswordResetResponse> {
        Ok(AdminPasswordResetResponse {
            inner: self
                .inner
                .admin_user_password_reset(&username)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_key_regenerate(&self, username: String) -> PyResult<KeyRegenerateResponse> {
        Ok(KeyRegenerateResponse {
            inner: self
                .inner
                .admin_user_key_regenerate(&username)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_delete(&self, username: String) -> PyResult<bool> {
        Ok(self
            .inner
            .admin_user_delete(&username)
            .map_err(map_web_error)?
            .ok)
    }

    pub fn admin_user_picture_delete(&self, username: String) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .admin_user_picture_delete(&username)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_two_factor_require(
        &self,
        username: String,
        required: bool,
    ) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .admin_user_two_factor_require(&username, required)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_two_factor_disable(&self, username: String) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .admin_user_two_factor_disable(&username)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_user_two_factor_reset(&self, username: String) -> PyResult<AuthUser> {
        Ok(AuthUser {
            inner: self
                .inner
                .admin_user_two_factor_reset(&username)
                .map_err(map_web_error)?,
        })
    }

    pub fn admin_delete_corpus(&self, corpus: String) -> PyResult<bool> {
        Ok(self
            .inner
            .admin_delete_corpus(&corpus)
            .map_err(map_web_error)?
            .ok)
    }

    pub fn admin_delete_tag(&self, tag: String) -> PyResult<bool> {
        Ok(self.inner.admin_delete_tag(&tag).map_err(map_web_error)?.ok)
    }

    pub fn admin_delete_symbol(&self, symbol: String) -> PyResult<bool> {
        Ok(self
            .inner
            .admin_delete_symbol(&symbol)
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
impl MetadataUser {
    pub fn username(&self) -> String {
        self.inner.username.clone()
    }

    pub fn profile_picture(&self) -> Option<String> {
        self.inner.profile_picture.clone()
    }
}

#[pymethods]
impl MetadataItem {
    pub fn name(&self) -> String {
        self.inner.name.clone()
    }

    pub fn created_by(&self) -> MetadataUser {
        MetadataUser {
            inner: self.inner.created_by.clone(),
        }
    }

    pub fn created_timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.created_timestamp)
    }

    pub fn assigned_by(&self) -> Option<MetadataUser> {
        self.inner
            .assigned_by
            .clone()
            .map(|inner| MetadataUser { inner })
    }

    pub fn assigned_timestamp(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match &self.inner.assigned_timestamp {
            Some(value) => Ok(Some(python_datetime_from_string(py, value)?)),
            None => Ok(None),
        }
    }
}

#[pymethods]
impl UploadResponse {
    pub fn ok(&self) -> bool {
        self.inner.ok
    }

    pub fn sha256(&self) -> Option<String> {
        self.inner.sha256.clone()
    }

    pub fn error(&self) -> Option<String> {
        self.inner.error.clone()
    }
}

#[pymethods]
impl UploadStatusResponse {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }

    pub fn status(&self) -> String {
        self.inner.status.clone()
    }

    pub fn timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }

    pub fn error_message(&self) -> Option<String> {
        self.inner.error_message.clone()
    }

    pub fn id(&self) -> Option<String> {
        self.inner.id.clone()
    }
}

#[pymethods]
impl SearchRow {
    pub fn side(&self) -> String {
        self.inner.side.clone()
    }
    pub fn grouped(&self) -> bool {
        self.inner.grouped
    }
    pub fn group_end(&self) -> bool {
        self.inner.group_end
    }
    pub fn detail_loaded(&self) -> bool {
        self.inner.detail_loaded
    }
    pub fn object_id(&self) -> String {
        self.inner.object_id.clone()
    }
    pub fn timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
    pub fn username(&self) -> String {
        self.inner.username.clone()
    }
    pub fn profile_picture(&self) -> Option<String> {
        self.inner.profile_picture.clone()
    }
    pub fn size(&self) -> u64 {
        self.inner.size
    }
    pub fn score(&self) -> Option<f32> {
        self.inner.score
    }
    pub fn similarity_score(&self) -> Option<f32> {
        self.inner.similarity_score
    }
    pub fn vector(&self) -> Vec<f32> {
        self.inner.vector.clone()
    }
    pub fn json(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        optional_json_value_to_python(py, self.inner.json.as_ref())
    }
    pub fn symbol(&self) -> Option<String> {
        self.inner.symbol.clone()
    }
    pub fn architecture(&self) -> String {
        self.inner.architecture.clone()
    }
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Collection {
        python_collection_from_name(&self.inner.collection)
    }
    pub fn address(&self) -> u64 {
        self.inner.address
    }
    pub fn cyclomatic_complexity(&self) -> Option<u64> {
        self.inner.cyclomatic_complexity
    }
    pub fn average_instructions_per_block(&self) -> Option<f64> {
        self.inner.average_instructions_per_block
    }
    pub fn instructions(&self) -> Option<u64> {
        self.inner.number_of_instructions
    }
    pub fn blocks(&self) -> Option<u64> {
        self.inner.number_of_blocks
    }
    pub fn markov(&self) -> Option<f64> {
        self.inner.markov
    }
    pub fn entropy(&self) -> Option<f64> {
        self.inner.entropy
    }
    pub fn contiguous(&self) -> Option<bool> {
        self.inner.contiguous
    }
    pub fn chromosome_entropy(&self) -> Option<f64> {
        self.inner.chromosome_entropy
    }
    pub fn embedding(&self) -> String {
        self.inner.embedding.clone()
    }
    pub fn embeddings(&self) -> u64 {
        self.inner.embeddings
    }
    pub fn corpora(&self) -> Vec<String> {
        self.inner.corpora.clone()
    }
    pub fn corpora_count(&self) -> usize {
        self.inner.corpora_count
    }
    pub fn tag_count(&self) -> usize {
        self.inner.collection_tag_count
    }
    pub fn comment_count(&self) -> usize {
        self.inner.collection_comment_count
    }
}

#[pymethods]
impl SearchResponse {
    pub fn message(&self) -> Option<String> {
        self.inner.message.clone()
    }
    pub fn warning(&self) -> Option<String> {
        self.inner.warning.clone()
    }
    pub fn error(&self) -> Option<String> {
        self.inner.error.clone()
    }
    pub fn query(&self) -> String {
        self.inner.query.clone()
    }
    pub fn uploaded_sha256(&self) -> Option<String> {
        self.inner.uploaded_sha256.clone()
    }
    pub fn page(&self) -> usize {
        self.inner.page
    }
    pub fn top_k(&self) -> usize {
        self.inner.top_k
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_previous_page(&self) -> bool {
        self.inner.has_previous_page
    }
    pub fn has_next_page(&self) -> bool {
        self.inner.has_next_page
    }
    pub fn sample_downloads_enabled(&self) -> bool {
        self.inner.sample_downloads_enabled
    }
    pub fn results(&self) -> Vec<SearchRow> {
        self.inner
            .results
            .iter()
            .cloned()
            .map(|inner| SearchRow { inner })
            .collect()
    }
}

#[pymethods]
impl SearchDetail {
    pub fn detail_loaded(&self) -> bool {
        self.inner.detail_loaded
    }
    pub fn object_id(&self) -> String {
        self.inner.object_id.clone()
    }
    pub fn timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
    pub fn username(&self) -> String {
        self.inner.username.clone()
    }
    pub fn size(&self) -> u64 {
        self.inner.size
    }
    pub fn score(&self) -> Option<f32> {
        self.inner.score
    }
    pub fn similarity_score(&self) -> Option<f32> {
        self.inner.similarity_score
    }
    pub fn vector(&self) -> Vec<f32> {
        self.inner.vector.clone()
    }
    pub fn json(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        optional_json_value_to_python(py, self.inner.json.as_ref())
    }
    pub fn symbol(&self) -> Option<String> {
        self.inner.symbol.clone()
    }
    pub fn architecture(&self) -> String {
        self.inner.architecture.clone()
    }
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Collection {
        python_collection_from_name(&self.inner.collection)
    }
    pub fn address(&self) -> u64 {
        self.inner.address
    }
    pub fn cyclomatic_complexity(&self) -> Option<u64> {
        self.inner.cyclomatic_complexity
    }
    pub fn average_instructions_per_block(&self) -> Option<f64> {
        self.inner.average_instructions_per_block
    }
    pub fn instructions(&self) -> Option<u64> {
        self.inner.number_of_instructions
    }
    pub fn blocks(&self) -> Option<u64> {
        self.inner.number_of_blocks
    }
    pub fn markov(&self) -> Option<f64> {
        self.inner.markov
    }
    pub fn entropy(&self) -> Option<f64> {
        self.inner.entropy
    }
    pub fn contiguous(&self) -> Option<bool> {
        self.inner.contiguous
    }
    pub fn chromosome_entropy(&self) -> Option<f64> {
        self.inner.chromosome_entropy
    }
    pub fn embedding(&self) -> String {
        self.inner.embedding.clone()
    }
    pub fn embeddings(&self) -> u64 {
        self.inner.embeddings
    }
    pub fn corpora(&self) -> Vec<String> {
        self.inner.corpora.clone()
    }
    pub fn corpora_count(&self) -> usize {
        self.inner.corpora_count
    }
}

#[pymethods]
impl TagsResponse {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Option<Collection> {
        self.inner
            .collection
            .as_ref()
            .map(|value| python_collection_from_name(value))
    }
    pub fn address(&self) -> Option<u64> {
        self.inner.address
    }
    pub fn tags(&self) -> Vec<MetadataItem> {
        self.inner
            .tags
            .iter()
            .cloned()
            .map(|inner| MetadataItem { inner })
            .collect()
    }
    pub fn page(&self) -> usize {
        self.inner.page
    }
    pub fn limit(&self) -> usize {
        self.inner.limit
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl TagsCatalog {
    pub fn tags(&self) -> Vec<MetadataItem> {
        self.inner
            .tags
            .iter()
            .cloned()
            .map(|inner| MetadataItem { inner })
            .collect()
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl SymbolsResponse {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Collection {
        python_collection_from_name(&self.inner.collection)
    }
    pub fn architecture(&self) -> String {
        self.inner.architecture.clone()
    }
    pub fn address(&self) -> u64 {
        self.inner.address
    }
    pub fn symbols(&self) -> Vec<MetadataItem> {
        self.inner
            .symbols
            .iter()
            .cloned()
            .map(|inner| MetadataItem { inner })
            .collect()
    }
    pub fn page(&self) -> usize {
        self.inner.page
    }
    pub fn limit(&self) -> usize {
        self.inner.limit
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl SymbolsCatalog {
    pub fn symbols(&self) -> Vec<MetadataItem> {
        self.inner
            .symbols
            .iter()
            .cloned()
            .map(|inner| MetadataItem { inner })
            .collect()
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl CorporaResponse {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Option<Collection> {
        self.inner
            .collection
            .as_ref()
            .map(|value| python_collection_from_name(value))
    }
    pub fn architecture(&self) -> Option<String> {
        self.inner.architecture.clone()
    }
    pub fn address(&self) -> Option<u64> {
        self.inner.address
    }
    pub fn corpora(&self) -> Vec<MetadataItem> {
        self.inner
            .corpora
            .iter()
            .cloned()
            .map(|inner| MetadataItem { inner })
            .collect()
    }
    pub fn page(&self) -> usize {
        self.inner.page
    }
    pub fn limit(&self) -> usize {
        self.inner.limit
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl CorporaCatalog {
    pub fn corpora(&self) -> Vec<MetadataItem> {
        self.inner
            .corpora
            .iter()
            .cloned()
            .map(|inner| MetadataItem { inner })
            .collect()
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
}

#[pymethods]
impl CollectionTagSearchItem {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Collection {
        python_collection_from_name(&self.inner.collection)
    }
    pub fn address(&self) -> u64 {
        self.inner.address
    }
    pub fn tag(&self) -> String {
        self.inner.tag.clone()
    }
    pub fn timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pymethods]
impl CollectionTagSearchResponse {
    pub fn items(&self) -> Vec<CollectionTagSearchItem> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| CollectionTagSearchItem { inner })
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
impl EntityComment {
    pub fn id(&self) -> i64 {
        self.inner.id
    }
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Collection {
        python_collection_from_name(&self.inner.collection)
    }
    pub fn address(&self) -> u64 {
        self.inner.address
    }
    pub fn user(&self) -> MetadataUser {
        MetadataUser {
            inner: self.inner.user.clone(),
        }
    }
    pub fn timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
    pub fn body(&self) -> String {
        self.inner.body.clone()
    }
}

#[pymethods]
impl EntityCommentsResponse {
    pub fn sha256(&self) -> String {
        self.inner.sha256.clone()
    }
    pub fn collection(&self) -> Collection {
        python_collection_from_name(&self.inner.collection)
    }
    pub fn address(&self) -> u64 {
        self.inner.address
    }
    pub fn items(&self) -> Vec<EntityComment> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| EntityComment { inner })
            .collect()
    }
    pub fn page(&self) -> usize {
        self.inner.page
    }
    pub fn page_size(&self) -> usize {
        self.inner.page_size
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl AdminCommentsResponse {
    pub fn items(&self) -> Vec<EntityComment> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| EntityComment { inner })
            .collect()
    }
    pub fn page(&self) -> usize {
        self.inner.page
    }
    pub fn page_size(&self) -> usize {
        self.inner.page_size
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl Captcha {
    pub fn captcha_id(&self) -> String {
        self.inner.captcha_id.clone()
    }
    pub fn image_base64(&self) -> String {
        self.inner.image_base64.clone()
    }
    pub fn expires(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.expires)
    }
}

#[pymethods]
impl AuthUser {
    pub fn username(&self) -> String {
        self.inner.username.clone()
    }
    pub fn key(&self) -> String {
        self.inner.key.clone()
    }
    pub fn role(&self) -> String {
        self.inner.role.clone()
    }
    pub fn enabled(&self) -> bool {
        self.inner.enabled
    }
    pub fn profile_picture(&self) -> Option<String> {
        self.inner.profile_picture.clone()
    }
    pub fn two_factor_enabled(&self) -> bool {
        self.inner.two_factor_enabled
    }
    pub fn two_factor_required(&self) -> bool {
        self.inner.two_factor_required
    }
    pub fn timestamp(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        python_datetime_from_string(py, &self.inner.timestamp)
    }
}

#[pymethods]
impl AuthSession {
    pub fn authenticated(&self) -> bool {
        self.inner.authenticated
    }
    pub fn registration_enabled(&self) -> bool {
        self.inner.registration_enabled
    }
    pub fn bootstrap_required(&self) -> bool {
        self.inner.bootstrap_required
    }
    pub fn two_factor_required(&self) -> bool {
        self.inner.two_factor_required
    }
    pub fn two_factor_setup_required(&self) -> bool {
        self.inner.two_factor_setup_required
    }
    pub fn challenge_token(&self) -> Option<String> {
        self.inner.challenge_token.clone()
    }
    pub fn user(&self) -> Option<AuthUser> {
        self.inner.user.clone().map(|inner| AuthUser { inner })
    }
    pub fn recovery_codes(&self) -> Option<Vec<String>> {
        self.inner.recovery_codes.clone()
    }
}

#[pymethods]
impl TwoFactorSetup {
    pub fn manual_secret(&self) -> String {
        self.inner.manual_secret.clone()
    }
    pub fn qr_svg(&self) -> String {
        self.inner.qr_svg.clone()
    }
}

#[pymethods]
impl UsernameCheck {
    pub fn normalized(&self) -> String {
        self.inner.normalized.clone()
    }
    pub fn valid(&self) -> bool {
        self.inner.valid
    }
    pub fn available(&self) -> bool {
        self.inner.available
    }
    pub fn error(&self) -> Option<String> {
        self.inner.error.clone()
    }
}

#[pymethods]
impl UsersListResponse {
    pub fn items(&self) -> Vec<AuthUser> {
        self.inner
            .items
            .iter()
            .cloned()
            .map(|inner| AuthUser { inner })
            .collect()
    }
    pub fn page(&self) -> usize {
        self.inner.page
    }
    pub fn limit(&self) -> usize {
        self.inner.limit
    }
    pub fn total_results(&self) -> usize {
        self.inner.total_results
    }
    pub fn has_next(&self) -> bool {
        self.inner.has_next
    }
}

#[pymethods]
impl AdminUserCreateResponse {
    pub fn user(&self) -> AuthUser {
        AuthUser {
            inner: self.inner.user.clone(),
        }
    }
    pub fn key(&self) -> String {
        self.inner.key.clone()
    }
    pub fn recovery_codes(&self) -> Vec<String> {
        self.inner.recovery_codes.clone()
    }
}

#[pymethods]
impl KeyRegenerateResponse {
    pub fn key(&self) -> String {
        self.inner.key.clone()
    }
}

#[pymethods]
impl RecoveryCodesResponse {
    pub fn recovery_codes(&self) -> Vec<String> {
        self.inner.recovery_codes.clone()
    }
}

#[pymethods]
impl AdminPasswordResetResponse {
    pub fn username(&self) -> String {
        self.inner.username.clone()
    }
    pub fn password(&self) -> String {
        self.inner.password.clone()
    }
}

#[pymethods]
impl SearchResult {
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

    pub fn username(&self) -> String {
        self.hit.username().to_string()
    }

    pub fn cyclomatic_complexity(&self) -> Option<u64> {
        self.hit.cyclomatic_complexity()
    }

    pub fn average_instructions_per_block(&self) -> Option<f64> {
        self.hit.average_instructions_per_block()
    }

    pub fn instructions(&self) -> Option<u64> {
        self.hit.instructions()
    }

    pub fn blocks(&self) -> Option<u64> {
        self.hit.blocks()
    }

    pub fn markov(&self) -> Option<f64> {
        self.hit.markov()
    }

    pub fn entropy(&self) -> Option<f64> {
        self.hit.entropy()
    }

    pub fn contiguous(&self) -> Option<bool> {
        self.hit.contiguous()
    }

    pub fn chromosome_entropy(&self) -> Option<f64> {
        self.hit.chromosome_entropy()
    }

    pub fn corpora_count(&self) -> usize {
        self.hit.corpora_count()
    }

    pub fn tag_count(&self) -> usize {
        self.hit.tag_count()
    }

    pub fn comment_count(&self) -> usize {
        self.hit.comment_count()
    }

    #[pyo3(signature = (web, page=None, limit=None))]
    pub fn symbols(
        &self,
        web: &Web,
        page: Option<usize>,
        limit: Option<usize>,
    ) -> PyResult<SymbolsResponse> {
        let _ = (page, limit);
        Ok(SymbolsResponse {
            inner: web
                .inner
                .collection_symbols(
                    self.hit.sha256(),
                    self.hit.collection(),
                    self.hit.architecture(),
                    self.hit.address(),
                )
                .map_err(map_web_error)?,
        })
    }

    #[pyo3(signature = (web, page=None, limit=None))]
    pub fn tags(
        &self,
        web: &Web,
        page: Option<usize>,
        limit: Option<usize>,
    ) -> PyResult<TagsResponse> {
        let _ = (page, limit);
        Ok(TagsResponse {
            inner: web
                .inner
                .collection_tags(self.hit.sha256(), self.hit.collection(), self.hit.address())
                .map_err(map_web_error)?,
        })
    }

    #[pyo3(signature = (web, page=None, limit=None))]
    pub fn corpora(
        &self,
        web: &Web,
        page: Option<usize>,
        limit: Option<usize>,
    ) -> PyResult<CorporaResponse> {
        let _ = (page, limit);
        Ok(CorporaResponse {
            inner: web
                .inner
                .collection_corpora(
                    self.hit.sha256(),
                    self.hit.collection(),
                    self.hit.architecture(),
                    self.hit.address(),
                )
                .map_err(map_web_error)?,
        })
    }

    pub fn function(
        &self,
        py: Python<'_>,
        web: &Web,
    ) -> PyResult<Option<FunctionJsonDeserializer>> {
        if self.hit.collection() != binlex::indexing::Collection::Function {
            return Ok(None);
        }
        let detail = web
            .inner
            .search_detail(
                self.hit.sha256(),
                self.hit.collection(),
                self.hit.architecture(),
                self.hit.address(),
                self.hit.symbol(),
            )
            .map_err(map_web_error)?;
        let value = detail.json.ok_or_else(|| {
            PyRuntimeError::new_err("search detail response is missing entity json")
        })?;
        let string = serde_json::to_string(&value)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Some(FunctionJsonDeserializer::new(
            py,
            string,
            web.config.clone_ref(py),
        )?))
    }

    pub fn block(&self, py: Python<'_>, web: &Web) -> PyResult<Option<BlockJsonDeserializer>> {
        if self.hit.collection() != binlex::indexing::Collection::Block {
            return Ok(None);
        }
        let detail = web
            .inner
            .search_detail(
                self.hit.sha256(),
                self.hit.collection(),
                self.hit.architecture(),
                self.hit.address(),
                self.hit.symbol(),
            )
            .map_err(map_web_error)?;
        let value = detail.json.ok_or_else(|| {
            PyRuntimeError::new_err("search detail response is missing entity json")
        })?;
        let string = serde_json::to_string(&value)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Some(BlockJsonDeserializer::new(
            py,
            string,
            web.config.clone_ref(py),
        )?))
    }

    pub fn instruction(
        &self,
        py: Python<'_>,
        web: &Web,
    ) -> PyResult<Option<InstructionJsonDeserializer>> {
        if self.hit.collection() != binlex::indexing::Collection::Instruction {
            return Ok(None);
        }
        let detail = web
            .inner
            .search_detail(
                self.hit.sha256(),
                self.hit.collection(),
                self.hit.architecture(),
                self.hit.address(),
                self.hit.symbol(),
            )
            .map_err(map_web_error)?;
        let value = detail.json.ok_or_else(|| {
            PyRuntimeError::new_err("search detail response is missing entity json")
        })?;
        let string = serde_json::to_string(&value)
            .map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
        Ok(Some(InstructionJsonDeserializer::new(
            py,
            string,
            web.config.clone_ref(py),
        )?))
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

fn python_collection_from_name(value: &str) -> Collection {
    let inner = match value.trim().to_ascii_lowercase().as_str() {
        "instructions" | "instruction" => binlex::indexing::Collection::Instruction,
        "blocks" | "block" => binlex::indexing::Collection::Block,
        _ => binlex::indexing::Collection::Function,
    };
    Collection { inner }
}

fn python_datetime_from_string(py: Python<'_>, value: &str) -> PyResult<Py<PyAny>> {
    let datetime = py.import("datetime")?;
    let cls = datetime.getattr("datetime")?;
    Ok(cls.call_method1("fromisoformat", (value,))?.into())
}

fn json_value_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<Py<PyAny>> {
    let json = py.import("json")?;
    let text =
        serde_json::to_string(value).map_err(|error| PyRuntimeError::new_err(error.to_string()))?;
    Ok(json.call_method1("loads", (text,))?.unbind())
}

fn optional_json_value_to_python(
    py: Python<'_>,
    value: Option<&serde_json::Value>,
) -> PyResult<Option<Py<PyAny>>> {
    match value {
        Some(value) => Ok(Some(json_value_to_python(py, value)?)),
        None => Ok(None),
    }
}

fn python_to_json_value(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<Value> {
    let json = py.import("json")?;
    let text = json.call_method1("dumps", (value,))?;
    let text: String = text.extract()?;
    serde_json::from_str(&text).map_err(|error| PyValueError::new_err(error.to_string()))
}

#[pymodule]
#[pyo3(name = "clients")]
pub fn clients_init(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Server>()?;
    m.add_class::<Web>()?;
    m.add_class::<MetadataUser>()?;
    m.add_class::<MetadataItem>()?;
    m.add_class::<UploadResponse>()?;
    m.add_class::<UploadStatusResponse>()?;
    m.add_class::<SearchRow>()?;
    m.add_class::<SearchResponse>()?;
    m.add_class::<SearchDetail>()?;
    m.add_class::<TagsResponse>()?;
    m.add_class::<TagsCatalog>()?;
    m.add_class::<SymbolsResponse>()?;
    m.add_class::<SymbolsCatalog>()?;
    m.add_class::<CorporaResponse>()?;
    m.add_class::<CorporaCatalog>()?;
    m.add_class::<CollectionTagSearchItem>()?;
    m.add_class::<CollectionTagSearchResponse>()?;
    m.add_class::<EntityComment>()?;
    m.add_class::<EntityCommentsResponse>()?;
    m.add_class::<AdminCommentsResponse>()?;
    m.add_class::<Captcha>()?;
    m.add_class::<AuthUser>()?;
    m.add_class::<AuthSession>()?;
    m.add_class::<TwoFactorSetup>()?;
    m.add_class::<UsernameCheck>()?;
    m.add_class::<UsersListResponse>()?;
    m.add_class::<AdminUserCreateResponse>()?;
    m.add_class::<KeyRegenerateResponse>()?;
    m.add_class::<RecoveryCodesResponse>()?;
    m.add_class::<AdminPasswordResetResponse>()?;
    m.add_class::<SearchResult>()?;
    m.add_class::<QueryResult>()?;
    py.import("sys")?
        .getattr("modules")?
        .set_item("binlex_bindings.binlex.clients", m)?;
    m.setattr("__name__", "binlex_bindings.binlex.clients")?;
    Ok(())
}
