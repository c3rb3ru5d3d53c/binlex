use crate::Config;
use crate::clients::{decode_response, normalize_url};
use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::indexing::Collection;
use crate::server::request_id::X_REQUEST_ID;
use chrono::{DateTime, Utc};
use reqwest::blocking::Client as HttpClient;
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderName};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

#[derive(Clone)]
pub struct Web {
    url: String,
    verify: bool,
    api_key: Option<String>,
}

#[derive(Debug)]
pub enum WebError {
    InvalidConfiguration(&'static str),
    Io(String),
    Http(u16, String),
    Serialization(String),
    Protocol(String),
}

impl fmt::Display for WebError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "binlex-web client configuration error: {}", message)
            }
            Self::Io(message) => write!(f, "binlex-web client io error: {}", message),
            Self::Http(status, message) => {
                write!(f, "binlex-web http error {}: {}", status, message)
            }
            Self::Serialization(message) => {
                write!(f, "binlex-web serialization error: {}", message)
            }
            Self::Protocol(message) => write!(f, "binlex-web protocol error: {}", message),
        }
    }
}

impl std::error::Error for WebError {}

#[derive(Clone, Debug)]
pub struct WebResult {
    inner: WebSearchRowResponse,
}

impl WebResult {
    pub fn corpus(&self) -> &str {
        self.inner
            .corpora
            .first()
            .map(String::as_str)
            .unwrap_or("default")
    }

    pub fn corpora(&self) -> &[String] {
        &self.inner.corpora
    }

    pub fn score(&self) -> f32 {
        self.inner
            .similarity_score
            .or(self.inner.score)
            .unwrap_or_default()
    }

    pub fn sha256(&self) -> &str {
        &self.inner.sha256
    }

    pub fn username(&self) -> &str {
        &self.inner.username
    }

    pub fn address(&self) -> u64 {
        self.inner.address
    }

    pub fn size(&self) -> u64 {
        self.inner.size
    }

    pub fn timestamp(&self) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(&self.inner.timestamp)
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
    }

    pub fn symbol(&self) -> Option<&str> {
        self.inner.symbol.as_deref()
    }

    pub fn architecture(&self) -> &str {
        &self.inner.architecture
    }

    pub fn embedding(&self) -> &str {
        &self.inner.embedding
    }

    pub fn embeddings(&self) -> u64 {
        self.inner.embeddings
    }

    pub fn collection(&self) -> Collection {
        parse_collection(&self.inner.collection)
    }

    pub fn vector(&self) -> &[f32] {
        &self.inner.vector
    }

    pub fn json(&self) -> Option<&Value> {
        self.inner.json.as_ref()
    }
}

#[derive(Clone, Debug)]
pub struct WebQueryResult {
    lhs: Option<WebResult>,
    rhs: Option<WebResult>,
    score: f32,
}

impl WebQueryResult {
    pub fn lhs(&self) -> Option<&WebResult> {
        self.lhs.as_ref()
    }

    pub fn rhs(&self) -> Option<&WebResult> {
        self.rhs.as_ref()
    }

    pub fn score(&self) -> f32 {
        self.score
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebSearchRequest {
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebIndexActionResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebTagsResponse {
    pub sha256: String,
    #[serde(default)]
    pub collection: Option<String>,
    #[serde(default)]
    pub address: Option<u64>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebTagsActionResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebCollectionTagSearchItemResponse {
    pub sha256: String,
    pub collection: String,
    pub address: u64,
    pub tag: String,
    pub timestamp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebCollectionTagSearchResponse {
    pub items: Vec<WebCollectionTagSearchItemResponse>,
    pub page: usize,
    pub page_size: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebSearchResponse {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub warning: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    pub query: String,
    #[serde(default)]
    pub uploaded_sha256: Option<String>,
    pub page: usize,
    pub top_k: usize,
    pub has_previous_page: bool,
    pub has_next_page: bool,
    pub sample_downloads_enabled: bool,
    pub results: Vec<WebSearchRowResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebSearchRowResponse {
    pub side: String,
    pub grouped: bool,
    pub group_end: bool,
    pub timestamp: String,
    pub username: String,
    pub size: u64,
    #[serde(default)]
    pub score: Option<f32>,
    #[serde(default)]
    pub similarity_score: Option<f32>,
    pub vector: Vec<f32>,
    #[serde(default)]
    pub json: Option<Value>,
    #[serde(default)]
    pub symbol: Option<String>,
    pub architecture: String,
    pub sha256: String,
    pub collection: String,
    pub address: u64,
    #[serde(default)]
    pub cyclomatic_complexity: Option<u64>,
    #[serde(default)]
    pub average_instructions_per_block: Option<f64>,
    #[serde(default)]
    pub number_of_instructions: Option<u64>,
    #[serde(default)]
    pub number_of_blocks: Option<u64>,
    #[serde(default)]
    pub markov: Option<f64>,
    #[serde(default)]
    pub entropy: Option<f64>,
    #[serde(default)]
    pub contiguous: Option<bool>,
    #[serde(default)]
    pub chromosome_entropy: Option<f64>,
    pub embedding: String,
    pub embeddings: u64,
    pub corpora: Vec<String>,
}

#[derive(Clone, Serialize)]
struct IndexGraphRequest<'a> {
    sha256: &'a str,
    graph: crate::controlflow::GraphSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    attributes: Option<Value>,
    collections: Vec<String>,
    corpora: Vec<String>,
}

#[derive(Clone, Serialize)]
struct IndexEntityRequest<'a> {
    sha256: &'a str,
    #[serde(flatten)]
    entity: IndexEntityBody,
    corpora: Vec<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum IndexEntityBody {
    Function {
        function: crate::controlflow::FunctionJson,
    },
    Block {
        block: crate::controlflow::BlockJson,
    },
    Instruction {
        instruction: crate::controlflow::InstructionJson,
    },
}

#[derive(Clone, Debug, Serialize)]
struct IndexCommitRequest {}

#[derive(Clone, Debug, Serialize)]
struct CollectionTagActionRequest<'a> {
    sha256: &'a str,
    collection: String,
    address: u64,
    tag: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct CollectionTagsReplaceRequest<'a> {
    sha256: &'a str,
    collection: String,
    address: u64,
    tags: Vec<String>,
}

impl Web {
    pub fn new(
        config: Config,
        url: Option<String>,
        verify: Option<bool>,
        api_key: Option<String>,
    ) -> Result<Self, WebError> {
        let url = normalize_url(url.unwrap_or_else(|| "http://127.0.0.1:8080".to_string()))
            .map_err(map_client_error)?;
        let _ = config;
        Ok(Self {
            url,
            verify: verify.unwrap_or(true),
            api_key,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn verify(&self) -> bool {
        self.verify
    }

    pub fn api_key(&self) -> Option<&str> {
        self.api_key.as_deref()
    }

    pub fn set_api_key(&mut self, api_key: Option<String>) {
        self.api_key = api_key;
    }

    pub fn index_graph(
        &self,
        sha256: &str,
        graph: &Graph,
        collections: &[Collection],
        corpora: &[String],
    ) -> Result<WebIndexActionResponse, WebError> {
        self.index_graph_with_request_id(sha256, graph, collections, corpora, None)
    }

    pub fn index_graph_with_request_id(
        &self,
        sha256: &str,
        graph: &Graph,
        collections: &[Collection],
        corpora: &[String],
        request_id: Option<&str>,
    ) -> Result<WebIndexActionResponse, WebError> {
        let request = IndexGraphRequest {
            sha256,
            graph: graph.snapshot(),
            attributes: None,
            collections: collections
                .iter()
                .map(|value| value.as_str().to_string())
                .collect(),
            corpora: corpora.to_vec(),
        };
        self.post_json("/api/v1/index/graph", &request, request_id)
    }

    pub fn index_function(
        &self,
        sha256: &str,
        function: &Function,
        corpora: &[String],
    ) -> Result<WebIndexActionResponse, WebError> {
        self.index_entity(
            "/api/v1/index/function",
            sha256,
            IndexEntityBody::Function {
                function: function.process(),
            },
            corpora,
            None,
        )
    }

    pub fn index_block(
        &self,
        sha256: &str,
        block: &Block,
        corpora: &[String],
    ) -> Result<WebIndexActionResponse, WebError> {
        self.index_entity(
            "/api/v1/index/block",
            sha256,
            IndexEntityBody::Block {
                block: block.process(),
            },
            corpora,
            None,
        )
    }

    pub fn index_instruction(
        &self,
        sha256: &str,
        instruction: &Instruction,
        corpora: &[String],
    ) -> Result<WebIndexActionResponse, WebError> {
        self.index_entity(
            "/api/v1/index/instruction",
            sha256,
            IndexEntityBody::Instruction {
                instruction: instruction.process(),
            },
            corpora,
            None,
        )
    }

    pub fn commit_index(&self) -> Result<WebIndexActionResponse, WebError> {
        self.commit_index_with_request_id(None)
    }

    pub fn commit_index_with_request_id(
        &self,
        request_id: Option<&str>,
    ) -> Result<WebIndexActionResponse, WebError> {
        self.post_json("/api/v1/index/commit", &IndexCommitRequest {}, request_id)
    }

    pub fn clear_index(&self) -> Result<WebIndexActionResponse, WebError> {
        self.clear_index_with_request_id(None)
    }

    pub fn clear_index_with_request_id(
        &self,
        request_id: Option<&str>,
    ) -> Result<WebIndexActionResponse, WebError> {
        self.post_json("/api/v1/index/clear", &IndexCommitRequest {}, request_id)
    }

    pub fn query(
        &self,
        query: &str,
        top_k: usize,
        page: usize,
    ) -> Result<Vec<WebQueryResult>, WebError> {
        self.query_with_request_id(query, top_k, page, None)
    }

    pub fn query_with_request_id(
        &self,
        query: &str,
        top_k: usize,
        page: usize,
        request_id: Option<&str>,
    ) -> Result<Vec<WebQueryResult>, WebError> {
        let response = self.search_response_with_request_id(
            &WebSearchRequest {
                query: query.to_string(),
                top_k: Some(top_k),
                page: Some(page),
            },
            request_id,
        )?;
        Ok(rebuild_query_results(response.results))
    }

    pub fn search(
        &self,
        query: &str,
        top_k: usize,
        page: usize,
    ) -> Result<Vec<WebQueryResult>, WebError> {
        self.query(query, top_k, page)
    }

    pub fn search_response(
        &self,
        request: &WebSearchRequest,
    ) -> Result<WebSearchResponse, WebError> {
        self.search_response_with_request_id(request, None)
    }

    pub fn search_response_with_request_id(
        &self,
        request: &WebSearchRequest,
        request_id: Option<&str>,
    ) -> Result<WebSearchResponse, WebError> {
        self.post_json("/api/v1/search", request, request_id)
    }

    pub fn collection_tags(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<WebTagsResponse, WebError> {
        self.collection_tags_with_request_id(sha256, collection, address, None)
    }

    pub fn collection_tags_with_request_id(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        request_id: Option<&str>,
    ) -> Result<WebTagsResponse, WebError> {
        self.get_json(
            "/api/v1/tags/collection",
            &[
                ("sha256", sha256.to_string()),
                ("collection", collection.as_str().to_string()),
                ("address", address.to_string()),
            ],
            request_id,
        )
    }

    pub fn add_collection_tag(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tag: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.post_json(
            "/api/v1/tags/collection/add",
            &CollectionTagActionRequest {
                sha256,
                collection: collection.as_str().to_string(),
                address,
                tag,
            },
            None,
        )
    }

    pub fn remove_collection_tag(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tag: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.post_json(
            "/api/v1/tags/collection/remove",
            &CollectionTagActionRequest {
                sha256,
                collection: collection.as_str().to_string(),
                address,
                tag,
            },
            None,
        )
    }

    pub fn replace_collection_tags(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tags: &[String],
    ) -> Result<WebTagsActionResponse, WebError> {
        self.post_json(
            "/api/v1/tags/collection/replace",
            &CollectionTagsReplaceRequest {
                sha256,
                collection: collection.as_str().to_string(),
                address,
                tags: tags.to_vec(),
            },
            None,
        )
    }

    pub fn search_collection_tags(
        &self,
        query: &str,
        collection: Option<Collection>,
        page: usize,
        page_size: usize,
    ) -> Result<WebCollectionTagSearchResponse, WebError> {
        let mut query_items = vec![
            ("q", query.to_string()),
            ("page", page.to_string()),
            ("page_size", page_size.to_string()),
        ];
        if let Some(collection) = collection {
            query_items.push(("collection", collection.as_str().to_string()));
        }
        self.get_json("/api/v1/tags/search/collection", &query_items, None)
    }

    fn index_entity(
        &self,
        path: &str,
        sha256: &str,
        entity: IndexEntityBody,
        corpora: &[String],
        request_id: Option<&str>,
    ) -> Result<WebIndexActionResponse, WebError> {
        let request = IndexEntityRequest {
            sha256,
            entity,
            corpora: corpora.to_vec(),
        };
        self.post_json(path, &request, request_id)
    }

    fn http_client(&self) -> Result<HttpClient, WebError> {
        HttpClient::builder()
            .danger_accept_invalid_certs(!self.verify)
            .user_agent(format!("binlex/{}", crate::VERSION))
            .build()
            .map_err(|error| WebError::Protocol(error.to_string()))
    }

    fn apply_auth_headers(
        &self,
        mut builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        if let Some(api_key) = &self.api_key {
            builder = builder.header("Authorization", format!("Bearer {}", api_key));
        }
        builder
    }

    fn post_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        request: &T,
        request_id: Option<&str>,
    ) -> Result<R, WebError> {
        let client = self.http_client()?;
        let mut builder = client
            .post(format!("{}{}", self.url, path))
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .json(request);
        builder = self.apply_auth_headers(builder);
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        decode_web_response(
            builder
                .send()
                .map_err(|error| WebError::Io(error.to_string()))?,
        )
    }

    fn get_json<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        query: &[(&str, String)],
        request_id: Option<&str>,
    ) -> Result<R, WebError> {
        let client = self.http_client()?;
        let mut builder = client
            .get(format!("{}{}", self.url, path))
            .header(ACCEPT, "application/json")
            .query(query);
        builder = self.apply_auth_headers(builder);
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        decode_web_response(
            builder
                .send()
                .map_err(|error| WebError::Io(error.to_string()))?,
        )
    }
}

fn decode_web_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::blocking::Response,
) -> Result<T, WebError> {
    decode_response(response).map_err(map_client_error)
}

fn parse_collection(value: &str) -> Collection {
    match value.to_ascii_lowercase().as_str() {
        "instructions" => Collection::Instruction,
        "blocks" => Collection::Block,
        "functions" => Collection::Function,
        _ => Collection::Function,
    }
}

fn rebuild_query_results(rows: Vec<WebSearchRowResponse>) -> Vec<WebQueryResult> {
    let mut results = Vec::new();
    let mut index = 0usize;
    while index < rows.len() {
        let row = rows[index].clone();
        let score = row.score.or(row.similarity_score).unwrap_or_default();
        if row.grouped && row.side.eq_ignore_ascii_case("lhs") {
            if let Some(next) = rows.get(index + 1).cloned() {
                if next.side.eq_ignore_ascii_case("rhs") {
                    let pair_score = next.score.or(next.similarity_score).unwrap_or(score);
                    results.push(WebQueryResult {
                        lhs: Some(WebResult { inner: row }),
                        rhs: Some(WebResult { inner: next }),
                        score: pair_score,
                    });
                    index += 2;
                    continue;
                }
            }
        }

        let lhs = if row.side.eq_ignore_ascii_case("lhs") {
            Some(WebResult { inner: row.clone() })
        } else {
            None
        };
        let rhs = if row.side.eq_ignore_ascii_case("rhs") {
            Some(WebResult { inner: row })
        } else {
            None
        };
        results.push(WebQueryResult { lhs, rhs, score });
        index += 1;
    }
    results
}

fn map_client_error(error: crate::clients::Error) -> WebError {
    match error {
        crate::clients::Error::InvalidConfiguration(message) => {
            WebError::InvalidConfiguration(message)
        }
        crate::clients::Error::Io(message) => WebError::Io(message),
        crate::clients::Error::Http(status, message) => WebError::Http(status, message),
        crate::clients::Error::Serialization(message) => WebError::Serialization(message),
        crate::clients::Error::Protocol(message) => WebError::Protocol(message),
        crate::clients::Error::Compression(message) => WebError::Protocol(message),
        crate::clients::Error::Graph(message) => WebError::Protocol(message),
    }
}
