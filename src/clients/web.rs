use crate::Config;
use crate::clients::{decode_response, normalize_url};
use crate::controlflow::{Block, Function, Graph, Instruction};
use crate::indexing::Collection;
use crate::server::request_id::X_REQUEST_ID;
use chrono::{DateTime, Utc};
use reqwest::Method;
use reqwest::blocking::Client as HttpClient;
use reqwest::blocking::multipart::{Form, Part};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderName};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

const WEB_VERSION_PATH: &str = "/api/v1/version";
const WEB_TAGS_COLLECTION_PATH: &str = "/api/v1/tags/collection";
const WEB_GRAPH_PATH: &str = "/api/v1/graph";

#[derive(Clone)]
pub struct Web {
    config: Config,
    client: HttpClient,
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
    pub fn corpora(&self) -> &[String] {
        &self.inner.corpora
    }

    pub fn corpora_count(&self) -> usize {
        self.inner.corpora_count
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

    pub fn tag_count(&self) -> usize {
        self.inner.collection_tag_count
    }

    pub fn comment_count(&self) -> usize {
        self.inner.collection_comment_count
    }

    pub fn project_count(&self) -> usize {
        self.inner.sample_project_count
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
pub struct WebVersionResponse {
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebUploadResponse {
    pub ok: bool,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub stored: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebUploadStatusResponse {
    pub sha256: String,
    pub status: String,
    pub timestamp: String,
    #[serde(default)]
    pub error_message: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebMetadataUserResponse {
    pub username: String,
    #[serde(default)]
    pub profile_picture: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebMetadataItemResponse {
    pub name: String,
    pub created_by: WebMetadataUserResponse,
    pub created_timestamp: String,
    #[serde(default)]
    pub assigned_by: Option<WebMetadataUserResponse>,
    #[serde(default)]
    pub assigned_timestamp: Option<String>,
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
    pub tags: Vec<WebMetadataItemResponse>,
    pub page: usize,
    pub limit: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebTagsActionResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebSymbolsResponse {
    pub sha256: String,
    pub collection: String,
    pub architecture: String,
    pub address: u64,
    pub symbols: Vec<WebMetadataItemResponse>,
    pub page: usize,
    pub limit: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebSymbolsCatalogResponse {
    pub symbols: Vec<WebMetadataItemResponse>,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebTagsCatalogResponse {
    pub tags: Vec<WebMetadataItemResponse>,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebCorporaResponse {
    pub sha256: String,
    #[serde(default)]
    pub collection: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub address: Option<u64>,
    pub corpora: Vec<WebMetadataItemResponse>,
    pub page: usize,
    pub limit: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebCorporaCatalogResponse {
    pub corpora: Vec<WebMetadataItemResponse>,
    pub total_results: usize,
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
    #[serde(default)]
    pub total_results: usize,
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
    #[serde(default)]
    pub detail_loaded: bool,
    #[serde(default)]
    pub object_id: String,
    pub timestamp: String,
    pub username: String,
    #[serde(default)]
    pub profile_picture: Option<String>,
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
    #[serde(default)]
    pub corpora_count: usize,
    #[serde(default)]
    pub collection_tag_count: usize,
    #[serde(default)]
    pub collection_comment_count: usize,
    #[serde(default)]
    pub sample_project_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebProjectSummaryResponse {
    pub project_sha256: String,
    pub tool: String,
    pub original_filename: String,
    pub size_bytes: u64,
    pub content_type: String,
    pub container_format: String,
    pub uploaded_by: WebMetadataUserResponse,
    pub uploaded_timestamp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebProjectsResponse {
    pub sha256: String,
    pub projects: Vec<WebProjectSummaryResponse>,
    pub page: usize,
    pub limit: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebProjectAssignedSampleResponse {
    pub sample_sha256: String,
    pub sample_state: String,
    pub assigned_by: WebMetadataUserResponse,
    pub assigned_timestamp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebProjectAssignedSamplesResponse {
    pub project_sha256: String,
    pub samples: Vec<WebProjectAssignedSampleResponse>,
    pub page: usize,
    pub limit: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebProjectUploadResponse {
    pub ok: bool,
    #[serde(default)]
    pub project_sha256: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebSearchDetailResponse {
    pub detail_loaded: bool,
    pub object_id: String,
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
    #[serde(default)]
    pub corpora_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebEntityCommentResponse {
    pub id: i64,
    pub sha256: String,
    pub collection: String,
    pub address: u64,
    pub user: WebMetadataUserResponse,
    pub timestamp: String,
    pub body: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebEntityCommentsResponse {
    pub sha256: String,
    pub collection: String,
    pub address: u64,
    pub items: Vec<WebEntityCommentResponse>,
    pub page: usize,
    pub page_size: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebAdminCommentsResponse {
    pub items: Vec<WebEntityCommentResponse>,
    pub page: usize,
    pub page_size: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebCaptchaResponse {
    pub captcha_id: String,
    pub image_base64: String,
    pub expires: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebAuthUserResponse {
    pub username: String,
    pub key: String,
    pub role: String,
    pub enabled: bool,
    #[serde(default)]
    pub profile_picture: Option<String>,
    pub two_factor_enabled: bool,
    pub two_factor_required: bool,
    pub timestamp: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebAuthSessionResponse {
    pub authenticated: bool,
    pub registration_enabled: bool,
    pub bootstrap_required: bool,
    #[serde(default)]
    pub two_factor_required: bool,
    #[serde(default)]
    pub two_factor_setup_required: bool,
    #[serde(default)]
    pub challenge_token: Option<String>,
    #[serde(default)]
    pub user: Option<WebAuthUserResponse>,
    #[serde(default)]
    pub recovery_codes: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebTwoFactorSetupResponse {
    pub manual_secret: String,
    pub qr_svg: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebKeyRegenerateResponse {
    pub key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebRecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebUsernameCheckResponse {
    pub normalized: String,
    pub valid: bool,
    pub available: bool,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebUsersListResponse {
    pub items: Vec<WebAuthUserResponse>,
    pub page: usize,
    pub limit: usize,
    pub total_results: usize,
    pub has_next: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebAdminUserCreateResponse {
    pub user: WebAuthUserResponse,
    pub key: String,
    pub recovery_codes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebAdminPasswordResetResponse {
    pub username: String,
    pub password: String,
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

#[derive(Clone, Debug, Serialize)]
struct CollectionSymbolActionRequest<'a> {
    sha256: &'a str,
    collection: String,
    architecture: String,
    address: u64,
    symbol: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct CollectionSymbolsReplaceRequest<'a> {
    sha256: &'a str,
    collection: String,
    architecture: String,
    address: u64,
    symbols: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SymbolActionRequest<'a> {
    symbol: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct TagActionRequest<'a> {
    tag: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct CollectionCorpusActionRequest<'a> {
    sha256: &'a str,
    collection: String,
    architecture: String,
    address: u64,
    corpus: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct EntityCommentCreateRequest<'a> {
    sha256: &'a str,
    collection: String,
    address: u64,
    body: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct CorpusActionRequest<'a> {
    corpus: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AuthBootstrapRequest<'a> {
    username: &'a str,
    password: &'a str,
    password_confirm: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AuthLoginRequest<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AuthRegisterRequest<'a> {
    username: &'a str,
    password: &'a str,
    password_confirm: &'a str,
    captcha_id: &'a str,
    captcha_answer: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AuthLoginTwoFactorRequest<'a> {
    challenge_token: &'a str,
    code: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AuthLoginTwoFactorSetupRequest<'a> {
    challenge_token: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct TwoFactorSetupRequest {}

#[derive(Clone, Debug, Serialize)]
struct TwoFactorEnableRequest<'a> {
    current_password: &'a str,
    code: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct TwoFactorDisableRequest<'a> {
    current_password: &'a str,
    code: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct ProfilePasswordRequest<'a> {
    current_password: &'a str,
    new_password: &'a str,
    password_confirm: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct ProfileDeleteRequest<'a> {
    password: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AuthPasswordResetRequest<'a> {
    username: &'a str,
    recovery_code: &'a str,
    new_password: &'a str,
    password_confirm: &'a str,
    captcha_id: &'a str,
    captcha_answer: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AdminUserCreateRequest<'a> {
    username: &'a str,
    password: &'a str,
    password_confirm: &'a str,
    role: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AdminUserRoleRequest<'a> {
    username: &'a str,
    role: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AdminUserNameRequest<'a> {
    username: &'a str,
}

#[derive(Clone, Debug, Serialize)]
struct AdminUserTwoFactorRequiredRequest<'a> {
    username: &'a str,
    required: bool,
}

#[derive(Clone, Debug, Serialize)]
struct AdminUserEnabledRequest<'a> {
    username: &'a str,
    enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebYaraItemRequest {
    pub corpus: String,
    pub sha256: String,
    pub collection: String,
    pub architecture: String,
    pub address: u64,
}

#[derive(Clone, Debug, Serialize)]
struct WebYaraRenderRequest<'a> {
    query: &'a str,
    items: &'a [WebYaraItemRequest],
}

impl Web {
    pub fn new(
        config: Config,
        url: Option<String>,
        verify: Option<bool>,
        api_key: Option<String>,
    ) -> Result<Self, WebError> {
        let url = normalize_url(url.unwrap_or_else(|| "http://127.0.0.1:8000".to_string()))
            .map_err(map_client_error)?;
        let _ = config;
        let verify = verify.unwrap_or(true);
        let client = HttpClient::builder()
            .danger_accept_invalid_certs(!verify)
            .cookie_store(true)
            .user_agent(format!("binlex/{}", crate::VERSION))
            .build()
            .map_err(|error| WebError::Protocol(error.to_string()))?;
        Ok(Self {
            config,
            client,
            url,
            verify,
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

    pub fn version(&self) -> Result<WebVersionResponse, WebError> {
        self.get_json(WEB_VERSION_PATH, &[], None)
    }

    pub fn graph(&self, sha256: &str) -> Result<Graph, WebError> {
        let snapshot: crate::controlflow::GraphSnapshot =
            self.get_json(WEB_GRAPH_PATH, &[("sha256", sha256.to_string())], None)?;
        Graph::from_snapshot(snapshot, self.config.clone())
            .map_err(|error| WebError::Protocol(error.to_string()))
    }

    pub fn upload_sample(
        &self,
        data: &[u8],
        filename: Option<&str>,
        format: Option<&str>,
        architecture: Option<&str>,
        corpora: &[String],
        tags: &[String],
    ) -> Result<WebUploadResponse, WebError> {
        self.upload_sample_with_request_id(
            data,
            filename,
            format,
            architecture,
            corpora,
            tags,
            None,
        )
    }

    pub fn upload_sample_with_request_id(
        &self,
        data: &[u8],
        filename: Option<&str>,
        format: Option<&str>,
        architecture: Option<&str>,
        corpora: &[String],
        tags: &[String],
        request_id: Option<&str>,
    ) -> Result<WebUploadResponse, WebError> {
        let mut form = Form::new().part(
            "data",
            Part::bytes(data.to_vec())
                .file_name(filename.unwrap_or("sample.bin").to_string())
                .mime_str("application/octet-stream")
                .map_err(|error| WebError::Protocol(error.to_string()))?,
        );
        if let Some(format) = format {
            form = form.text("format", format.to_string());
        }
        if let Some(architecture) = architecture {
            form = form.text("architecture", architecture.to_string());
        }
        for corpus in corpora {
            form = form.text("corpus", corpus.clone());
        }
        for tag in tags {
            form = form.text("tag", tag.clone());
        }
        self.post_multipart("/api/v1/index/sample", form, request_id)
    }

    pub fn upload_status(&self, sha256: &str) -> Result<WebUploadStatusResponse, WebError> {
        self.get_json(
            "/api/v1/index/status",
            &[("sha256", sha256.to_string())],
            None,
        )
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

    pub fn search_detail(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        symbol: Option<&str>,
    ) -> Result<WebSearchDetailResponse, WebError> {
        let mut query = vec![
            ("sha256", sha256.to_string()),
            ("collection", collection.as_str().to_string()),
            ("architecture", architecture.to_string()),
            ("address", address.to_string()),
        ];
        if let Some(symbol) = symbol {
            query.push(("symbol", symbol.to_string()));
        }
        self.get_json("/api/v1/search/detail", &query, None)
    }

    pub fn search_tags(
        &self,
        query: &str,
        limit: Option<usize>,
    ) -> Result<WebTagsCatalogResponse, WebError> {
        let mut query_items = vec![("q", query.to_string())];
        if let Some(limit) = limit {
            query_items.push(("limit", limit.to_string()));
        }
        self.get_json("/api/v1/tags/search", &query_items, None)
    }

    pub fn add_tag(&self, tag: &str) -> Result<WebTagsActionResponse, WebError> {
        self.post_json("/api/v1/tags", &TagActionRequest { tag }, None)
    }

    pub fn search_corpora(&self, query: &str) -> Result<WebCorporaCatalogResponse, WebError> {
        self.get_json("/api/v1/corpora", &[("q", query.to_string())], None)
    }

    pub fn add_corpus(&self, corpus: &str) -> Result<WebTagsActionResponse, WebError> {
        self.post_json("/api/v1/corpora", &CorpusActionRequest { corpus }, None)
    }

    pub fn collection_tags(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<WebTagsResponse, WebError> {
        self.collection_tags_with_request_id(sha256, collection, address, None, None, None)
    }

    pub fn collection_tags_with_request_id(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        page: Option<usize>,
        limit: Option<usize>,
        request_id: Option<&str>,
    ) -> Result<WebTagsResponse, WebError> {
        let mut query = vec![
            ("sha256", sha256.to_string()),
            ("collection", collection.as_str().to_string()),
            ("address", address.to_string()),
        ];
        if let Some(page) = page {
            query.push(("page", page.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        self.get_json(WEB_TAGS_COLLECTION_PATH, &query, request_id)
    }

    pub fn add_collection_tag(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        tag: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.send_json(
            Method::POST,
            WEB_TAGS_COLLECTION_PATH,
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
        self.send_json(
            Method::DELETE,
            WEB_TAGS_COLLECTION_PATH,
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
        self.send_json(
            Method::PUT,
            WEB_TAGS_COLLECTION_PATH,
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

    pub fn collection_symbols(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
    ) -> Result<WebSymbolsResponse, WebError> {
        self.collection_symbols_paginated(sha256, collection, architecture, address, None, None)
    }

    pub fn collection_symbols_paginated(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        page: Option<usize>,
        limit: Option<usize>,
    ) -> Result<WebSymbolsResponse, WebError> {
        let mut query = vec![
            ("sha256", sha256.to_string()),
            ("collection", collection.as_str().to_string()),
            ("architecture", architecture.to_string()),
            ("address", address.to_string()),
        ];
        if let Some(page) = page {
            query.push(("page", page.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        self.get_json("/api/v1/symbols/collection", &query, None)
    }

    pub fn search_symbols(
        &self,
        query: &str,
        limit: Option<usize>,
    ) -> Result<WebSymbolsCatalogResponse, WebError> {
        let mut query_items = vec![("q", query.to_string())];
        if let Some(limit) = limit {
            query_items.push(("limit", limit.to_string()));
        }
        self.get_json("/api/v1/symbols/search", &query_items, None)
    }

    pub fn add_symbol(&self, symbol: &str) -> Result<WebTagsActionResponse, WebError> {
        self.post_json("/api/v1/symbols", &SymbolActionRequest { symbol }, None)
    }

    pub fn add_collection_symbol(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        symbol: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.send_json(
            Method::POST,
            "/api/v1/symbols/collection",
            &CollectionSymbolActionRequest {
                sha256,
                collection: collection.as_str().to_string(),
                architecture: architecture.to_string(),
                address,
                symbol,
            },
            None,
        )
    }

    pub fn remove_collection_symbol(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        symbol: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.send_json(
            Method::DELETE,
            "/api/v1/symbols/collection",
            &CollectionSymbolActionRequest {
                sha256,
                collection: collection.as_str().to_string(),
                architecture: architecture.to_string(),
                address,
                symbol,
            },
            None,
        )
    }

    pub fn replace_collection_symbols(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        symbols: &[String],
    ) -> Result<WebTagsActionResponse, WebError> {
        self.send_json(
            Method::PUT,
            "/api/v1/symbols/collection",
            &CollectionSymbolsReplaceRequest {
                sha256,
                collection: collection.as_str().to_string(),
                architecture: architecture.to_string(),
                address,
                symbols: symbols.to_vec(),
            },
            None,
        )
    }

    pub fn collection_corpora(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
    ) -> Result<WebCorporaResponse, WebError> {
        self.collection_corpora_paginated(sha256, collection, architecture, address, None, None)
    }

    pub fn collection_corpora_paginated(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        page: Option<usize>,
        limit: Option<usize>,
    ) -> Result<WebCorporaResponse, WebError> {
        let mut query = vec![
            ("sha256", sha256.to_string()),
            ("collection", collection.as_str().to_string()),
            ("architecture", architecture.to_string()),
            ("address", address.to_string()),
        ];
        if let Some(page) = page {
            query.push(("page", page.to_string()));
        }
        if let Some(limit) = limit {
            query.push(("limit", limit.to_string()));
        }
        self.get_json("/api/v1/corpora/collection", &query, None)
    }

    pub fn add_collection_corpus(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        corpus: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.send_json(
            Method::POST,
            "/api/v1/corpora/collection",
            &CollectionCorpusActionRequest {
                sha256,
                collection: collection.as_str().to_string(),
                architecture: architecture.to_string(),
                address,
                corpus,
            },
            None,
        )
    }

    pub fn remove_collection_corpus(
        &self,
        sha256: &str,
        collection: Collection,
        architecture: &str,
        address: u64,
        corpus: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.send_json(
            Method::DELETE,
            "/api/v1/corpora/collection",
            &CollectionCorpusActionRequest {
                sha256,
                collection: collection.as_str().to_string(),
                architecture: architecture.to_string(),
                address,
                corpus,
            },
            None,
        )
    }

    pub fn entity_comments(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        page: Option<usize>,
        page_size: Option<usize>,
    ) -> Result<WebEntityCommentsResponse, WebError> {
        let mut query = vec![
            ("sha256", sha256.to_string()),
            ("collection", collection.as_str().to_string()),
            ("address", address.to_string()),
        ];
        if let Some(page) = page {
            query.push(("page", page.to_string()));
        }
        if let Some(page_size) = page_size {
            query.push(("page_size", page_size.to_string()));
        }
        self.get_json("/api/v1/comments", &query, None)
    }

    pub fn add_entity_comment(
        &self,
        sha256: &str,
        collection: Collection,
        address: u64,
        body: &str,
    ) -> Result<WebEntityCommentResponse, WebError> {
        self.post_json(
            "/api/v1/comments/add",
            &EntityCommentCreateRequest {
                sha256,
                collection: collection.as_str().to_string(),
                address,
                body,
            },
            None,
        )
    }

    pub fn delete_entity_comment(&self, id: i64) -> Result<WebTagsActionResponse, WebError> {
        self.send_without_body(Method::DELETE, &format!("/api/v1/comments/{id}"), None)
    }

    pub fn admin_comments(
        &self,
        query: &str,
        page: Option<usize>,
        page_size: Option<usize>,
    ) -> Result<WebAdminCommentsResponse, WebError> {
        let mut query_items = vec![("q", query.to_string())];
        if let Some(page) = page {
            query_items.push(("page", page.to_string()));
        }
        if let Some(page_size) = page_size {
            query_items.push(("page_size", page_size.to_string()));
        }
        self.get_json("/api/v1/admin/comments", &query_items, None)
    }

    pub fn render_yara(
        &self,
        query: &str,
        items: &[WebYaraItemRequest],
    ) -> Result<String, WebError> {
        self.post_text(
            "/api/v1/yara/render",
            &WebYaraRenderRequest { query, items },
            None,
        )
    }

    pub fn download_sample(&self, sha256: &str) -> Result<Vec<u8>, WebError> {
        self.get_bytes(
            "/api/v1/download/sample",
            &[("sha256", sha256.to_string())],
            None,
        )
    }

    pub fn download_samples(&self, sha256: &[String]) -> Result<Vec<u8>, WebError> {
        let query = sha256
            .iter()
            .map(|value| ("sha256", value.clone()))
            .collect::<Vec<_>>();
        self.get_bytes("/api/v1/download/samples", &query, None)
    }

    pub fn download_json(
        &self,
        corpus: &str,
        sha256: &str,
        collection: Collection,
        address: u64,
    ) -> Result<Value, WebError> {
        self.get_json(
            "/api/v1/download/json",
            &[
                ("corpus", corpus.to_string()),
                ("sha256", sha256.to_string()),
                ("collection", collection.as_str().to_string()),
                ("address", address.to_string()),
            ],
            None,
        )
    }

    pub fn search_projects(
        &self,
        sample_sha256: &str,
        username: Option<&str>,
        tool: Option<&str>,
        project_sha256: Option<&str>,
        limit: Option<usize>,
        page: Option<usize>,
    ) -> Result<WebProjectsResponse, WebError> {
        let mut query = vec![("sha256", sample_sha256.to_string())];
        if let Some(value) = username {
            query.push(("username", value.to_string()));
        }
        if let Some(value) = tool {
            query.push(("tool", value.to_string()));
        }
        if let Some(value) = project_sha256 {
            query.push(("project_sha256", value.to_string()));
        }
        if let Some(value) = limit {
            query.push(("limit", value.to_string()));
        }
        if let Some(value) = page {
            query.push(("page", value.to_string()));
        }
        self.get_json("/api/v1/projects/search", &query, None)
    }

    pub fn search_project_assignments(
        &self,
        project_sha256: &str,
        sample_sha256: Option<&str>,
        limit: Option<usize>,
        page: Option<usize>,
    ) -> Result<WebProjectAssignedSamplesResponse, WebError> {
        let mut query = Vec::new();
        if let Some(value) = sample_sha256 {
            query.push(("sample_sha256", value.to_string()));
        }
        if let Some(value) = limit {
            query.push(("limit", value.to_string()));
        }
        if let Some(value) = page {
            query.push(("page", value.to_string()));
        }
        self.get_json(
            &format!("/api/v1/projects/{project_sha256}/samples/search"),
            &query,
            None,
        )
    }

    pub fn assign_project_sample(
        &self,
        project_sha256: &str,
        sample_sha256: &str,
        sample_state: Option<&str>,
    ) -> Result<WebIndexActionResponse, WebError> {
        #[derive(Serialize)]
        struct Request<'a> {
            sample_sha256: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            sample_state: Option<&'a str>,
        }
        self.post_json(
            &format!("/api/v1/projects/{project_sha256}/samples"),
            &Request {
                sample_sha256,
                sample_state,
            },
            None,
        )
    }

    pub fn unassign_project_sample(
        &self,
        project_sha256: &str,
        sample_sha256: &str,
    ) -> Result<WebIndexActionResponse, WebError> {
        self.send_without_body(
            Method::DELETE,
            &format!("/api/v1/projects/{project_sha256}/samples/{sample_sha256}"),
            None,
        )
    }

    pub fn download_project(&self, project_sha256: &str) -> Result<Vec<u8>, WebError> {
        self.get_bytes(
            &format!("/api/v1/download/project/{project_sha256}"),
            &[],
            None,
        )
    }

    pub fn auth_bootstrap(
        &self,
        username: &str,
        password: &str,
        password_confirm: &str,
    ) -> Result<WebAuthSessionResponse, WebError> {
        self.post_json(
            "/api/v1/auth/bootstrap",
            &AuthBootstrapRequest {
                username,
                password,
                password_confirm,
            },
            None,
        )
    }

    pub fn auth_login(
        &self,
        username: &str,
        password: &str,
    ) -> Result<WebAuthSessionResponse, WebError> {
        self.post_json(
            "/api/v1/auth/login",
            &AuthLoginRequest { username, password },
            None,
        )
    }

    pub fn auth_login_two_factor(
        &self,
        challenge_token: &str,
        code: &str,
    ) -> Result<WebAuthSessionResponse, WebError> {
        self.post_json(
            "/api/v1/auth/login/2fa",
            &AuthLoginTwoFactorRequest {
                challenge_token,
                code,
            },
            None,
        )
    }

    pub fn auth_login_two_factor_setup(
        &self,
        challenge_token: &str,
    ) -> Result<WebTwoFactorSetupResponse, WebError> {
        self.post_json(
            "/api/v1/auth/login/2fa/setup",
            &AuthLoginTwoFactorSetupRequest { challenge_token },
            None,
        )
    }

    pub fn auth_login_two_factor_enable(
        &self,
        challenge_token: &str,
        code: &str,
    ) -> Result<WebAuthSessionResponse, WebError> {
        self.post_json(
            "/api/v1/auth/login/2fa/enable",
            &AuthLoginTwoFactorRequest {
                challenge_token,
                code,
            },
            None,
        )
    }

    pub fn auth_captcha(&self) -> Result<WebCaptchaResponse, WebError> {
        self.get_json("/api/v1/auth/captcha", &[], None)
    }

    pub fn auth_register(
        &self,
        username: &str,
        password: &str,
        password_confirm: &str,
        captcha_id: &str,
        captcha_answer: &str,
    ) -> Result<WebAuthSessionResponse, WebError> {
        self.post_json(
            "/api/v1/auth/register",
            &AuthRegisterRequest {
                username,
                password,
                password_confirm,
                captcha_id,
                captcha_answer,
            },
            None,
        )
    }

    pub fn auth_logout(&self) -> Result<WebTagsActionResponse, WebError> {
        self.send_without_body(Method::POST, "/api/v1/auth/logout", None)
    }

    pub fn auth_me(&self) -> Result<WebAuthSessionResponse, WebError> {
        self.get_json("/api/v1/auth/me", &[], None)
    }

    pub fn auth_username_check(
        &self,
        username: &str,
    ) -> Result<WebUsernameCheckResponse, WebError> {
        self.get_json(
            "/api/v1/auth/username/check",
            &[("username", username.to_string())],
            None,
        )
    }

    pub fn auth_password_reset(
        &self,
        username: &str,
        recovery_code: &str,
        new_password: &str,
        password_confirm: &str,
        captcha_id: &str,
        captcha_answer: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.post_json(
            "/api/v1/auth/password/reset",
            &AuthPasswordResetRequest {
                username,
                recovery_code,
                new_password,
                password_confirm,
                captcha_id,
                captcha_answer,
            },
            None,
        )
    }

    pub fn profile(&self) -> Result<WebAuthUserResponse, WebError> {
        self.get_json("/api/v1/profile", &[], None)
    }

    pub fn profile_password(
        &self,
        current_password: &str,
        new_password: &str,
        password_confirm: &str,
    ) -> Result<WebTagsActionResponse, WebError> {
        self.post_json(
            "/api/v1/profile/password",
            &ProfilePasswordRequest {
                current_password,
                new_password,
                password_confirm,
            },
            None,
        )
    }

    pub fn profile_picture_upload(
        &self,
        data: &[u8],
        filename: Option<&str>,
    ) -> Result<WebAuthUserResponse, WebError> {
        let form = Form::new().part(
            "picture",
            Part::bytes(data.to_vec())
                .file_name(filename.unwrap_or("avatar.png").to_string())
                .mime_str("image/png")
                .map_err(|error| WebError::Protocol(error.to_string()))?,
        );
        self.post_multipart("/api/v1/profile/picture", form, None)
    }

    pub fn profile_picture_delete(&self) -> Result<WebAuthUserResponse, WebError> {
        self.send_without_body(Method::DELETE, "/api/v1/profile/picture", None)
    }

    pub fn profile_picture_get(&self, username: &str) -> Result<Vec<u8>, WebError> {
        self.get_bytes(&format!("/api/v1/profile/picture/{username}"), &[], None)
    }

    pub fn profile_key_regenerate(&self) -> Result<WebKeyRegenerateResponse, WebError> {
        self.send_without_body(Method::POST, "/api/v1/profile/key/regenerate", None)
    }

    pub fn profile_recovery_regenerate(&self) -> Result<WebRecoveryCodesResponse, WebError> {
        self.send_without_body(Method::POST, "/api/v1/profile/recovery/regenerate", None)
    }

    pub fn profile_two_factor_setup(&self) -> Result<WebTwoFactorSetupResponse, WebError> {
        self.post_json("/api/v1/profile/2fa/setup", &TwoFactorSetupRequest {}, None)
    }

    pub fn profile_two_factor_enable(
        &self,
        current_password: &str,
        code: &str,
    ) -> Result<WebAuthSessionResponse, WebError> {
        self.post_json(
            "/api/v1/profile/2fa/enable",
            &TwoFactorEnableRequest {
                current_password,
                code,
            },
            None,
        )
    }

    pub fn profile_two_factor_disable(
        &self,
        current_password: &str,
        code: &str,
    ) -> Result<WebAuthUserResponse, WebError> {
        self.post_json(
            "/api/v1/profile/2fa/disable",
            &TwoFactorDisableRequest {
                current_password,
                code,
            },
            None,
        )
    }

    pub fn profile_delete(&self, password: &str) -> Result<WebTagsActionResponse, WebError> {
        self.send_json(
            Method::DELETE,
            "/api/v1/profile",
            &ProfileDeleteRequest { password },
            None,
        )
    }

    pub fn admin_users(
        &self,
        query: &str,
        page: Option<usize>,
        limit: Option<usize>,
    ) -> Result<WebUsersListResponse, WebError> {
        let mut query_items = vec![("q", query.to_string())];
        if let Some(page) = page {
            query_items.push(("page", page.to_string()));
        }
        if let Some(limit) = limit {
            query_items.push(("limit", limit.to_string()));
        }
        self.get_json("/api/v1/admin/users", &query_items, None)
    }

    pub fn admin_user_create(
        &self,
        username: &str,
        password: &str,
        password_confirm: &str,
        role: &str,
    ) -> Result<WebAdminUserCreateResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/create",
            &AdminUserCreateRequest {
                username,
                password,
                password_confirm,
                role,
            },
            None,
        )
    }

    pub fn admin_user_role(
        &self,
        username: &str,
        role: &str,
    ) -> Result<WebAuthUserResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/role",
            &AdminUserRoleRequest { username, role },
            None,
        )
    }

    pub fn admin_user_enabled(
        &self,
        username: &str,
        enabled: bool,
    ) -> Result<WebAuthUserResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/enabled",
            &AdminUserEnabledRequest { username, enabled },
            None,
        )
    }

    pub fn admin_user_password_reset(
        &self,
        username: &str,
    ) -> Result<WebAdminPasswordResetResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/password/reset",
            &AdminUserNameRequest { username },
            None,
        )
    }

    pub fn admin_user_key_regenerate(
        &self,
        username: &str,
    ) -> Result<WebKeyRegenerateResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/key/regenerate",
            &AdminUserNameRequest { username },
            None,
        )
    }

    pub fn admin_user_delete(&self, username: &str) -> Result<WebTagsActionResponse, WebError> {
        self.send_without_body(
            Method::DELETE,
            &format!("/api/v1/admin/users/{username}"),
            None,
        )
    }

    pub fn admin_user_picture_delete(
        &self,
        username: &str,
    ) -> Result<WebAuthUserResponse, WebError> {
        self.send_without_body(
            Method::DELETE,
            &format!("/api/v1/admin/users/{username}/picture"),
            None,
        )
    }

    pub fn admin_user_two_factor_require(
        &self,
        username: &str,
        required: bool,
    ) -> Result<WebAuthUserResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/2fa/require",
            &AdminUserTwoFactorRequiredRequest { username, required },
            None,
        )
    }

    pub fn admin_user_two_factor_disable(
        &self,
        username: &str,
    ) -> Result<WebAuthUserResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/2fa/disable",
            &AdminUserNameRequest { username },
            None,
        )
    }

    pub fn admin_user_two_factor_reset(
        &self,
        username: &str,
    ) -> Result<WebAuthUserResponse, WebError> {
        self.post_json(
            "/api/v1/admin/users/2fa/reset",
            &AdminUserNameRequest { username },
            None,
        )
    }

    pub fn admin_delete_corpus(&self, corpus: &str) -> Result<WebTagsActionResponse, WebError> {
        self.send_without_body(
            Method::DELETE,
            &format!("/api/v1/admin/corpora/{corpus}"),
            None,
        )
    }

    pub fn admin_delete_tag(&self, tag: &str) -> Result<WebTagsActionResponse, WebError> {
        self.send_without_body(Method::DELETE, &format!("/api/v1/admin/tags/{tag}"), None)
    }

    pub fn admin_delete_symbol(&self, symbol: &str) -> Result<WebTagsActionResponse, WebError> {
        self.send_without_body(
            Method::DELETE,
            &format!("/api/v1/admin/symbols/{symbol}"),
            None,
        )
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
        self.send_json(Method::POST, path, request, request_id)
    }

    fn send_json<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        request: &T,
        request_id: Option<&str>,
    ) -> Result<R, WebError> {
        let mut builder = self
            .client
            .request(method, format!("{}{}", self.url, path))
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

    fn send_without_body<R: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        request_id: Option<&str>,
    ) -> Result<R, WebError> {
        let mut builder = self
            .client
            .request(method, format!("{}{}", self.url, path))
            .header(ACCEPT, "application/json");
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
        let mut builder = self
            .client
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

    fn post_text<T: Serialize>(
        &self,
        path: &str,
        request: &T,
        request_id: Option<&str>,
    ) -> Result<String, WebError> {
        let mut builder = self
            .client
            .post(format!("{}{}", self.url, path))
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "text/plain")
            .json(request);
        builder = self.apply_auth_headers(builder);
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .send()
            .map_err(|error| WebError::Io(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(map_client_error(
                decode_response::<serde_json::Value>(response)
                    .err()
                    .unwrap_or(crate::clients::Error::Http(
                        status.as_u16(),
                        "request failed".to_string(),
                    )),
            ));
        }
        response
            .text()
            .map_err(|error| WebError::Io(error.to_string()))
    }

    fn post_multipart<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        form: Form,
        request_id: Option<&str>,
    ) -> Result<R, WebError> {
        let mut builder = self
            .client
            .post(format!("{}{}", self.url, path))
            .header(ACCEPT, "application/json")
            .multipart(form);
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

    fn get_bytes(
        &self,
        path: &str,
        query: &[(&str, String)],
        request_id: Option<&str>,
    ) -> Result<Vec<u8>, WebError> {
        let mut builder = self
            .client
            .get(format!("{}{}", self.url, path))
            .query(query);
        builder = self.apply_auth_headers(builder);
        if let Some(request_id) = request_id {
            builder = builder.header(HeaderName::from_static(X_REQUEST_ID), request_id);
        }
        let response = builder
            .send()
            .map_err(|error| WebError::Io(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            return Err(map_client_error(
                decode_response::<serde_json::Value>(response)
                    .err()
                    .unwrap_or(crate::clients::Error::Http(
                        status.as_u16(),
                        "request failed".to_string(),
                    )),
            ));
        }
        response
            .bytes()
            .map(|value| value.to_vec())
            .map_err(|error| WebError::Io(error.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn web_route_constants_match_current_api() {
        assert_eq!(WEB_VERSION_PATH, "/api/v1/version");
        assert_eq!(WEB_TAGS_COLLECTION_PATH, "/api/v1/tags/collection");
    }
}
