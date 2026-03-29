use axum::Json;
use axum::Router;
use axum::extract::{Form, Multipart, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use binlex::client::Client;
use binlex::index::{Collection, LocalIndex, SearchResult};
use binlex::{Architecture, Config, Magic};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::io::Cursor;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task;
use tracing::{info, warn};
use zip::CompressionMethod;
use zip::ZipWriter;
use zip::unstable::write::FileOptionsExt;
use zip::write::FileOptions;

const DEFAULT_LISTEN: &str = "127.0.0.1";
const DEFAULT_PORT: u16 = 8000;
const DEFAULT_URL: &str = "http://127.0.0.1:8000";
const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:5000";
const DEFAULT_TOP_K: usize = 16;
const MAX_TOP_K: usize = 64;
const DEFAULT_CORPUS: &str = "default";
const CONFIG_FILE_NAME: &str = "binlex-web.toml";

#[derive(Parser, Debug)]
#[command(name = "binlex-web")]
struct Args {
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebConfigFile {
    #[serde(default)]
    binlex: BinlexConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BinlexConfig {
    #[serde(default)]
    web: WebRuntimeConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebRuntimeConfig {
    #[serde(default = "default_listen_string")]
    listen: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default = "default_url_string")]
    url: String,
    #[serde(default = "default_corpus_string")]
    corpus: String,
    #[serde(default)]
    server: WebServerConfig,
    #[serde(default)]
    collection: WebCollectionConfig,
    #[serde(default)]
    index: WebIndexConfig,
    #[serde(default)]
    upload: WebUploadConfig,
    #[serde(default)]
    download: WebDownloadConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebServerConfig {
    #[serde(default = "default_server_url_string")]
    url: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebCollectionConfig {
    #[serde(default)]
    instruction: bool,
    #[serde(default)]
    block: bool,
    #[serde(default = "default_true")]
    function: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebIndexConfig {
    #[serde(default)]
    local: WebLocalIndexConfig,
    #[serde(default)]
    remote: WebRemoteIndexConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebLocalIndexConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_local_index_path")]
    path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebRemoteIndexConfig {
    #[serde(default)]
    enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebUploadConfig {
    #[serde(default)]
    samples: WebUploadSamplesConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebUploadSamplesConfig {
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebDownloadConfig {
    #[serde(default)]
    samples: WebDownloadSamplesConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebDownloadSamplesConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_sample_download_password")]
    password: String,
}

impl Default for WebConfigFile {
    fn default() -> Self {
        Self {
            binlex: BinlexConfig::default(),
        }
    }
}

impl Default for BinlexConfig {
    fn default() -> Self {
        Self {
            web: WebRuntimeConfig::default(),
        }
    }
}

impl Default for WebRuntimeConfig {
    fn default() -> Self {
        Self {
            listen: default_listen_string(),
            port: default_port(),
            url: default_url_string(),
            corpus: default_corpus_string(),
            server: WebServerConfig::default(),
            collection: WebCollectionConfig::default(),
            index: WebIndexConfig::default(),
            upload: WebUploadConfig::default(),
            download: WebDownloadConfig::default(),
        }
    }
}

impl Default for WebServerConfig {
    fn default() -> Self {
        Self {
            url: default_server_url_string(),
        }
    }
}

impl Default for WebCollectionConfig {
    fn default() -> Self {
        Self {
            instruction: false,
            block: false,
            function: true,
        }
    }
}

impl Default for WebIndexConfig {
    fn default() -> Self {
        Self {
            local: WebLocalIndexConfig::default(),
            remote: WebRemoteIndexConfig::default(),
        }
    }
}

impl Default for WebLocalIndexConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_local_index_path(),
        }
    }
}

impl Default for WebRemoteIndexConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

impl Default for WebUploadConfig {
    fn default() -> Self {
        Self {
            samples: WebUploadSamplesConfig::default(),
        }
    }
}

impl Default for WebUploadSamplesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
        }
    }
}

impl Default for WebDownloadConfig {
    fn default() -> Self {
        Self {
            samples: WebDownloadSamplesConfig::default(),
        }
    }
}

impl Default for WebDownloadSamplesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            password: default_sample_download_password(),
        }
    }
}

impl WebConfigFile {
    fn default_path() -> Result<PathBuf, Error> {
        let root = dirs::config_dir()
            .ok_or_else(|| Error::other("unable to resolve config directory"))?
            .join("binlex");
        Ok(root.join(CONFIG_FILE_NAME))
    }

    fn ensure_default() -> Result<PathBuf, Error> {
        let path = Self::default_path()?;
        if !path.exists() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(
                &path,
                toml::to_string_pretty(&Self::default()).map_err(Error::other)?,
            )?;
        }
        Ok(path)
    }

    fn load() -> Result<Self, Error> {
        let path = Self::ensure_default()?;
        let raw = fs::read_to_string(&path)?;
        toml::from_str(&raw).map_err(|error| {
            Error::new(
                ErrorKind::InvalidData,
                format!("failed to parse {}: {}", path.display(), error),
            )
        })
    }
}

fn default_true() -> bool {
    true
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_listen_string() -> String {
    DEFAULT_LISTEN.to_string()
}

fn default_url_string() -> String {
    DEFAULT_URL.to_string()
}

fn default_corpus_string() -> String {
    DEFAULT_CORPUS.to_string()
}

fn default_server_url_string() -> String {
    DEFAULT_SERVER_URL.to_string()
}

fn default_local_index_path() -> String {
    dirs::data_local_dir()
        .or_else(dirs::data_dir)
        .unwrap_or_else(std::env::temp_dir)
        .join("binlex")
        .join("index")
        .to_string_lossy()
        .into_owned()
}

fn default_sample_download_password() -> String {
    "infected".to_string()
}

#[derive(Clone)]
struct AppState {
    ui: WebRuntimeConfig,
    client: Client,
    index: LocalIndex,
}

#[derive(Clone, Default, Deserialize, Serialize)]
struct PageParams {
    #[serde(default)]
    search: Option<String>,
    #[serde(default)]
    query: String,
    #[serde(default)]
    uploaded_sha256: Option<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    corpora: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    architectures: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    collections: Vec<String>,
    #[serde(default)]
    top_k: Option<usize>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Default)]
struct UploadForm {
    filename: Option<String>,
    bytes: Vec<u8>,
    format: Option<String>,
    architecture_override: Option<String>,
    query: String,
    uploaded_sha256: Option<String>,
    corpora: Vec<String>,
    architectures: Vec<String>,
    collections: Vec<String>,
    top_k: Option<usize>,
}

#[derive(Default)]
struct PageData {
    corpora_options: Vec<String>,
    architecture_options: Vec<String>,
    collection_options: Vec<String>,
    status: UiStatus,
    uploaded_sha256: Option<String>,
    message: Option<String>,
    error: Option<String>,
    query: String,
    top_k: usize,
    results: Vec<SearchResult>,
    upload_format_options: Vec<String>,
    upload_architecture_options: Vec<String>,
    uploads_enabled: bool,
    sample_downloads_enabled: bool,
}

#[derive(Default)]
struct UiStatus {
    server_ok: bool,
    index_ok: bool,
}

#[derive(Deserialize)]
struct CorporaApiParams {
    #[serde(default)]
    q: String,
}

#[derive(Serialize)]
struct UploadResponse {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct DownloadSampleParams {
    sha256: String,
}

#[derive(Deserialize)]
struct DownloadJsonParams {
    corpus: String,
    sha256: String,
    collection: String,
    address: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QueryField {
    Sha256,
    Vector,
    Corpus,
    Collection,
    Architecture,
    Address,
    Symbol,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QueryTerm {
    field: QueryField,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QueryExpr {
    Term(QueryTerm),
    Not(Box<QueryExpr>),
    And(Box<QueryExpr>, Box<QueryExpr>),
    Or(Box<QueryExpr>, Box<QueryExpr>),
}

#[derive(Clone, Debug)]
enum SearchRoot {
    Sha256(String),
    Vector(Vec<f32>),
}

#[derive(Clone, Debug)]
struct SearchPlan {
    expr: QueryExpr,
    root: Option<SearchRoot>,
    corpora: Vec<String>,
    collections: Vec<Collection>,
    architectures: Vec<Architecture>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum QueryToken {
    Term(QueryTerm),
    And,
    Or,
    Not,
    LParen,
    RParen,
}

fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrVec {
        One(String),
        Many(Vec<String>),
    }

    Ok(match Option::<StringOrVec>::deserialize(deserializer)? {
        Some(StringOrVec::One(value)) => vec![value],
        Some(StringOrVec::Many(values)) => values,
        None => Vec::new(),
    })
}

#[derive(Debug)]
struct AppError(String);

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        Html(format!(
            "<html><body><h1>Binlex Web</h1><p>{}</p></body></html>",
            escape_html(&self.0)
        ))
        .into_response()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut config = WebConfigFile::load()?;
    if let Some(listen) = args.listen {
        config.binlex.web.listen = listen;
    }
    if let Some(port) = args.port {
        config.binlex.web.port = port;
    }
    if let Some(url) = args.url {
        config.binlex.web.url = url;
    }

    tracing_subscriber::fmt().with_target(false).init();
    info!(
        "binlex-web starting bind={} server_url={} corpus={} index_path={} collections=function:{} block:{} instruction:{}",
        format!("{}:{}", config.binlex.web.listen, config.binlex.web.port),
        config.binlex.web.server.url,
        config.binlex.web.corpus,
        config.binlex.web.index.local.path,
        config.binlex.web.collection.function,
        config.binlex.web.collection.block,
        config.binlex.web.collection.instruction
    );

    let analysis_config = build_analysis_config(&config.binlex.web.server.url)?;
    let client = Client::new(
        analysis_config.clone(),
        Some(config.binlex.web.server.url.clone()),
        Some(false),
        Some(true),
    )
    .map_err(|error| Error::other(error.to_string()))?;
    let index = LocalIndex::with_options(
        analysis_config,
        Some(PathBuf::from(expand_path(
            &config.binlex.web.index.local.path,
        ))),
        Some(64),
    )
    .map_err(|error| Error::other(error.to_string()))?;

    let state = Arc::new(AppState {
        ui: config.binlex.web.clone(),
        client,
        index,
    });

    let bind: SocketAddr = format!("{}:{}", config.binlex.web.listen, config.binlex.web.port)
        .parse()
        .map_err(|error| Error::new(ErrorKind::InvalidInput, error))?;
    info!("binlex-web listening on {}", bind);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        run_server(state, bind).await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}

async fn run_server(
    state: Arc<AppState>,
    bind: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let router = Router::new()
        .route("/", get(index_page))
        .route("/search", post(search_page))
        .route("/api/corpora", get(search_corpora_api))
        .route("/upload", post(upload))
        .route("/download/sample", get(download_sample))
        .route("/download/json", get(download_json))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn index_page(
    State(state): State<Arc<AppState>>,
    Query(mut params): Query<PageParams>,
) -> Result<Html<String>, AppError> {
    clamp_top_k(&mut params);
    let state_for_page = state.clone();
    let data = task::spawn_blocking(move || build_page_data(state_for_page.as_ref(), params))
        .await
        .map_err(|error| AppError(error.to_string()))??;
    Ok(Html(render_page(&data)))
}

async fn search_page(
    State(state): State<Arc<AppState>>,
    Form(mut params): Form<PageParams>,
) -> Result<Html<String>, AppError> {
    clamp_top_k(&mut params);
    let state_for_page = state.clone();
    let data = task::spawn_blocking(move || build_page_data(state_for_page.as_ref(), params))
        .await
        .map_err(|error| AppError(error.to_string()))??;
    Ok(Html(render_page(&data)))
}

async fn upload(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<UploadResponse>, AppError> {
    if !state.ui.upload.samples.enabled {
        return Ok(Json(UploadResponse {
            ok: false,
            sha256: None,
            error: Some("sample uploads are disabled".to_string()),
        }));
    }
    let mut form = UploadForm::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| AppError(error.to_string()))?
    {
        let name = field.name().unwrap_or_default().to_string();
        match name.as_str() {
            "file" => {
                form.filename = field.file_name().map(ToOwned::to_owned);
                form.bytes = field
                    .bytes()
                    .await
                    .map_err(|error| AppError(error.to_string()))?
                    .to_vec();
            }
            "format" => {
                let value = field.text().await.unwrap_or_default();
                if !value.trim().is_empty() {
                    form.format = Some(value);
                }
            }
            "architecture_override" => {
                let value = field.text().await.unwrap_or_default();
                if !value.trim().is_empty() {
                    form.architecture_override = Some(value);
                }
            }
            "query" => {
                form.query = field.text().await.unwrap_or_default();
            }
            "uploaded_sha256" => {
                let value = field.text().await.unwrap_or_default();
                if !value.trim().is_empty() {
                    form.uploaded_sha256 = Some(value);
                }
            }
            "corpora" => form.corpora.push(field.text().await.unwrap_or_default()),
            "architectures" => form
                .architectures
                .push(field.text().await.unwrap_or_default()),
            "collections" => form
                .collections
                .push(field.text().await.unwrap_or_default()),
            "top_k" => {
                form.top_k = field
                    .text()
                    .await
                    .ok()
                    .and_then(|value| value.parse::<usize>().ok());
            }
            _ => {}
        }
    }

    let state_for_upload = state.clone();
    let result = task::spawn_blocking(move || ingest_upload(state_for_upload.as_ref(), form))
        .await
        .map_err(|error| AppError(error.to_string()))?;

    match result {
        Ok(params) => Ok(Json(UploadResponse {
            ok: true,
            sha256: params.uploaded_sha256,
            error: None,
        })),
        Err(params) => Ok(Json(UploadResponse {
            ok: false,
            sha256: params.uploaded_sha256,
            error: params.error,
        })),
    }
}

fn build_page_data(state: &AppState, mut params: PageParams) -> Result<PageData, AppError> {
    let corpora_options = state
        .index
        .search_corpora("", 10)
        .map_err(|error| AppError(error.to_string()))?;
    let architecture_options = Architecture::to_vec();
    let mut collection_options = vec![
        Collection::Instruction.as_str().to_string(),
        Collection::Block.as_str().to_string(),
        Collection::Function.as_str().to_string(),
    ];
    collection_options.sort();

    let status = UiStatus {
        server_ok: state.client.health().is_ok(),
        index_ok: state.ui.index.local.enabled,
    };
    info!(
        "page request search={} query_len={} top_k={} server_ok={} index_ok={}",
        params.search.is_some(),
        params.query.len(),
        params.top_k.unwrap_or(DEFAULT_TOP_K),
        status.server_ok,
        status.index_ok
    );

    let mut results = Vec::new();
    if params.search.is_some() {
        match execute_search(state, &params) {
            Ok(items) => {
                info!("page search completed results={}", items.len());
                results = items;
            }
            Err(error) => {
                warn!("page search failed error={}", error);
                params.error = Some(error);
            }
        }
    } else {
        info!("page render without search");
    }
    if let Some(message) = &params.message {
        info!("page message={}", message);
    }
    if let Some(error) = &params.error {
        warn!("page error={}", error);
    }

    Ok(PageData {
        corpora_options,
        architecture_options,
        collection_options,
        status,
        uploaded_sha256: params.uploaded_sha256.clone(),
        message: params.message.clone(),
        error: params.error.clone(),
        query: params.query.clone(),
        top_k: params.top_k.unwrap_or(DEFAULT_TOP_K),
        results,
        upload_format_options: vec![
            "Auto".to_string(),
            "PE".to_string(),
            "ELF".to_string(),
            "Mach-O".to_string(),
            "Shellcode".to_string(),
        ],
        upload_architecture_options: vec![
            "Auto".to_string(),
            display_architecture("amd64"),
            display_architecture("i386"),
            display_architecture("cil"),
        ],
        uploads_enabled: state.ui.upload.samples.enabled,
        sample_downloads_enabled: state.ui.download.samples.enabled,
    })
}

async fn search_corpora_api(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CorporaApiParams>,
) -> Result<Json<Vec<String>>, AppError> {
    info!("corpora api query={}", params.q);
    let state = state.clone();
    let values = task::spawn_blocking(move || state.index.search_corpora(&params.q, 10))
        .await
        .map_err(|error| AppError(error.to_string()))?
        .map_err(|error| AppError(error.to_string()))?;
    info!("corpora api results={}", values.len());
    Ok(Json(values))
}

async fn download_sample(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DownloadSampleParams>,
) -> Result<impl IntoResponse, AppError> {
    if !state.ui.download.samples.enabled {
        return Err(AppError("sample downloads are disabled".to_string()));
    }
    let password = state.ui.download.samples.password.trim().to_string();
    if password.is_empty() {
        return Err(AppError(
            "sample downloads are enabled but no password is configured".to_string(),
        ));
    }
    if !is_sha256(params.sha256.trim()) {
        return Err(AppError("invalid sha256".to_string()));
    }

    let sha256 = params.sha256.trim().to_string();
    let state_for_download = state.clone();
    let sha256_for_download = sha256.clone();
    let password_for_download = password.clone();
    let payload = task::spawn_blocking(move || {
        let bytes = state_for_download
            .index
            .get(&sha256_for_download)
            .map_err(|error| AppError(error.to_string()))?;
        create_encrypted_sample_zip(&sha256_for_download, &bytes, &password_for_download)
            .map_err(|error| AppError(error.to_string()))
    })
    .await
    .map_err(|error| AppError(error.to_string()))??;

    info!("sample download sha256={}", sha256);
    Ok(download_response(
        "application/zip",
        format!("{}.zip", sha256),
        payload,
    ))
}

async fn download_json(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DownloadJsonParams>,
) -> Result<impl IntoResponse, AppError> {
    let collection = parse_collection(&params.collection)
        .ok_or_else(|| AppError("invalid collection".to_string()))?;
    let state_for_download = state.clone();
    let corpus = params.corpus.clone();
    let sha256 = params.sha256.clone();
    let address = params.address;
    let payload = task::spawn_blocking(move || {
        let json = entity_json_for_download(
            state_for_download.as_ref(),
            &corpus,
            &sha256,
            collection,
            address,
        )
        .ok_or_else(|| AppError("entity json is unavailable".to_string()))?;
        serde_json::to_vec_pretty(&json).map_err(|error| AppError(error.to_string()))
    })
    .await
    .map_err(|error| AppError(error.to_string()))??;

    info!(
        "json download corpus={} sha256={} collection={} address={:#x}",
        params.corpus, params.sha256, params.collection, params.address
    );
    Ok(download_response(
        "application/json",
        format!(
            "{}-{}-0x{:x}.json",
            collection.as_str(),
            params.sha256,
            params.address
        ),
        payload,
    ))
}

fn execute_search(state: &AppState, params: &PageParams) -> Result<Vec<SearchResult>, String> {
    let limit = params.top_k.unwrap_or(DEFAULT_TOP_K);
    let query = params.query.trim();
    if query.is_empty() {
        return Err("enter a search query".to_string());
    }
    let plan = build_search_plan(state, query).map_err(|error| error.to_string())?;
    let broad_limit = limit.saturating_mul(8).clamp(64, 512);
    let mut candidates = match &plan.root {
        Some(SearchRoot::Sha256(sha256)) => {
            info!(
                "search root=sha256 sha256={} corpora={:?} collections={:?} architectures={:?} top_k={}",
                sha256, plan.corpora, plan.collections, plan.architectures, limit
            );
            state
                .index
                .exact_search(
                    &plan.corpora,
                    sha256,
                    Some(&plan.collections),
                    &plan.architectures,
                    usize::MAX,
                )
                .map_err(|error| error.to_string())?
        }
        Some(SearchRoot::Vector(vector)) => {
            info!(
                "search root=vector dims={} corpora={:?} collections={:?} architectures={:?} top_k={}",
                vector.len(),
                plan.corpora,
                plan.collections,
                plan.architectures,
                limit
            );
            state
                .index
                .search(
                    &plan.corpora,
                    vector,
                    Some(&plan.collections),
                    &plan.architectures,
                    broad_limit,
                )
                .map_err(|error| error.to_string())?
        }
        None => {
            info!(
                "search root=scan corpora={:?} collections={:?} architectures={:?} top_k={}",
                plan.corpora, plan.collections, plan.architectures, limit
            );
            state
                .index
                .scan_search(
                    &plan.corpora,
                    Some(&plan.collections),
                    &plan.architectures,
                    usize::MAX,
                )
                .map_err(|error| error.to_string())?
        }
    };

    candidates.retain(|result| search_expr_matches(result, &plan.expr, &plan.root));
    candidates.sort_by(|lhs, rhs| rhs.score().total_cmp(&lhs.score()));
    if candidates.len() > limit {
        candidates.truncate(limit);
    }
    Ok(candidates)
}

fn parse_collection(value: &str) -> Option<Collection> {
    match value.trim().to_ascii_lowercase().as_str() {
        "instruction" => Some(Collection::Instruction),
        "block" => Some(Collection::Block),
        "function" => Some(Collection::Function),
        _ => None,
    }
}

fn ingest_upload(state: &AppState, form: UploadForm) -> Result<PageParams, PageParams> {
    let mut params = PageParams {
        query: form.query,
        uploaded_sha256: form.uploaded_sha256,
        top_k: form.top_k,
        ..PageParams::default()
    };
    clamp_top_k(&mut params);

    if form.bytes.is_empty() {
        params.error = Some("no file was selected".to_string());
        return Err(params);
    }

    let corpora = upload_corpora_for_query(state, &params.query);
    let selected = default_collections(&state.ui.collection);
    info!(
        "upload start filename={:?} bytes={} corpora={:?} configured_index_collections={:?} format_override={:?} architecture_override={:?}",
        form.filename,
        form.bytes.len(),
        corpora,
        selected,
        form.format,
        form.architecture_override
    );

    let magic_override = parse_magic_override(form.format.as_deref());
    let architecture_override = if matches!(magic_override, Some(Magic::CODE)) {
        parse_architecture_override(form.architecture_override.as_deref())
    } else {
        None
    };
    let detected_magic = Magic::from_bytes(&form.bytes);
    if matches!(magic_override, Some(Magic::CODE))
        && matches!(detected_magic, Magic::PE | Magic::ELF | Magic::MACHO)
    {
        params.error = Some(format!(
            "shellcode format cannot be used for detected {} input",
            detected_magic
        ));
        return Err(params);
    }
    if matches!(magic_override, Some(Magic::CODE)) && architecture_override.is_none() {
        params.error = Some("shellcode uploads require an architecture override".to_string());
        return Err(params);
    }

    let _graph = match state
        .client
        .analyze_bytes_with_corpora(&form.bytes, magic_override, architecture_override, &corpora)
    {
        Ok(graph) => {
            info!(
                "upload analysis complete architecture={} instructions={}",
                graph.architecture,
                graph.instructions().len()
            );
            graph
        }
        Err(error) => {
            warn!("upload analysis failed error={}", error);
            params.error = Some(format!("upload failed: {}", error));
            return Err(params);
        }
    };

    let sha256 = match state.index.put(&form.bytes) {
        Ok(sha256) => {
            info!("upload sample stored sha256={}", sha256);
            sha256
        }
        Err(error) => {
            warn!("upload sample store failed error={}", error);
            params.error = Some(format!("failed to store sample: {}", error));
            return Err(params);
        }
    };

    info!(
        "upload indexing delegated to binlex-server sha256={} corpora={:?} collections={:?}",
        sha256, corpora, selected
    );

    params.uploaded_sha256 = Some(sha256.clone());
    let filename = form.filename.unwrap_or_else(|| "sample".to_string());
    params.message = Some(format!("uploaded {} ({})", filename, sha256));
    Ok(params)
}

fn upload_corpora_for_query(state: &AppState, query: &str) -> Vec<String> {
    match build_search_plan(state, query) {
        Ok(plan) if !plan.corpora.is_empty() => plan.corpora,
        _ => vec![state.ui.corpus.clone()],
    }
}

fn build_analysis_config(server_url: &str) -> Result<Config, Error> {
    let mut config = Config::default();
    let embeddings = config
        .processors
        .ensure_processor("embeddings")
        .ok_or_else(|| Error::other("embeddings processor is unavailable"))?;
    embeddings.enabled = true;
    embeddings.instructions.enabled = false;
    embeddings.blocks.enabled = false;
    embeddings.functions.enabled = false;
    embeddings.graph.enabled = true;
    embeddings.complete.enabled = false;
    embeddings.transport.ipc.enabled = false;
    embeddings.transport.http.enabled = true;
    embeddings
        .transport
        .http
        .options
        .insert("url".to_string(), server_url.to_string().into());
    embeddings
        .transport
        .http
        .options
        .insert("verify".to_string(), false.into());
    Ok(config)
}

fn resolve_corpora(
    index: &LocalIndex,
    requested: &[String],
    default_corpus: &str,
) -> Result<Vec<String>, binlex::index::local::Error> {
    if !requested.is_empty() {
        return Ok(requested.to_vec());
    }
    let corpora = index.corpora()?;
    if corpora.is_empty() {
        return Ok(vec![default_corpus.to_string()]);
    }
    if corpora.iter().any(|corpus| corpus == default_corpus) {
        return Ok(vec![default_corpus.to_string()]);
    }
    Ok(corpora)
}

fn default_collections(config: &WebCollectionConfig) -> Vec<Collection> {
    let mut collections = Vec::new();
    if config.function {
        collections.push(Collection::Function);
    }
    if config.block {
        collections.push(Collection::Block);
    }
    if config.instruction {
        collections.push(Collection::Instruction);
    }
    if collections.is_empty() {
        collections.push(Collection::Function);
    }
    collections
}

fn build_search_plan(state: &AppState, query: &str) -> Result<SearchPlan, AppError> {
    let tokens = tokenize_search_query(query)?;
    let expr = parse_search_query(&tokens)?;
    let mut analysis = QueryAnalysis::default();
    analyze_query_expr(&expr, &mut analysis, false, false)?;
    let corpora = resolve_corpora(&state.index, &analysis.corpora, &state.ui.corpus)
        .map_err(|error| AppError(error.to_string()))?;
    let collections = if analysis.collections.is_empty() {
        default_collections(&state.ui.collection)
    } else {
        analysis.collections.clone()
    };
    Ok(SearchPlan {
        expr,
        root: analysis.root,
        corpora,
        collections,
        architectures: analysis.architectures,
    })
}

#[derive(Default)]
struct QueryAnalysis {
    root: Option<SearchRoot>,
    corpora: Vec<String>,
    collections: Vec<Collection>,
    architectures: Vec<Architecture>,
}

fn analyze_query_expr(
    expr: &QueryExpr,
    analysis: &mut QueryAnalysis,
    negated: bool,
    inside_or: bool,
) -> Result<(), AppError> {
    match expr {
        QueryExpr::Term(term) => analyze_query_term(term, analysis, negated, inside_or),
        QueryExpr::Not(inner) => analyze_query_expr(inner, analysis, true, inside_or),
        QueryExpr::And(lhs, rhs) => {
            analyze_query_expr(lhs, analysis, negated, inside_or)?;
            analyze_query_expr(rhs, analysis, negated, inside_or)
        }
        QueryExpr::Or(lhs, rhs) => {
            analyze_query_expr(lhs, analysis, negated, true)?;
            analyze_query_expr(rhs, analysis, negated, true)
        }
    }
}

fn analyze_query_term(
    term: &QueryTerm,
    analysis: &mut QueryAnalysis,
    negated: bool,
    inside_or: bool,
) -> Result<(), AppError> {
    match term.field {
        QueryField::Sha256 => {
            if negated || inside_or {
                return Err(AppError(
                    "sha256 queries can only be combined with AND filters".to_string(),
                ));
            }
            if !is_sha256(term.value.trim()) {
                return Err(AppError("sha256 must be 64 hexadecimal characters".to_string()));
            }
            set_search_root(analysis, SearchRoot::Sha256(term.value.trim().to_ascii_lowercase()))
        }
        QueryField::Vector => {
            if negated || inside_or {
                return Err(AppError(
                    "vector queries can only be combined with AND filters".to_string(),
                ));
            }
            let vector = parse_query_vector(term.value.trim()).ok_or_else(|| {
                AppError("vector expects a JSON array with at least two numbers".to_string())
            })?;
            set_search_root(analysis, SearchRoot::Vector(vector))
        }
        QueryField::Corpus if !negated => push_unique_string(&mut analysis.corpora, &term.value),
        QueryField::Collection if !negated => {
            let collection = parse_collection(&term.value)
                .ok_or_else(|| AppError(format!("invalid collection {}", term.value)))?;
            push_unique_collection(&mut analysis.collections, collection);
            Ok(())
        }
        QueryField::Architecture if !negated => {
            let architecture = Architecture::from_string(&term.value)
                .map_err(|_| AppError(format!("invalid architecture {}", term.value)))?;
            push_unique_architecture(&mut analysis.architectures, architecture);
            Ok(())
        }
        _ => Ok(()),
    }
}

fn set_search_root(analysis: &mut QueryAnalysis, root: SearchRoot) -> Result<(), AppError> {
    match (&analysis.root, &root) {
        (None, _) => {
            analysis.root = Some(root);
            Ok(())
        }
        (Some(SearchRoot::Sha256(lhs)), SearchRoot::Sha256(rhs)) if lhs == rhs => Ok(()),
        (Some(SearchRoot::Vector(lhs)), SearchRoot::Vector(rhs))
            if lhs.len() == rhs.len()
                && lhs
                    .iter()
                    .zip(rhs.iter())
                    .all(|(left, right)| (*left - *right).abs() < f32::EPSILON) =>
        {
            Ok(())
        }
        _ => Err(AppError(
            "only one primary search root is supported per query".to_string(),
        )),
    }
}

fn push_unique_string(values: &mut Vec<String>, value: &str) -> Result<(), AppError> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return Err(AppError("query values must not be empty".to_string()));
    }
    if !values.iter().any(|existing| existing == normalized) {
        values.push(normalized.to_string());
    }
    Ok(())
}

fn push_unique_collection(values: &mut Vec<Collection>, value: Collection) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn push_unique_architecture(values: &mut Vec<Architecture>, value: Architecture) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn search_expr_matches(result: &SearchResult, expr: &QueryExpr, root: &Option<SearchRoot>) -> bool {
    match expr {
        QueryExpr::Term(term) => search_term_matches(result, term, root),
        QueryExpr::Not(inner) => !search_expr_matches(result, inner, root),
        QueryExpr::And(lhs, rhs) => {
            search_expr_matches(result, lhs, root) && search_expr_matches(result, rhs, root)
        }
        QueryExpr::Or(lhs, rhs) => {
            search_expr_matches(result, lhs, root) || search_expr_matches(result, rhs, root)
        }
    }
}

fn search_term_matches(
    result: &SearchResult,
    term: &QueryTerm,
    root: &Option<SearchRoot>,
) -> bool {
    let value = term.value.trim();
    match term.field {
        QueryField::Sha256 => result.sha256().eq_ignore_ascii_case(value),
        QueryField::Vector => matches!(root, Some(SearchRoot::Vector(_))),
        QueryField::Corpus => result.corpus().eq_ignore_ascii_case(value),
        QueryField::Collection => result.collection().as_str().eq_ignore_ascii_case(value),
        QueryField::Architecture => result.architecture().eq_ignore_ascii_case(value),
        QueryField::Address => parse_query_address(value) == Some(result.address()),
        QueryField::Symbol => result
            .symbol()
            .map(|symbol| symbol.eq_ignore_ascii_case(value))
            .unwrap_or(false),
    }
}

fn tokenize_search_query(query: &str) -> Result<Vec<QueryToken>, AppError> {
    let chars = query.chars().collect::<Vec<_>>();
    let mut index = 0usize;
    let mut tokens = Vec::new();
    while index < chars.len() {
        if chars[index].is_whitespace() {
            index += 1;
            continue;
        }
        if chars[index] == '(' {
            tokens.push(QueryToken::LParen);
            index += 1;
            continue;
        }
        if chars[index] == ')' {
            tokens.push(QueryToken::RParen);
            index += 1;
            continue;
        }

        if let Some((operator, next_index)) = parse_query_operator(&chars, index) {
            tokens.push(operator);
            index = next_index;
            continue;
        }

        let start = index;
        while index < chars.len()
            && !chars[index].is_whitespace()
            && chars[index] != '('
            && chars[index] != ')'
            && chars[index] != ':'
        {
            index += 1;
        }
        let head = chars[start..index].iter().collect::<String>();
        if index >= chars.len() || chars[index] != ':' {
            return Err(AppError(format!(
                "unexpected token {}. Use explicit fields like sha256: or vector:",
                head
            )));
        }
        index += 1;
        let field = parse_query_field(&head)?;
        skip_query_whitespace(&chars, &mut index);
        let value = match field {
            QueryField::Vector => parse_vector_token_value(&chars, &mut index)?,
            QueryField::Symbol => parse_quoted_query_value(&chars, &mut index)?,
            _ => parse_simple_query_value(&chars, &mut index)?,
        };
        if value.trim().is_empty() {
            return Err(AppError(format!("{} requires a value", head)));
        }
        tokens.push(QueryToken::Term(QueryTerm { field, value }));
    }
    Ok(tokens)
}

fn parse_query_operator(chars: &[char], index: usize) -> Option<(QueryToken, usize)> {
    for (label, token) in [
        ("AND", QueryToken::And),
        ("OR", QueryToken::Or),
        ("NOT", QueryToken::Not),
    ] {
        let end = index + label.len();
        if end > chars.len() {
            continue;
        }
        let candidate = chars[index..end].iter().collect::<String>();
        if candidate.eq_ignore_ascii_case(label)
            && (end == chars.len()
                || chars[end].is_whitespace()
                || chars[end] == '('
                || chars[end] == ')')
        {
            return Some((token, end));
        }
    }
    None
}

fn skip_query_whitespace(chars: &[char], index: &mut usize) {
    while *index < chars.len() && chars[*index].is_whitespace() {
        *index += 1;
    }
}

fn parse_simple_query_value(chars: &[char], index: &mut usize) -> Result<String, AppError> {
    let start = *index;
    while *index < chars.len() && chars[*index] != '(' && chars[*index] != ')' {
        if chars[*index].is_whitespace() && next_query_operator_index(chars, *index).is_some() {
            break;
        }
        *index += 1;
    }
    Ok(chars[start..*index].iter().collect::<String>().trim().to_string())
}

fn next_query_operator_index(chars: &[char], mut index: usize) -> Option<usize> {
    while index < chars.len() && chars[index].is_whitespace() {
        index += 1;
    }
    parse_query_operator(chars, index).map(|_| index)
}

fn parse_quoted_query_value(chars: &[char], index: &mut usize) -> Result<String, AppError> {
    if *index >= chars.len() || chars[*index] != '"' {
        return Err(AppError(
            "symbol expects a quoted string like symbol: \"kernel32:CreateFileW\"".to_string(),
        ));
    }
    *index += 1;
    let mut value = String::new();
    let mut escaped = false;
    while *index < chars.len() {
        let ch = chars[*index];
        *index += 1;
        if escaped {
            value.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Ok(value),
            _ => value.push(ch),
        }
    }
    Err(AppError("symbol expects a closing quote".to_string()))
}

fn parse_vector_token_value(chars: &[char], index: &mut usize) -> Result<String, AppError> {
    skip_query_whitespace(chars, index);
    if *index >= chars.len() || chars[*index] != '[' {
        return Err(AppError("vector expects a JSON array".to_string()));
    }
    let start = *index;
    let mut depth = 0usize;
    while *index < chars.len() {
        match chars[*index] {
            '[' => depth += 1,
            ']' => {
                if depth == 0 {
                    return Err(AppError("vector expects a balanced JSON array".to_string()));
                }
                depth -= 1;
                if depth == 0 {
                    *index += 1;
                    return Ok(chars[start..*index].iter().collect::<String>());
                }
            }
            _ => {}
        }
        *index += 1;
    }
    Err(AppError("vector expects a balanced JSON array".to_string()))
}

fn parse_query_field(value: &str) -> Result<QueryField, AppError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "sha256" => Ok(QueryField::Sha256),
        "vector" => Ok(QueryField::Vector),
        "corpus" => Ok(QueryField::Corpus),
        "collection" => Ok(QueryField::Collection),
        "architecture" => Ok(QueryField::Architecture),
        "address" => Ok(QueryField::Address),
        "symbol" => Ok(QueryField::Symbol),
        other => Err(AppError(format!("unknown search field {}", other))),
    }
}

fn parse_search_query(tokens: &[QueryToken]) -> Result<QueryExpr, AppError> {
    struct Parser<'a> {
        tokens: &'a [QueryToken],
        index: usize,
    }

    impl<'a> Parser<'a> {
        fn parse_or(&mut self) -> Result<QueryExpr, AppError> {
            let mut expr = self.parse_and()?;
            while matches!(self.tokens.get(self.index), Some(QueryToken::Or)) {
                self.index += 1;
                let rhs = self.parse_and()?;
                expr = QueryExpr::Or(Box::new(expr), Box::new(rhs));
            }
            Ok(expr)
        }

        fn parse_and(&mut self) -> Result<QueryExpr, AppError> {
            let mut expr = self.parse_not()?;
            while matches!(self.tokens.get(self.index), Some(QueryToken::And)) {
                self.index += 1;
                let rhs = self.parse_not()?;
                expr = QueryExpr::And(Box::new(expr), Box::new(rhs));
            }
            Ok(expr)
        }

        fn parse_not(&mut self) -> Result<QueryExpr, AppError> {
            if matches!(self.tokens.get(self.index), Some(QueryToken::Not)) {
                self.index += 1;
                return Ok(QueryExpr::Not(Box::new(self.parse_not()?)));
            }
            self.parse_primary()
        }

        fn parse_primary(&mut self) -> Result<QueryExpr, AppError> {
            match self.tokens.get(self.index) {
                Some(QueryToken::Term(term)) => {
                    self.index += 1;
                    Ok(QueryExpr::Term(term.clone()))
                }
                Some(QueryToken::LParen) => {
                    self.index += 1;
                    let expr = self.parse_or()?;
                    match self.tokens.get(self.index) {
                        Some(QueryToken::RParen) => {
                            self.index += 1;
                            Ok(expr)
                        }
                        _ => Err(AppError("unclosed parenthesis".to_string())),
                    }
                }
                Some(_) => Err(AppError("expected a search term".to_string())),
                None => Err(AppError("enter a search query".to_string())),
            }
        }
    }

    let mut parser = Parser { tokens, index: 0 };
    let expr = parser.parse_or()?;
    if parser.index != tokens.len() {
        return Err(AppError("unexpected trailing tokens in query".to_string()));
    }
    Ok(expr)
}

fn parse_query_address(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }
    trimmed.parse::<u64>().ok()
}

fn display_architecture(value: &str) -> String {
    value.to_ascii_uppercase()
}

fn display_collection(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => {
            first.to_uppercase().collect::<String>() + &chars.as_str().to_ascii_lowercase()
        }
        None => String::new(),
    }
}

fn clamp_top_k(params: &mut PageParams) {
    params.top_k = Some(params.top_k.unwrap_or(DEFAULT_TOP_K).clamp(1, MAX_TOP_K));
}

fn expand_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn parse_query_vector(value: &str) -> Option<Vec<f32>> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.starts_with('[') {
        return None;
    }

    let parsed: serde_json::Value = serde_json::from_str(trimmed).ok()?;
    let values = parsed.as_array()?;
    if values.len() < 2 {
        return None;
    }
    values
        .iter()
        .map(|item| item.as_f64().map(|number| number as f32))
        .collect()
}

fn parse_magic_override(value: Option<&str>) -> Option<Magic> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("PE") => Some(Magic::PE),
        Some("ELF") => Some(Magic::ELF),
        Some("Mach-O") => Some(Magic::MACHO),
        Some("Shellcode") => Some(Magic::CODE),
        _ => None,
    }
}

fn parse_architecture_override(value: Option<&str>) -> Option<Architecture> {
    match value.map(str::trim).filter(|value| !value.is_empty()) {
        Some("AMD64") => Some(Architecture::AMD64),
        Some("I386") => Some(Architecture::I386),
        Some("CIL") => Some(Architecture::CIL),
        _ => None,
    }
}

fn entity_json_for_download(
    state: &AppState,
    corpus: &str,
    sha256: &str,
    entity: Collection,
    address: u64,
) -> Option<serde_json::Value> {
    let graph = state.index.load(corpus, sha256).ok()?;
    match entity {
        Collection::Instruction => {
            serde_json::to_value(graph.get_instruction(address)?.process()).ok()
        }
        Collection::Block => serde_json::to_value(binlex::controlflow::Block::new(address, &graph).ok()?.process()).ok(),
        Collection::Function => serde_json::to_value(
            binlex::controlflow::Function::new(address, &graph).ok()?.process(),
        )
        .ok(),
    }
}

fn create_encrypted_sample_zip(sha256: &str, sample: &[u8], password: &str) -> Result<Vec<u8>, Error> {
    let cursor = Cursor::new(Vec::<u8>::new());
    let mut writer = ZipWriter::new(cursor);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o600)
        .with_deprecated_encryption(password.as_bytes());
    writer
        .start_file(format!("{}.bin", sha256), options)
        .map_err(|error| Error::other(error.to_string()))?;
    std::io::Write::write_all(&mut writer, sample).map_err(Error::other)?;
    let cursor = writer.finish().map_err(|error| Error::other(error.to_string()))?;
    Ok(cursor.into_inner())
}

fn download_response(content_type: &str, filename: String, payload: Vec<u8>) -> Response {
    let headers = [
        (
            header::CONTENT_TYPE,
            HeaderValue::from_str(content_type)
                .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream")),
        ),
        (
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!("attachment; filename=\"{}\"", filename))
                .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
        ),
    ];
    (StatusCode::OK, headers, payload).into_response()
}

fn url_encode(value: &str) -> String {
    serde_urlencoded::to_string([("v", value)])
        .unwrap_or_else(|_| format!("v={}", value))
        .trim_start_matches("v=")
        .to_string()
}

fn render_page(data: &PageData) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    html.push_str("<title>Binlex Web</title><style>");
    html.push_str(STYLES);
    html.push_str("</style></head><body><main class=\"page\">");
    html.push_str("<header class=\"header\"><h1>Binlex Web</h1><div class=\"status-row\">");
    html.push_str("<div class=\"theme-toggle\" role=\"group\" aria-label=\"Theme\"><button type=\"button\" class=\"theme-button active\" id=\"theme-dark\" onclick=\"setTheme('dark')\" aria-label=\"Dark mode\">🌙</button><button type=\"button\" class=\"theme-button\" id=\"theme-light\" onclick=\"setTheme('light')\" aria-label=\"Light mode\">☀️</button></div>");
    html.push_str(&status_badge(
        "server",
        if data.status.server_ok {
            "connected"
        } else {
            "disconnected"
        },
        data.status.server_ok,
    ));
    html.push_str(&status_badge("index", "local", data.status.index_ok));
    html.push_str("</div></header>");

    if let Some(message) = &data.message {
        html.push_str(&render_notice("success", message));
    }
    if let Some(error) = &data.error {
        html.push_str(&render_notice("error", error));
    }

    html.push_str("<section class=\"controls\">");
    html.push_str("<div class=\"action-row\">");
    if data.uploads_enabled {
        html.push_str("<form method=\"post\" action=\"/upload\" enctype=\"multipart/form-data\" class=\"upload-form\" id=\"upload-form\">");
        html.push_str("<input id=\"upload-input\" type=\"file\" name=\"file\" class=\"hidden-file\">");
        html.push_str("<input id=\"upload-format\" type=\"hidden\" name=\"format\" value=\"\">");
        html.push_str("<input id=\"upload-architecture-override\" type=\"hidden\" name=\"architecture_override\" value=\"\">");
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"query\" value=\"{}\">",
            escape_html(&data.query)
        ));
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"top_k\" value=\"{}\">",
            data.top_k
        ));
        if let Some(sha256) = &data.uploaded_sha256 {
            html.push_str(&format!(
                "<input type=\"hidden\" name=\"uploaded_sha256\" value=\"{}\">",
                escape_html(sha256)
            ));
        }
        html.push_str("<button class=\"secondary upload-button\" type=\"button\" onclick=\"openUploadModal()\">Upload</button>");
        html.push_str("</form>");
    }
    html.push_str(&format!(
        "<form method=\"post\" action=\"/search\" class=\"search-form\" id=\"search-form\" onsubmit=\"syncSearchState()\" data-corpora='{}' data-architectures='{}' data-collections='{}'>",
        escape_html(&serde_json::to_string(&data.corpora_options).unwrap_or_else(|_| "[]".to_string())),
        escape_html(&serde_json::to_string(&data.architecture_options).unwrap_or_else(|_| "[]".to_string())),
        escape_html(&serde_json::to_string(&data.collection_options).unwrap_or_else(|_| "[]".to_string()))
    ));
    html.push_str("<input type=\"hidden\" name=\"search\" value=\"1\">");
    if let Some(sha256) = &data.uploaded_sha256 {
        html.push_str(&format!(
            "<input type=\"hidden\" name=\"uploaded_sha256\" value=\"{}\">",
            escape_html(sha256)
        ));
    }
    html.push_str("<div class=\"search-stack\">");
    html.push_str("<div class=\"search-row\">");
    html.push_str(&format!(
        "<input type=\"hidden\" name=\"top_k\" id=\"top-k-input\" value=\"{}\">",
        data.top_k
    ));
    html.push_str(&format!(
        "<input class=\"search-input\" id=\"query-input\" type=\"text\" name=\"query\" value=\"{}\" placeholder=\"sha256: ... AND corpus: default\" autocomplete=\"off\" oninput=\"updateQueryAssistant()\" onfocus=\"updateQueryAssistant()\" onkeydown=\"handleQueryInputKeydown(event)\">",
        escape_html(&data.query)
    ));
    html.push_str(&format!(
        "<div class=\"top-k-control\"><button type=\"button\" class=\"secondary top-k-trigger\" id=\"top-k-trigger\" onclick=\"toggleTopKPopover()\">Top K: <span id=\"top-k-label\">{}</span></button><div class=\"top-k-popover\" id=\"top-k-popover\" hidden><div class=\"top-k-slider-wrap\"><span class=\"top-k-tick top\">64</span><input type=\"range\" min=\"1\" max=\"64\" value=\"{}\" id=\"top-k-slider\" class=\"top-k-slider\" orient=\"vertical\" oninput=\"updateTopKValue(this.value)\"><span class=\"top-k-tick bottom\">1</span></div></div></div>",
        data.top_k,
        data.top_k
    ));
    html.push_str("<button class=\"primary\" type=\"submit\">Search</button>");
    html.push_str("</div>");
    html.push_str("<div class=\"query-assistant\" id=\"query-assistant\" hidden>");
    html.push_str("</div></div></form></div></section>");

    html.push_str("<section class=\"results\"><table><thead><tr>");
    for header in [
        "score",
        "corpus",
        "architecture",
        "sha256",
        "collection",
        "address",
        "symbol",
        "action",
    ] {
        let class = if header == "action" {
            " class=\"action-cell\""
        } else {
            ""
        };
        html.push_str(&format!("<th{}>{}</th>", class, escape_html(header)));
    }
    html.push_str("</tr></thead><tbody>");

    if data.results.is_empty() {
        html.push_str("<tr><td colspan=\"8\" class=\"empty\">No results yet.</td></tr>");
    } else {
        for result in &data.results {
            html.push_str("<tr>");
            html.push_str(&format!("<td>{:.4}</td>", result.score()));
            html.push_str(&format!("<td>{}</td>", escape_html(result.corpus())));
            html.push_str(&format!(
                "<td>{}</td>",
                escape_html(&display_architecture(result.architecture()))
            ));
            html.push_str(&format!(
                "<td class=\"sha256-cell\"><code>{}</code></td>",
                escape_html(result.sha256())
            ));
            html.push_str(&format!(
                "<td>{}</td>",
                escape_html(&display_collection(result.collection().as_str()))
            ));
            html.push_str(&format!("<td>{:#x}</td>", result.address()));
            html.push_str(&format!(
                "<td>{}</td>",
                escape_html(result.symbol().unwrap_or("-"))
            ));
            html.push_str(&format!(
                "<td class=\"action-cell\">{}</td>",
                render_result_actions(result, data.sample_downloads_enabled)
            ));
            html.push_str("</tr>");
        }
    }
    html.push_str("</tbody></table></section>");
    if data.uploads_enabled {
        html.push_str(&render_upload_modal(data));
    }
    html.push_str("<script>");
    html.push_str(SCRIPT);
    html.push_str("</script></main></body></html>");
    html
}

fn render_notice(kind: &str, message: &str) -> String {
    format!(
        "<div class=\"notice {}\"><span>{}</span><button type=\"button\" class=\"notice-dismiss\" onclick=\"dismissNotice(this)\">Close</button></div>",
        escape_html(kind),
        escape_html(message)
    )
}

fn render_result_actions(result: &SearchResult, sample_downloads_enabled: bool) -> String {
    let actions = build_result_action_tree(result, sample_downloads_enabled);
    if actions.is_empty() {
        return "-".to_string();
    }
    let mut html = String::from(
        "<details class=\"row-actions\"><summary class=\"row-actions-trigger\">Actions</summary><div class=\"menu row-actions-menu\">",
    );
    html.push_str(&format!(
        "<div class=\"row-actions-shell\" data-actions=\"{}\" data-path=\"\"><div class=\"row-actions-header\"><button type=\"button\" class=\"secondary row-actions-back\" onclick=\"navigateRowActions(this)\" hidden>Back</button><div class=\"row-actions-breadcrumb\">Actions</div></div><input class=\"menu-search\" type=\"text\" placeholder=\"Search actions\" oninput=\"renderRowActionMenu(this.closest('.row-actions-shell'))\"><div class=\"row-action-options\"></div></div>",
        escape_html(&serde_json::to_string(&actions).unwrap_or_else(|_| "[]".to_string()))
    ));
    html.push_str("</div></details>");
    html
}

fn build_result_action_tree(result: &SearchResult, sample_downloads_enabled: bool) -> Vec<serde_json::Value> {
    let mut copy_children = Vec::<serde_json::Value>::new();
    let mut root = Vec::<serde_json::Value>::new();

    if let Some(json) = result.json() {
        copy_children.push(action_leaf(
            "JSON",
            serde_json::to_string(json).unwrap_or_else(|_| "null".to_string()),
        ));
    }
    if !result.vector().is_empty() {
        copy_children.push(action_leaf(
            "Vector",
            serde_json::to_string(result.vector()).unwrap_or_else(|_| "[]".to_string()),
        ));
    }
    copy_children.push(action_leaf("Address", format!("{:#x}", result.address())));
    copy_children.push(action_leaf("SHA256", result.sha256().to_string()));
    copy_children.push(action_leaf("Corpus", result.corpus().to_string()));
    copy_children.push(action_leaf(
        "Architecture",
        result.architecture().to_string(),
    ));
    if let Some(symbol) = result.symbol().filter(|symbol| *symbol != "-") {
        copy_children.push(action_leaf("Symbol", symbol.to_string()));
    }

    if let Some(chromosome) = result.json().and_then(|json| json.get("chromosome")) {
        let mut chromosome_children = Vec::<serde_json::Value>::new();
        if let Some(pattern) = chromosome
            .get("pattern")
            .and_then(serde_json::Value::as_str)
        {
            chromosome_children.push(action_leaf("Pattern", pattern.to_string()));
        }
        if let Some(minhash) = chromosome
            .get("minhash")
            .and_then(serde_json::Value::as_str)
        {
            chromosome_children.push(action_leaf("Minhash", minhash.to_string()));
        }
        if let Some(tlsh) = chromosome.get("tlsh").and_then(serde_json::Value::as_str) {
            chromosome_children.push(action_leaf("TLSH", tlsh.to_string()));
        }
        if let Some(sha256) = chromosome.get("sha256").and_then(serde_json::Value::as_str) {
            chromosome_children.push(action_leaf("SHA256", sha256.to_string()));
        }
        if !chromosome_children.is_empty() {
            copy_children.push(action_branch("Chromosome", chromosome_children));
        }
    }

    if !copy_children.is_empty() {
        root.push(action_branch("Copy", copy_children));
    }

    let mut download_children = Vec::<serde_json::Value>::new();
    if sample_downloads_enabled {
        download_children.push(action_download(
            "Sample",
            format!("/download/sample?sha256={}", url_encode(result.sha256())),
        ));
    }
    if result.json().is_some() {
        download_children.push(action_download(
            "JSON",
            format!(
                "/download/json?corpus={}&sha256={}&collection={}&address={}",
                url_encode(result.corpus()),
                url_encode(result.sha256()),
                url_encode(result.collection().as_str()),
                result.address()
            ),
        ));
    }
    if !download_children.is_empty() {
        root.push(action_branch("Download", download_children));
    }

    root
}

fn action_leaf(label: &str, payload: String) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "payload": payload,
    })
}

fn action_branch(label: &str, children: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "children": children,
    })
}

fn action_download(label: &str, url: String) -> serde_json::Value {
    serde_json::json!({
        "label": label,
        "action": "download",
        "url": url,
    })
}

fn render_upload_modal(data: &PageData) -> String {
    let mut html = String::new();
    html.push_str("<div id=\"upload-modal\" class=\"modal-backdrop\" hidden>");
    html.push_str(
        "<div class=\"modal-card\" role=\"dialog\" aria-modal=\"true\" aria-label=\"Upload\">",
    );
    html.push_str("<div class=\"modal-grid modal-grid-single\">");
    html.push_str("<div class=\"modal-field modal-file-field\">");
    html.push_str("<input id=\"upload-file-picker\" type=\"file\" class=\"hidden-file\">");
    html.push_str(
        "<label for=\"upload-file-picker\" id=\"upload-dropzone\" class=\"upload-dropzone\">",
    );
    html.push_str("<strong>Click to Upload or Drag and Drop</strong>");
    html.push_str("<em id=\"upload-file-name\">No file selected</em>");
    html.push_str("</label>");
    html.push_str("</div>");
    html.push_str("<div class=\"modal-select-row\">");
    html.push_str(&render_single_select_dropdown(
        "upload-format",
        "Format",
        &data.upload_format_options,
        "Auto",
    ));
    html.push_str(&render_single_select_dropdown(
        "upload-architecture",
        "Architecture",
        &data.upload_architecture_options,
        "Auto",
    ));
    html.push_str("</div>");
    html.push_str("</div>");
    html.push_str("<p id=\"upload-modal-tip\" class=\"modal-tip\"></p>");
    html.push_str("<div class=\"modal-actions\">");
    html.push_str("<button type=\"button\" class=\"secondary\" onclick=\"closeUploadModal()\">Cancel</button>");
    html.push_str("<button type=\"button\" class=\"primary\" id=\"upload-submit\" onclick=\"submitUploadModal()\">Upload</button>");
    html.push_str("</div></div></div>");
    html.push_str("<div id=\"upload-status-modal\" class=\"modal-backdrop\" hidden>");
    html.push_str(
        "<div class=\"modal-card upload-status-card\" role=\"dialog\" aria-modal=\"true\" aria-label=\"Upload Status\">",
    );
    html.push_str("<div class=\"upload-status-body\">");
    html.push_str("<div id=\"upload-status-icon\" class=\"upload-status-icon uploading\"><div class=\"upload-status-spinner\"></div><div class=\"upload-status-checkmark\">&#10003;</div><div class=\"upload-status-fail\">!</div></div>");
    html.push_str("<h2 id=\"upload-status-title\">Uploading Sample</h2>");
    html.push_str("<p id=\"upload-status-text\" class=\"modal-tip\">Binlex Web is uploading and processing the sample.</p>");
    html.push_str("<div id=\"upload-status-extra\"></div>");
    html.push_str("</div><div class=\"modal-actions\">");
    html.push_str("<button type=\"button\" class=\"secondary\" id=\"upload-status-close\" onclick=\"closeUploadStatusModal()\" hidden>Close</button>");
    html.push_str("</div></div></div>");
    html
}

fn render_single_select_dropdown(
    name: &str,
    label: &str,
    options: &[String],
    selected: &str,
) -> String {
    let mut html = format!(
        "<details class=\"multiselect modal-select\" data-single-select=\"{}\"><summary>{}: {}</summary><div class=\"menu\">",
        escape_html(name),
        escape_html(label),
        escape_html(selected)
    );
    html.push_str(&format!(
        "<input class=\"menu-search\" type=\"text\" placeholder=\"Search {}\" oninput=\"filterSingleOptions(this, '{}')\">",
        escape_html(label),
        escape_html(name)
    ));
    html.push_str("<div class=\"menu-options\">");
    for option in options {
        let checked = if option == selected { " checked" } else { "" };
        html.push_str(&format!(
            "<label class=\"menu-option\" data-single-group=\"{}\" data-option=\"{}\"><input type=\"radio\" name=\"{}\" value=\"{}\"{} onchange=\"selectSingleOption('{}', this.value)\"> <span>{}</span></label>",
            escape_html(name),
            escape_html(option),
            escape_html(name),
            escape_html(option),
            checked,
            escape_html(name),
            escape_html(option)
        ));
    }
    html.push_str("</div></div></details>");
    html
}

fn status_badge(label: &str, value: &str, healthy: bool) -> String {
    format!(
        "<span class=\"status\"><span class=\"dot {}\"></span>{}: {}</span>",
        if healthy { "ok" } else { "fail" },
        escape_html(label),
        escape_html(value)
    )
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

const STYLES: &str = r#"
:root {
  --bg: #0e1318;
  --bg-soft: #151d24;
  --card: rgba(20, 28, 35, 0.94);
  --card-strong: #1a232c;
  --surface: #18222b;
  --surface-soft: #10171d;
  --surface-strong: #0e151b;
  --modal-card: #11171d;
  --ink: #e8edf2;
  --muted: #94a3b2;
  --line: #2d3945;
  --accent: #4fbf8f;
  --accent-soft: rgba(79, 191, 143, 0.14);
  --warn: #d86c62;
}
body[data-theme="light"] {
  --bg: #eef3f7;
  --bg-soft: #dfe8ef;
  --card: rgba(248, 251, 253, 0.96);
  --card-strong: #e7eef4;
  --surface: #f4f8fb;
  --surface-soft: #ffffff;
  --surface-strong: #edf3f7;
  --modal-card: #f8fbfd;
  --ink: #15202b;
  --muted: #5d7082;
  --line: #c6d4e0;
  --accent: #2a9a68;
  --accent-soft: rgba(42, 154, 104, 0.14);
  --warn: #c2574d;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
  color: var(--ink);
  background: radial-gradient(circle at top, var(--bg-soft), var(--bg));
}
.page { max-width: 1400px; margin: 0 auto; padding: 24px; }
.header, .controls, .results, .notice {
  background: var(--card);
  border: 1px solid var(--line);
  border-radius: 16px;
  box-shadow: 0 14px 40px rgba(0, 0, 0, 0.28);
  backdrop-filter: blur(10px);
}
.header, .notice { position: relative; z-index: 5; }
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 18px 22px;
}
.header h1 { margin: 0; font-size: 1.8rem; letter-spacing: -0.03em; }
.status-row { display: flex; gap: 18px; flex-wrap: wrap; }
.theme-toggle {
  display: inline-flex;
  align-items: center;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--card-strong);
  overflow: hidden;
}
.theme-button {
  border: 0;
  background: transparent;
  color: var(--muted);
  min-height: 36px;
  padding: 0 12px;
  cursor: pointer;
  font-size: 1rem;
}
.theme-button.active {
  background: var(--accent-soft);
  color: var(--ink);
}
.status { display: inline-flex; align-items: center; gap: 10px; color: var(--muted); }
.dot {
  width: 11px;
  height: 11px;
  border-radius: 999px;
  display: inline-block;
}
.dot.ok { background: #1f8a48; box-shadow: 0 0 0 4px rgba(31, 138, 72, 0.15); }
.dot.fail { background: #bf2d24; box-shadow: 0 0 0 4px rgba(191, 45, 36, 0.15); }
.notice { margin-top: 16px; padding: 12px 16px; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
.notice.success { border-color: #2d6f55; background: rgba(24, 76, 55, 0.4); }
.notice.error { border-color: #7a3d39; background: rgba(104, 39, 34, 0.38); }
.notice-dismiss {
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 7px 10px;
  cursor: pointer;
  background: var(--card-strong);
  color: var(--ink);
  white-space: nowrap;
}
.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.74);
  display: grid;
  place-items: center;
  z-index: 2000;
}
.modal-backdrop[hidden] { display: none !important; }
.modal-card {
  width: min(560px, calc(100vw - 32px));
  background: var(--modal-card);
  border: 1px solid var(--line);
  border-radius: 18px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.55);
  padding: 18px;
}
.modal-header,
.modal-actions {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}
.modal-header h2 { margin: 0; font-size: 1.15rem; }
.modal-grid {
  display: grid;
  gap: 14px;
  margin-top: 16px;
}
.modal-grid-single { grid-template-columns: 1fr; }
.modal-field {
  display: grid;
  gap: 8px;
  color: var(--muted);
}
.modal-field span { font-size: 0.9rem; }
.modal-select-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.upload-dropzone {
  min-height: 138px;
  border: 1px dashed var(--line);
  border-radius: 16px;
  background: var(--surface-strong);
  display: grid;
  place-items: center;
  text-align: center;
  gap: 8px;
  padding: 20px;
  cursor: pointer;
}
.upload-dropzone strong { color: var(--ink); }
.upload-dropzone span,
.upload-dropzone em { color: var(--muted); font-style: normal; }
.upload-dropzone.dragging {
  border-color: var(--accent);
  background: rgba(79, 191, 143, 0.12);
}
.modal-select .menu {
  position: absolute;
  z-index: 2100;
}
.modal-tip {
  color: var(--muted);
  margin: 14px 0 0;
}
.upload-status-card {
  width: min(520px, calc(100vw - 32px));
}
.upload-status-card .modal-actions {
  justify-content: center;
  margin-top: 16px;
}
.upload-status-body {
  display: grid;
  gap: 14px;
  justify-items: center;
  text-align: center;
}
.upload-status-body h2 {
  margin: 0;
  font-size: 1.3rem;
}
.upload-status-icon {
  width: 72px;
  height: 72px;
  border-radius: 999px;
  display: grid;
  place-items: center;
  border: 1px solid var(--line);
  background: var(--surface-strong);
}
.upload-status-spinner {
  width: 30px;
  height: 30px;
  border-radius: 999px;
  border: 3px solid rgba(79, 191, 143, 0.22);
  border-top-color: var(--accent);
  animation: spin 1s linear infinite;
}
.upload-status-checkmark,
.upload-status-fail {
  display: none;
  font-size: 2rem;
  font-weight: 700;
}
.upload-status-icon.success {
  border-color: var(--accent);
  background: rgba(79, 191, 143, 0.12);
}
.upload-status-icon.success .upload-status-spinner,
.upload-status-icon.failed .upload-status-spinner {
  display: none;
}
.upload-status-icon.success .upload-status-checkmark {
  display: block;
  color: var(--accent);
}
.upload-status-icon.failed {
  border-color: var(--warn);
  background: rgba(216, 108, 98, 0.12);
}
.upload-status-icon.failed .upload-status-fail {
  display: block;
  color: var(--warn);
}
.upload-status-sha {
  width: 100%;
  display: grid;
  gap: 8px;
  text-align: left;
}
.upload-status-sha span {
  color: var(--muted);
  font-size: 0.9rem;
}
.upload-status-sha-row {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 10px;
  align-items: center;
}
.upload-status-sha-row code {
  padding: 10px 12px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--surface-soft);
  word-break: break-all;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
.controls {
  margin-top: 16px;
  padding: 16px;
  display: grid;
  gap: 12px;
  position: relative;
  overflow: visible;
  z-index: 100;
}
.action-row {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 12px;
  align-items: center;
  position: relative;
  z-index: 1;
}
.search-form {
  min-width: 0;
  position: relative;
}
.search-stack {
  position: relative;
}
.search-row {
  display: grid;
  grid-template-columns: 1fr auto auto;
  gap: 12px;
  align-items: center;
}
.query-assistant {
  position: absolute;
  top: calc(100% + 8px);
  left: 0;
  right: 0;
  z-index: 1200;
  display: block;
}
.query-assistant-menu {
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  z-index: 1201;
  display: grid;
  gap: 6px;
  padding: 10px;
  border: 1px solid var(--line);
  border-top: none;
  border-bottom-left-radius: 12px;
  border-bottom-right-radius: 12px;
  background: var(--surface);
  box-shadow: 0 18px 42px rgba(0, 0, 0, 0.45);
}
.query-suggestion {
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 9px 10px;
  cursor: pointer;
  background: var(--card-strong);
  color: var(--ink);
  text-align: left;
}
.query-suggestion.active {
  border-color: var(--accent);
  background: var(--accent-soft);
}
.upload-form { margin: 0; }
.upload-button {
  min-width: 100px;
  min-height: 46px;
  align-self: stretch;
}
.hidden-file { display: none; }
.multiselect {
  display: block;
  position: relative;
  z-index: 60;
}
.multiselect.disabled summary {
  opacity: 0.6;
  cursor: not-allowed;
  pointer-events: none;
}
.multiselect summary {
  list-style: none;
  cursor: pointer;
  padding: 11px 14px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--card-strong);
  color: var(--ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.multiselect[open] summary { border-bottom-left-radius: 0; border-bottom-right-radius: 0; }
.menu {
  position: absolute;
  top: calc(100% - 1px);
  left: 0;
  right: 0;
  z-index: 999;
  padding: 10px;
  border: 1px solid var(--line);
  border-top: none;
  border-bottom-left-radius: 12px;
  border-bottom-right-radius: 12px;
  background: var(--surface);
  box-shadow: 0 18px 42px rgba(0, 0, 0, 0.45);
}
.menu-search, .search-input {
  width: 100%;
  height: 46px;
  padding: 11px 12px;
  border: 1px solid var(--line);
  border-radius: 12px;
  background: var(--surface-soft);
  color: var(--ink);
}
.search-input::placeholder, .menu-search::placeholder { color: #708090; }
.menu-actions {
  display: flex;
  gap: 8px;
  margin: 10px 0;
}
.menu-actions button, .secondary, .primary {
  border: 1px solid var(--line);
  border-radius: 12px;
  height: 46px;
  padding: 11px 14px;
  min-height: 46px;
  cursor: pointer;
  background: var(--card-strong);
  color: var(--ink);
}
.primary {
  background: var(--accent);
  color: var(--surface-strong);
  border-color: var(--accent);
}
.secondary { background: var(--card-strong); }
.menu-options {
  max-height: 180px;
  overflow: auto;
  display: grid;
  gap: 6px;
}
.menu-options.selected-only .menu-option:not(.selected-match) { display: none !important; }
.menu-option { color: var(--ink); }
.top-k-control {
  position: relative;
  justify-self: end;
}
.top-k-trigger {
  width: 120px;
  white-space: nowrap;
  position: relative;
  z-index: 1302;
}
.top-k-control.open .top-k-trigger {
  border-bottom-left-radius: 0;
  border-bottom-right-radius: 0;
  border-color: var(--line);
  border-bottom-color: transparent;
  background: var(--surface);
}
.top-k-popover {
  position: absolute;
  top: calc(100% - 1px);
  right: 0;
  z-index: 1301;
  width: 120px;
  padding: 12px 12px 14px;
  border: 1px solid var(--line);
  border-top: none;
  border-bottom-left-radius: 14px;
  border-bottom-right-radius: 14px;
  background: var(--surface);
  box-shadow: 0 18px 42px rgba(0, 0, 0, 0.45);
  display: grid;
  justify-items: center;
  gap: 10px;
}
.top-k-popover[hidden] {
  display: none !important;
}
.top-k-slider-wrap {
  position: relative;
  height: 180px;
  width: 56px;
  display: grid;
  justify-items: center;
  align-items: center;
}
.top-k-slider {
  -webkit-appearance: none;
  appearance: none;
  width: 150px;
  height: 12px;
  transform: rotate(-90deg);
  border-radius: 999px;
  background: linear-gradient(90deg, rgba(79, 191, 143, 0.28) 0%, var(--accent) 100%);
  outline: none;
}
.top-k-slider::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 18px;
  height: 18px;
  border-radius: 999px;
  border: 2px solid var(--surface-strong);
  background: var(--accent);
  cursor: pointer;
}
.top-k-slider::-moz-range-thumb {
  width: 18px;
  height: 18px;
  border-radius: 999px;
  border: 2px solid var(--surface-strong);
  background: var(--accent);
  cursor: pointer;
}
.top-k-tick {
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  color: var(--muted);
  font-size: 0.84rem;
}
.top-k-tick.top { top: -2px; }
.top-k-tick.bottom { bottom: -2px; }
.results { margin-top: 16px; overflow-x: auto; position: relative; z-index: 1; }
table { width: 100%; min-width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 12px 14px; border-bottom: 1px solid var(--line); }
th { font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
.sha256-cell code { word-break: break-all; }
.action-cell { width: 1%; white-space: nowrap; }
tbody tr:hover { background: rgba(79,191,143,0.08); }
.empty { color: var(--muted); text-align: center; padding: 28px; }
.row-actions {
  display: block;
  position: relative;
}
.row-actions-trigger {
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 7px 10px;
  cursor: pointer;
  background: var(--card-strong);
  color: var(--ink);
  white-space: nowrap;
  list-style: none;
}
.row-actions[open] .row-actions-trigger {
  border-bottom-left-radius: 0;
  border-bottom-right-radius: 0;
}
.row-actions-menu {
  left: auto;
  right: 0;
  min-width: 240px;
}
.row-actions-shell {
  display: grid;
  gap: 10px;
}
.row-actions-header {
  display: grid;
  grid-template-columns: auto 1fr;
  gap: 8px;
  align-items: center;
}
.row-actions-breadcrumb {
  color: var(--muted);
  font-size: 0.9rem;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.row-actions-back {
  padding: 7px 10px;
}
.row-action-options {
  display: grid;
  gap: 6px;
}
.row-action-button {
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 9px 10px;
  cursor: pointer;
  background: var(--card-strong);
  color: var(--ink);
  text-align: left;
}
.row-action-button.branch::after {
  content: "›";
  float: right;
  color: var(--muted);
}
.row-action-button.action-feedback {
  background: var(--accent-soft);
  border-color: var(--accent);
}
code { font-family: "IBM Plex Mono", monospace; font-size: 0.95em; }
@media (max-width: 980px) {
  .page { padding: 16px; }
  .header { flex-direction: column; align-items: flex-start; gap: 12px; }
  .modal-grid,
  .modal-select-row,
  .action-row,
  .search-row { grid-template-columns: 1fr; }
  .results { overflow-x: auto; }
}
"#;

const SCRIPT: &str = r#"
const QUERY_FIELD_SUGGESTIONS = [
  { label: "sha256:", insert: "sha256:", kind: "field" },
  { label: "vector:", insert: "vector:", kind: "field" },
  { label: "corpus:", insert: "corpus:", kind: "field" },
  { label: "collection:", insert: "collection:", kind: "field" },
  { label: "architecture:", insert: "architecture:", kind: "field" },
  { label: "address:", insert: "address:", kind: "field" },
  { label: "symbol:", insert: "symbol:", kind: "field" },
  { label: "AND", insert: "AND ", kind: "operator" },
  { label: "OR", insert: "OR ", kind: "operator" },
  { label: "NOT", insert: "NOT ", kind: "operator" },
  { label: "(", insert: "(", kind: "group" },
  { label: ")", insert: ")", kind: "group" },
];

let corpusSuggestionAbort = null;
let querySuggestionItems = [];
let querySuggestionIndex = 0;
const THEME_STORAGE_KEY = "binlex-web-theme";

function getSearchForm() {
  return document.getElementById("search-form");
}

function getQueryInput() {
  return document.getElementById("query-input");
}

function applyTheme(theme) {
  const normalized = theme === "light" ? "light" : "dark";
  document.body?.setAttribute("data-theme", normalized);
  document.getElementById("theme-dark")?.classList.toggle("active", normalized === "dark");
  document.getElementById("theme-light")?.classList.toggle("active", normalized === "light");
}

function setTheme(theme) {
  applyTheme(theme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme === "light" ? "light" : "dark");
  } catch (_) {}
}

function getQueryAssistantMenu() {
  return document.getElementById("query-assistant-menu");
}

function getQueryAssistant() {
  return document.getElementById("query-assistant");
}

function getTopKPopover() {
  return document.getElementById("top-k-popover");
}

function getTopKInput() {
  return document.getElementById("top-k-input");
}

function ensureQueryAssistantMenu() {
  const assistant = getQueryAssistant();
  if (!assistant) return null;
  let menu = getQueryAssistantMenu();
  if (menu) return menu;
  menu = document.createElement("div");
  menu.className = "query-assistant-menu";
  menu.id = "query-assistant-menu";
  menu.hidden = true;
  assistant.appendChild(menu);
  return menu;
}

function updateTopKValue(value) {
  const normalized = String(Math.max(1, Math.min(64, Number(value || 16) || 16)));
  const input = getTopKInput();
  const label = document.getElementById("top-k-label");
  const display = document.getElementById("top-k-value");
  const slider = document.getElementById("top-k-slider");
  if (input) input.value = normalized;
  if (label) label.textContent = normalized;
  if (display) display.textContent = normalized;
  if (slider && slider.value !== normalized) slider.value = normalized;
  syncFormState("upload-form");
}

function toggleTopKPopover() {
  const popover = getTopKPopover();
  const root = document.querySelector(".top-k-control");
  if (!popover) return;
  const next = popover.hidden;
  closeTopKPopover();
  if (!next) return;
  if (root) root.classList.add("open");
  popover.hidden = false;
}

function closeTopKPopover() {
  const popover = getTopKPopover();
  const root = document.querySelector(".top-k-control");
  if (root) root.classList.remove("open");
  if (popover) popover.hidden = true;
}

function parseQueryDataset(name) {
  const form = getSearchForm();
  if (!form) return [];
  try {
    return JSON.parse(form.dataset[name] || "[]");
  } catch (_) {
    return [];
  }
}

function queryGroupDepth(value, cursor) {
  const prefix = value.slice(0, cursor);
  let depth = 0;
  for (const ch of prefix) {
    if (ch === "(") {
      depth += 1;
    } else if (ch === ")" && depth > 0) {
      depth -= 1;
    }
  }
  return depth;
}

function analyzeQueryContext(input) {
  const value = input?.value || "";
  const cursor = input?.selectionStart ?? value.length;
  let index = 0;
  let depth = 0;
  let previousKind = "start";
  while (index < cursor) {
    while (index < cursor && /\s/.test(value[index])) {
      index += 1;
    }
    if (index >= cursor) {
      if (previousKind === "term" || previousKind === "group-close") {
        return {
          stage: "operator",
          partial: "",
          token: "",
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      return {
        stage: "field",
        partial: "",
        token: "",
        previousKind,
        depth,
        value,
        cursor,
      };
    }

    if (value[index] === "(") {
      depth += 1;
      index += 1;
      previousKind = "group-open";
      if (index >= cursor) {
        return {
          stage: "field",
          partial: "(",
          token: "(",
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      continue;
    }

    if (value[index] === ")") {
      depth = Math.max(0, depth - 1);
      index += 1;
      previousKind = "group-close";
      if (index >= cursor) {
        return {
          stage: "operator",
          partial: ")",
          token: ")",
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      continue;
    }

    if (previousKind === "term" || previousKind === "group-close") {
      const opStart = index;
      while (index < cursor && /[A-Za-z]/.test(value[index])) {
        index += 1;
      }
      const op = value.slice(opStart, index).toUpperCase();
      if (index >= cursor) {
        return {
          stage: "operator",
          partial: op,
          token: op,
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      if (!/\s/.test(value[index])) {
        return {
          stage: "operator",
          partial: op,
          token: op,
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      if (["AND", "OR", "NOT"].includes(op)) {
        previousKind = "operator";
        continue;
      }
      return {
        stage: "operator",
        partial: op,
        token: op,
        previousKind,
        depth,
        value,
        cursor,
      };
    }

    const fieldStart = index;
    while (index < cursor && /[A-Za-z_]/.test(value[index])) {
      index += 1;
    }
    const field = value.slice(fieldStart, index).toLowerCase();
    if (index >= cursor) {
      return {
        stage: "field",
        partial: field,
        token: field,
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    if (value[index] !== ":") {
      return {
        stage: "field",
        partial: field,
        token: field,
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    index += 1;
    if (index >= cursor) {
      return {
        stage: "field",
        partial: field,
        token: field,
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    let hadSpaceAfterColon = false;
    while (index < cursor && /\s/.test(value[index])) {
      hadSpaceAfterColon = true;
      index += 1;
    }
    if (!hadSpaceAfterColon) {
      return {
        stage: "field",
        partial: field,
        token: field,
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    if (index >= cursor) {
      return {
        stage: "value",
        field,
        partial: "",
        token: "",
        previousKind,
        depth,
        value,
        cursor,
      };
    }

    const valueStart = index;
    if (field === "vector") {
      if (value[index] !== "[") {
        return {
          stage: "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      let vectorDepth = 0;
      while (index < cursor) {
        if (value[index] === "[") vectorDepth += 1;
        if (value[index] === "]") {
          vectorDepth -= 1;
          if (vectorDepth === 0) {
            index += 1;
            break;
          }
        }
        index += 1;
      }
      if (index >= cursor) {
        return {
          stage: "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
    } else if (field === "symbol") {
      if (value[index] !== "\"") {
        return {
          stage: "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      index += 1;
      let escaped = false;
      while (index < cursor) {
        const ch = value[index];
        index += 1;
        if (escaped) {
          escaped = false;
          continue;
        }
        if (ch === "\\") {
          escaped = true;
          continue;
        }
        if (ch === "\"") {
          break;
        }
      }
      if (index >= cursor) {
        return {
          stage: "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
    } else {
      while (index < cursor && !/\s|\(|\)/.test(value[index])) {
        index += 1;
      }
      if (index >= cursor) {
        return {
          stage: "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
    }

    previousKind = "term";
  }

  return {
    stage: "field",
    partial: "",
    token: "",
    previousKind,
    depth,
    value,
    cursor,
  };
}

function isClauseComplete(context) {
  if (!context) return false;
  if (context.stage !== "value") return false;
  const value = (context.partial || "").trim();
  if (!value) return false;
  if (context.field === "sha256") return /^[0-9a-fA-F]{64}$/.test(value);
  if (context.field === "vector") {
    try {
      const parsed = JSON.parse(value);
      return Array.isArray(parsed) && parsed.length >= 2;
    } catch (_) {
      return false;
    }
  }
  if (context.field === "symbol") {
    return /^"(?:[^"\\]|\\.)+"$/.test(value);
  }
  if (context.field === "architecture") {
    return parseQueryDataset("architectures").some((item) => item.toLowerCase() === value.toLowerCase());
  }
  if (context.field === "collection") {
    return parseQueryDataset("collections").some((item) => item.toLowerCase() === value.toLowerCase());
  }
  if (context.field === "corpus") {
    return false;
  }
  if (context.field === "address") {
    return /^(0x[0-9a-fA-F]+|\d+)$/.test(value);
  }
  return false;
}

function continuationSuggestions() {
  return QUERY_FIELD_SUGGESTIONS.map((item) => ({
    ...item,
    insert: item.kind === "field" ? `${item.label} ` : item.insert,
  }));
}

function operatorSuggestions(context) {
  const items = continuationSuggestions().filter((item) => item.kind === "operator");
  if ((context.depth || 0) > 0) {
    const close = continuationSuggestions().find((item) => item.label === ")");
    if (close) {
      items.push(close);
    }
  }
  return items;
}

function fieldSuggestions(context) {
  const open = continuationSuggestions().find((item) => item.label === "(");
  const fields = continuationSuggestions().filter((item) => item.kind === "field");
  return open ? [...fields, open] : fields;
}

function helpTextForClause(clause) {
  if (!clause || !clause.token) {
    return "Use explicit fields like sha256:, vector:, corpus:, collection:, architecture:, address:, and symbol:.";
  }
  if (clause.stage === "field") {
    return "Use explicit fields like sha256:, vector:, corpus:, collection:, architecture:, address:, and symbol:.";
  }
  if (clause.field === "vector") {
    return "vector expects a JSON array like vector: [0.1, -0.2, 0.3]";
  }
  if (clause.field === "sha256") {
    return "sha256 expects 64 hexadecimal characters.";
  }
  if (clause.field === "address") {
    return "address accepts decimal or hexadecimal values like address: 0x401000";
  }
  if (clause.field === "corpus") {
    return "Select or search for a corpus value.";
  }
  if (clause.field === "architecture") {
    return "Select an architecture like amd64, i386, or cil.";
  }
  if (clause.field === "collection") {
    return "Select function, block, or instruction.";
  }
  if (clause.field === "symbol") {
    return "symbol expects a quoted string like symbol: \"kernel32:CreateFileW\"";
  }
  return "Use AND, OR, NOT, and parentheses to combine fielded terms.";
}

function replaceActiveQueryClause(input, replacement) {
  const context = analyzeQueryContext(input);
  const partialLength = (context.partial || "").length;
  const before = (context.value || "").slice(0, (context.cursor || 0) - partialLength);
  const after = (context.value || "").slice(context.cursor || 0);
  input.value = `${before}${replacement}${after}`;
  const nextCursor = (before + replacement).length;
  input.focus();
  input.setSelectionRange(nextCursor, nextCursor);
  updateQueryAssistant();
}

function applyQuerySuggestion(item) {
  const input = getQueryInput();
  if (!input) return;
  const context = analyzeQueryContext(input);
  const replacement = item.insert || item.label || "";
  const current = (context.partial || "").trim();
  if (item.kind === "group" && current === replacement.trim()) {
    const cursor = input.selectionStart ?? input.value.length;
    if (cursor >= input.value.length || !/\s/.test(input.value[cursor] || "")) {
      input.value = `${input.value.slice(0, cursor)} ${input.value.slice(cursor)}`;
      input.focus();
      input.setSelectionRange(cursor + 1, cursor + 1);
    }
    updateQueryAssistant();
    return;
  }
  replaceActiveQueryClause(input, replacement);
}

function hideQueryAssistantMenu() {
  const assistant = getQueryAssistant();
  const menu = getQueryAssistantMenu();
  if (!menu || !assistant) return;
  querySuggestionItems = [];
  querySuggestionIndex = 0;
  assistant.hidden = true;
  menu.remove();
}

function renderQuerySuggestions(items) {
  const assistant = getQueryAssistant();
  const menu = ensureQueryAssistantMenu();
  if (!menu || !assistant) return;
  if (!items.length) {
    hideQueryAssistantMenu();
    return;
  }
  querySuggestionItems = items.slice(0, 8);
  querySuggestionIndex = 0;
  assistant.hidden = false;
  menu.hidden = false;
  menu.innerHTML = "";
  querySuggestionItems.forEach((item, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "query-suggestion";
    if (index === querySuggestionIndex) button.classList.add("active");
    button.textContent = item.label;
    button.onclick = () => applyQuerySuggestion(item);
    menu.appendChild(button);
  });
}

function refreshActiveQuerySuggestion() {
  const menu = getQueryAssistantMenu();
  if (!menu) return;
  Array.from(menu.querySelectorAll(".query-suggestion")).forEach((button, index) => {
    button.classList.toggle("active", index === querySuggestionIndex);
  });
}

function filterQuerySuggestions(items, query) {
  const needle = (query || "").trim();
  return items
    .map((item, index) => ({
      item,
      index,
      score: needle ? fuzzyMenuScore(needle, item.label || "") : 0,
    }))
    .filter((entry) => !needle || entry.score >= 0)
    .sort((lhs, rhs) => {
      if (!needle) return lhs.index - rhs.index;
      if (rhs.score !== lhs.score) return rhs.score - lhs.score;
      return lhs.index - rhs.index;
    })
    .map((entry) => entry.item);
}

function suggestionItemsForValueField(field, partial) {
  if (field === "architecture") {
    return Promise.resolve(
      filterQuerySuggestions(
        parseQueryDataset("architectures").map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field === "collection") {
    return Promise.resolve(
      filterQuerySuggestions(
        parseQueryDataset("collections").map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field !== "corpus") {
    return Promise.resolve([]);
  }
  if (corpusSuggestionAbort) corpusSuggestionAbort.abort();
  corpusSuggestionAbort = new AbortController();
  const url = `/api/corpora?q=${encodeURIComponent(partial || "")}`;
  return fetch(url, { signal: corpusSuggestionAbort.signal })
    .then((response) => response.json())
    .then((items) =>
      filterQuerySuggestions(
        items.map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    )
    .catch(() => []);
}

async function updateQueryAssistant() {
  const assistant = getQueryAssistant();
  const input = getQueryInput();
  if (!assistant || !input) return;
  if (document.activeElement !== input) {
    hideQueryAssistantMenu();
    return;
  }
  const clause = analyzeQueryContext(input);
  const token = (clause.token || "").trim();
  assistant.hidden = false;

  if (!token && clause.stage === "field") {
    if (clause.previousKind === "term" || clause.previousKind === "group-close") {
      renderQuerySuggestions(operatorSuggestions(clause));
      return;
    }
    renderQuerySuggestions(fieldSuggestions(clause));
    return;
  }

  if (clause.stage === "value") {
    if (isClauseComplete(clause)) {
      hideQueryAssistantMenu();
      return;
    }
    if (["corpus", "architecture", "collection"].includes(clause.field)) {
      const items = await suggestionItemsForValueField(clause.field, clause.partial);
      renderQuerySuggestions(items);
      return;
    }
    querySuggestionItems = [];
    querySuggestionIndex = 0;
    const menu = getQueryAssistantMenu();
    if (menu) {
      menu.remove();
    }
    return;
  }

  if (clause.stage === "none") {
    hideQueryAssistantMenu();
    return;
  }
  const baseSuggestions =
    clause.stage === "operator"
      ? operatorSuggestions(clause)
      : fieldSuggestions(clause);
  const suggestions = filterQuerySuggestions(baseSuggestions, clause.partial);
  renderQuerySuggestions(suggestions);
}

function handleQueryInputKeydown(event) {
  const menu = getQueryAssistantMenu();
  const hasSuggestions = !!menu && !menu.hidden && querySuggestionItems.length > 0;
  if (event.key === "ArrowDown" && hasSuggestions) {
    event.preventDefault();
    querySuggestionIndex = (querySuggestionIndex + 1) % querySuggestionItems.length;
    refreshActiveQuerySuggestion();
    return;
  }
  if (event.key === "ArrowUp" && hasSuggestions) {
    event.preventDefault();
    querySuggestionIndex =
      (querySuggestionIndex - 1 + querySuggestionItems.length) % querySuggestionItems.length;
    refreshActiveQuerySuggestion();
    return;
  }
  if (event.key === "Enter" && hasSuggestions) {
    event.preventDefault();
    applyQuerySuggestion(querySuggestionItems[querySuggestionIndex]);
  }
}

function parseRowActions(shell) {
  try {
    return JSON.parse(shell?.dataset?.actions || "[]");
  } catch (_) {
    return [];
  }
}

function getRowActionItems(shell) {
  const tree = parseRowActions(shell);
  const path = (shell?.dataset?.path || "").split("/").filter(Boolean);
  let items = tree;
  for (const label of path) {
    const next = items.find((item) => item.label === label);
    if (!next || !Array.isArray(next.children)) return [];
    items = next.children;
  }
  return items;
}

function fuzzyMenuScore(query, label) {
  const rawQuery = (query || "").toLowerCase().trim();
  const rawLabel = (label || "").toLowerCase().trim();
  if (!rawQuery) return 0;
  if (rawLabel === rawQuery) return 5000;
  if (rawLabel.startsWith(rawQuery)) return 4000 - (rawLabel.length - rawQuery.length);
  if (rawLabel.includes(rawQuery)) return 3000 - (rawLabel.length - rawQuery.length);
  const q = rawQuery.replace(/[^a-z0-9]/g, "");
  const l = rawLabel.replace(/[^a-z0-9]/g, "");
  if (!q) return -1;
  if (l.includes(q)) return 1000 - (l.length - q.length);
  let score = 0;
  let position = 0;
  for (const ch of q) {
    const found = l.indexOf(ch, position);
    if (found === -1) return -1;
    score += 10;
    if (found === position) score += 4;
    position = found + 1;
  }
  return score - (l.length - q.length);
}

function renderRowActionMenu(shell) {
  if (!shell) return;
  const items = getRowActionItems(shell);
  const query = shell.querySelector(".menu-search")?.value?.trim() || "";
  const breadcrumb = shell.querySelector(".row-actions-breadcrumb");
  const back = shell.querySelector(".row-actions-back");
  const container = shell.querySelector(".row-action-options");
  if (!container || !breadcrumb || !back) return;

  const path = (shell.dataset.path || "").split("/").filter(Boolean);
  breadcrumb.textContent = ["Actions", ...path].join(" / ");
  back.hidden = path.length === 0;

  const ranked = items
    .map((item, index) => ({
      item,
      index,
      score: query ? fuzzyMenuScore(query, item.label || "") : 0,
    }))
    .filter((entry) => !query || entry.score >= 0)
    .sort((lhs, rhs) => {
      if (!query) return lhs.index - rhs.index;
      if (rhs.score !== lhs.score) return rhs.score - lhs.score;
      return lhs.index - rhs.index;
    });

  container.innerHTML = "";
  ranked.slice(0, query ? ranked.length : 3).forEach(({ item }) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "row-action-button";
    button.textContent = item.label || "";
    if (Array.isArray(item.children)) {
      button.classList.add("branch");
      button.onclick = (event) => {
        event.preventDefault();
        event.stopPropagation();
        navigateRowActions(button, item.label);
      };
    } else {
      button.onclick = async (event) => {
        event.preventDefault();
        event.stopPropagation();
        await runRowAction(button, item);
      };
    }
    container.appendChild(button);
  });
}

function navigateRowActions(button, label = null) {
  const shell = button.closest(".row-actions-shell");
  if (!shell) return;
  const path = (shell.dataset.path || "").split("/").filter(Boolean);
  if (label) {
    path.push(label);
  } else {
    path.pop();
  }
  shell.dataset.path = path.join("/");
  const search = shell.querySelector(".menu-search");
  if (search) search.value = "";
  renderRowActionMenu(shell);
}

async function runRowAction(button, item) {
  if ((item?.action || "copy") === "download") {
    if (item?.url) {
      window.location.assign(item.url);
    }
    return;
  }
  const payload = item?.payload || "";
  try {
    await navigator.clipboard.writeText(payload);
    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("action-feedback");
    }, 1200);
  } catch (_) {
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = "Copy";
    }, 1200);
  }
}

function dismissNotice(button) {
  button.closest(".notice")?.remove();
}

document.addEventListener("toggle", (event) => {
  const details = event.target;
  if (!(details instanceof HTMLDetailsElement) || !details.classList.contains("row-actions")) return;
  if (!details.open) return;
  document.querySelectorAll(".row-actions[open]").forEach((item) => {
    if (item !== details) item.open = false;
  });
  const shell = details.querySelector(".row-actions-shell");
  if (!shell) return;
  shell.dataset.path = "";
  const input = shell.querySelector(".menu-search");
  if (input) input.value = "";
  renderRowActionMenu(shell);
  if (input) setTimeout(() => input.focus(), 0);
}, true);

document.addEventListener("click", (event) => {
  document.querySelectorAll(".row-actions[open]").forEach((details) => {
    if (!details.contains(event.target)) {
      details.open = false;
    }
  });
});

function filterOptions(input, group) {
  const needle = input.value.toLowerCase();
  const root = input.closest('[data-group-root]');
  if (!root) return;
  if (root.dataset.remote === "true") {
    fetchRemoteOptions(root, group, needle);
    return;
  }
  root.querySelectorAll(`[data-group="${group}"]`).forEach((item) => {
    const text = item.innerText.toLowerCase();
    const visible = text.includes(needle);
    item.dataset.matchesSearch = visible ? "1" : "0";
    if (!root.querySelector('.menu-options').classList.contains('selected-only')) {
      item.style.display = visible ? "" : "none";
    }
  });
  applyVisibleLimit(root.querySelector('.menu-options'));
}

function clearGroup(button, group, defaults) {
  const root = button.closest('[data-group-root]');
  if (root) {
    const options = root.querySelector('.menu-options');
    root.querySelectorAll(`input[type="checkbox"][name="${group}"]`).forEach((item) => {
      item.checked = false;
    });
    if (options) {
      options.classList.remove('selected-only');
      if (root.dataset.remote === "true") {
        options.innerHTML = "";
      }
    }
    const selectedButton = Array.from(root.querySelectorAll('.menu-actions button'))
      .find((button) => button.textContent === 'View all');
    if (selectedButton) {
      selectedButton.textContent = 'View selected';
    }
    defaults.forEach((value) => {
      ensureCheckboxOption(root, group, value);
      const input = root.querySelector(`input[type="checkbox"][name="${group}"][value="${CSS.escape(value)}"]`);
      if (input) {
        input.checked = true;
      }
    });
    root.querySelectorAll(`[data-group="${group}"]`).forEach((item) => {
      const input = item.querySelector('input');
      const visible = !input || defaults.includes(input.value) || item.dataset.matchesSearch !== "0";
      item.style.display = visible ? "" : "none";
      item.classList.toggle('selected-match', !!input?.checked);
    });
    applyVisibleLimit(options);
  }
  syncFilterForms();
}

function toggleSelectedView(button, group) {
  const root = button.closest('[data-group-root]');
  if (!root) return;
  const options = root.querySelector('.menu-options');
  const selectedOnly = !options.classList.contains('selected-only');
  options.classList.toggle('selected-only', selectedOnly);
  root.querySelectorAll(`[data-group="${group}"]`).forEach((item) => {
    const checked = item.querySelector('input')?.checked;
    item.classList.toggle('selected-match', !!checked);
    if (selectedOnly) {
      item.style.display = checked ? "" : "none";
    } else {
      const matches = item.dataset.matchesSearch !== "0";
      item.style.display = matches ? "" : "none";
    }
  });
  applyVisibleLimit(options);
  button.textContent = selectedOnly ? "View all" : "View selected";
}

function syncFormState(formId) {
  const form = document.getElementById(formId);
  if (!form) return;
  const searchQuery = document.querySelector('#search-form input[name="query"]');
  const uploadQuery = document.querySelector('#upload-form input[name="query"]');
  if (searchQuery && uploadQuery) uploadQuery.value = searchQuery.value;
  const searchTopK = document.querySelector('#search-form input[name="top_k"]');
  const uploadTopK = document.querySelector('#upload-form input[name="top_k"]');
  if (searchTopK && uploadTopK) uploadTopK.value = searchTopK.value;
}

function syncFilterForms() {
  syncFormState("search-form");
  syncFormState("upload-form");
}

function syncUploadState() {
  syncFormState("upload-form");
}

function syncSearchState() {
  syncFormState("search-form");
}

function openUploadModal() {
  const modal = document.getElementById("upload-modal");
  if (!modal) return;
  modal.hidden = false;
  installDropzone();
  updateUploadModalState();
}

function closeUploadModal() {
  const modal = document.getElementById("upload-modal");
  if (!modal) return;
  modal.hidden = true;
}

function openUploadStatusModal(state, payload = {}) {
  const modal = document.getElementById("upload-status-modal");
  const icon = document.getElementById("upload-status-icon");
  const title = document.getElementById("upload-status-title");
  const text = document.getElementById("upload-status-text");
  const extra = document.getElementById("upload-status-extra");
  const closeButton = document.getElementById("upload-status-close");
  if (!modal || !icon || !title || !text || !extra || !closeButton) return;

  icon.classList.remove("uploading", "success", "failed");
  icon.classList.add(state);
  modal.hidden = false;
  extra.innerHTML = "";
  closeButton.hidden = state === "uploading";

  if (state === "uploading") {
    title.textContent = "Uploading Sample";
    text.textContent = "Binlex Web is uploading and processing the sample.";
  } else if (state === "success") {
    title.textContent = "Upload Successful";
    text.textContent = "The sample upload completed successfully. Results may take a moment to appear.";
    if (payload.sha256) {
      extra.innerHTML = `<div class="upload-status-sha"><span>SHA256</span><div class="upload-status-sha-row"><code id="upload-status-sha-value">${escapeHtml(payload.sha256)}</code><button type="button" class="secondary" id="upload-status-copy" onclick="copyUploadSha(this)">Copy</button></div></div>`;
    }
  } else {
    title.textContent = "Upload Failed";
    text.textContent = payload.error || "The upload failed.";
  }
}

function closeUploadStatusModal() {
  const modal = document.getElementById("upload-status-modal");
  if (!modal) return;
  modal.hidden = true;
}

async function copyUploadSha(button) {
  const code = document.getElementById("upload-status-sha-value");
  const payload = code?.textContent || "";
  if (!payload) return;
  try {
    await navigator.clipboard.writeText(payload);
    const previous = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  } catch (_) {
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = "Copy";
    }, 1200);
  }
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function setUploadedSha256State(sha256) {
  document.querySelectorAll('input[name="uploaded_sha256"]').forEach((item) => item.remove());
  if (!sha256) return;
  ["search-form", "upload-form"].forEach((id) => {
    const form = document.getElementById(id);
    if (!form) return;
    const hidden = document.createElement("input");
    hidden.type = "hidden";
    hidden.name = "uploaded_sha256";
    hidden.value = sha256;
    form.appendChild(hidden);
  });
}

function mirrorUploadFileList(files) {
  const target = document.getElementById("upload-input");
  const source = document.getElementById("upload-file-picker");
  const label = document.getElementById("upload-file-name");
  if (!target || !source || !files || !files.length) return;
  const dataTransfer = new DataTransfer();
  dataTransfer.items.add(files[0]);
  target.files = dataTransfer.files;
  source.files = dataTransfer.files;
  if (label) label.textContent = files[0].name;
  updateUploadModalState();
}

function updateUploadModalState() {
  const format = document.querySelector('input[name="upload-format"]:checked')?.value || "Auto";
  const shellcode = format === "Shellcode";
  setSingleOptionVisible("upload-architecture", "Auto", !shellcode);
  if (!shellcode) {
    setSingleSelectValue("upload-architecture", "Auto");
  } else if ((document.querySelector('input[name="upload-architecture"]:checked')?.value || "Auto") === "Auto") {
    clearSingleSelect("upload-architecture", "Architecture: Select");
  }
  setSingleSelectDisabled("upload-architecture", !shellcode);
  const arch = document.querySelector('input[name="upload-architecture"]:checked')?.value || "";
  const file = document.getElementById("upload-file-picker")?.files?.length || 0;
  const submit = document.getElementById("upload-submit");
  const tip = document.getElementById("upload-modal-tip");
  if (tip) tip.textContent = "";
  if (submit) {
    submit.disabled = file === 0 || (shellcode && !arch);
  }
}

async function submitUploadModal() {
  syncUploadState();
  const format = document.querySelector('input[name="upload-format"]:checked')?.value || "Auto";
  const arch = document.querySelector('input[name="upload-architecture"]:checked')?.value || "Auto";
  const formatTarget = document.getElementById("upload-format");
  const archTarget = document.getElementById("upload-architecture-override");
  if (formatTarget) formatTarget.value = format === "Auto" ? "" : format;
  if (archTarget) archTarget.value = arch === "Auto" ? "" : arch;
  const form = document.getElementById("upload-form");
  if (!(form instanceof HTMLFormElement)) return;
  const submit = document.getElementById("upload-submit");
  if (submit) submit.disabled = true;
  closeUploadModal();
  openUploadStatusModal("uploading");
  try {
    const response = await fetch("/upload", {
      method: "POST",
      body: new FormData(form),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      openUploadStatusModal("failed", { error: payload.error || "The upload failed." });
      return;
    }
    setUploadedSha256State(payload.sha256 || "");
    openUploadStatusModal("success", { sha256: payload.sha256 || "" });
  } catch (_) {
    openUploadStatusModal("failed", { error: "The upload failed." });
  } finally {
    if (submit) submit.disabled = false;
  }
}

function filterSingleOptions(input, group) {
  const needle = input.value.toLowerCase();
  const root = input.closest('[data-single-select]');
  if (!root) return;
  root.querySelectorAll(`[data-single-group="${group}"]`).forEach((item) => {
    const text = item.innerText.toLowerCase();
    item.style.display = text.includes(needle) ? "" : "none";
  });
}

function selectSingleOption(group, value) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  if (root.classList.contains("disabled")) return;
  setSingleSelectSummary(group, value);
  root.open = false;
  updateUploadModalState();
}

function setSingleSelectValue(group, value) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  root.querySelectorAll(`input[name="${group}"]`).forEach((item) => {
    item.checked = item.value === value;
  });
  setSingleSelectSummary(group, value);
}

function setSingleSelectDisabled(group, disabled) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  root.classList.toggle("disabled", disabled);
  if (disabled) {
    root.open = false;
  }
}

function clearSingleSelect(group, summaryText) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  root.querySelectorAll(`input[name="${group}"]`).forEach((item) => {
    item.checked = false;
  });
  const summary = root.querySelector('summary');
  if (summary) {
    summary.textContent = summaryText;
  }
}

function setSingleSelectSummary(group, value) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  const summary = root.querySelector('summary');
  if (!summary) return;
  const label = group === "upload-format" ? "Format" : "Architecture";
  summary.textContent = `${label}: ${value}`;
}

function setSingleOptionVisible(group, value, visible) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  const item = root.querySelector(`[data-option="${CSS.escape(value)}"]`);
  if (!item) return;
  item.style.display = visible ? "" : "none";
}

function installDropzone() {
  const input = document.getElementById("upload-file-picker");
  const zone = document.getElementById("upload-dropzone");
  if (!input || !zone || zone.dataset.installed === "1") return;
  zone.dataset.installed = "1";
  input.addEventListener("change", () => mirrorUploadFileList(input.files));
  ["dragenter", "dragover"].forEach((eventName) => {
    zone.addEventListener(eventName, (event) => {
      event.preventDefault();
      zone.classList.add("dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    zone.addEventListener(eventName, (event) => {
      event.preventDefault();
      zone.classList.remove("dragging");
    });
  });
  zone.addEventListener("drop", (event) => {
    const files = event.dataTransfer?.files;
    if (files && files.length) {
      mirrorUploadFileList(files);
    }
  });
}

document.addEventListener("click", (event) => {
  const assistant = document.getElementById("query-assistant");
  const input = getQueryInput();
  if (assistant && !assistant.contains(event.target) && input && event.target !== input) {
    hideQueryAssistantMenu();
  }
  const topK = document.querySelector(".top-k-control");
  if (topK && !topK.contains(event.target)) {
    closeTopKPopover();
  }
});

document.addEventListener("DOMContentLoaded", () => {
  let savedTheme = "dark";
  try {
    savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || "dark";
  } catch (_) {}
  applyTheme(savedTheme);
  const input = getQueryInput();
  window.setTimeout(() => {
    if (input && document.activeElement === input) {
      input.blur();
    }
    if (document.body instanceof HTMLElement) {
      document.body.focus({ preventScroll: true });
    }
    hideQueryAssistantMenu();
  }, 0);
});
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_preserves_vector_json_array() {
        let tokens =
            tokenize_search_query("vector: [0.1, -0.2, 0.3] AND collection: function").unwrap();
        assert_eq!(tokens.len(), 3);
        match &tokens[0] {
            QueryToken::Term(term) => {
                assert_eq!(term.field, QueryField::Vector);
                assert_eq!(term.value, "[0.1, -0.2, 0.3]");
            }
            other => panic!("unexpected token: {:?}", other),
        }
    }

    #[test]
    fn parser_gives_and_higher_precedence_than_or() {
        let tokens =
            tokenize_search_query("symbol: \"a\" OR symbol: \"b\" AND corpus: default").unwrap();
        let expr = parse_search_query(&tokens).unwrap();
        match expr {
            QueryExpr::Or(_, rhs) => match *rhs {
                QueryExpr::And(_, _) => {}
                other => panic!("unexpected rhs: {:?}", other),
            },
            other => panic!("unexpected expr: {:?}", other),
        }
    }

    #[test]
    fn root_terms_are_rejected_inside_or() {
        let tokens = tokenize_search_query(
            "sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef OR corpus: default",
        )
        .unwrap();
        let expr = parse_search_query(&tokens).unwrap();
        let error = analyze_query_expr(&expr, &mut QueryAnalysis::default(), false, false)
            .unwrap_err();
        assert!(error.to_string().contains("sha256 queries can only be combined with AND"));
    }

    #[test]
    fn symbol_requires_quoted_string() {
        let error = tokenize_search_query("symbol: kernel32:CreateFileW").unwrap_err();
        assert!(error.to_string().contains("quoted string"));
    }
}
