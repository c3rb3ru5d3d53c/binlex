use axum::Json;
use axum::Router;
use axum::extract::{Form, Multipart, Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use binlex::client::Client;
use binlex::index::{Collection, LocalIndex, SearchResult};
use binlex::search::{QueryCompletionSpec, query_architecture_values, query_collection_values, query_completion_specs};
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

mod assets;
mod page;
mod query;

use crate::page::{display_architecture, escape_html, render_page};
use crate::query::{SearchRoot, build_search_plan, search_expr_matches};

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
    page: Option<usize>,
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
    page: Option<usize>,
}

#[derive(Default)]
pub(crate) struct PageData {
    pub(crate) corpora_options: Vec<String>,
    pub(crate) architecture_options: Vec<String>,
    pub(crate) collection_options: Vec<String>,
    pub(crate) query_completion_specs: Vec<QueryCompletionSpec>,
    pub(crate) status: UiStatus,
    pub(crate) uploaded_sha256: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) query: String,
    pub(crate) top_k: usize,
    pub(crate) page: usize,
    pub(crate) has_previous_page: bool,
    pub(crate) has_next_page: bool,
    pub(crate) results: Vec<SearchResult>,
    pub(crate) upload_format_options: Vec<String>,
    pub(crate) upload_architecture_options: Vec<String>,
    pub(crate) uploads_enabled: bool,
    pub(crate) sample_downloads_enabled: bool,
}

#[derive(Default)]
pub(crate) struct UiStatus {
    pub(crate) server_ok: bool,
    pub(crate) index_ok: bool,
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

struct SearchPage {
    items: Vec<SearchResult>,
    has_next: bool,
}

#[derive(Deserialize)]
struct DownloadSampleParams {
    sha256: String,
}

#[derive(Deserialize)]
struct DownloadSamplesParams {
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    sha256: Vec<String>,
}

#[derive(Deserialize)]
struct DownloadJsonParams {
    corpus: String,
    sha256: String,
    collection: String,
    address: u64,
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
        .route("/download/samples", get(download_samples))
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
    clamp_page(&mut params);
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
    clamp_page(&mut params);
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
            "page" => {
                form.page = field
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
    let architecture_options = query_architecture_values();
    let mut collection_options = query_collection_values();
    collection_options.sort();
    let query_completion_specs = query_completion_specs();

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

    let current_page = params.page.unwrap_or(1);
    let mut results = Vec::new();
    let mut has_next_page = false;
    if params.search.is_some() {
        match execute_search(state, &params) {
            Ok(search_page) => {
                info!(
                    "page search completed results={} page={} has_next={}",
                    search_page.items.len(),
                    current_page,
                    search_page.has_next
                );
                has_next_page = search_page.has_next;
                results = search_page.items;
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
        query_completion_specs,
        status,
        uploaded_sha256: params.uploaded_sha256.clone(),
        message: params.message.clone(),
        error: params.error.clone(),
        query: params.query.clone(),
        top_k: params.top_k.unwrap_or(DEFAULT_TOP_K),
        page: current_page,
        has_previous_page: current_page > 1,
        has_next_page,
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

async fn download_samples(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DownloadSamplesParams>,
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
    let hashes = unique_sha256_list(&params.sha256)?;
    if hashes.is_empty() {
        return Err(AppError("no sample hashes were provided".to_string()));
    }

    let state_for_download = state.clone();
    let password_for_download = password.clone();
    let hashes_for_download = hashes.clone();
    let payload = task::spawn_blocking(move || {
        create_encrypted_samples_zip(
            &state_for_download.index,
            &hashes_for_download,
            &password_for_download,
        )
        .map_err(|error| AppError(error.to_string()))
    })
    .await
    .map_err(|error| AppError(error.to_string()))??;

    info!("sample batch download count={}", hashes.len());
    Ok(download_response(
        "application/zip",
        "samples.zip".to_string(),
        payload,
    ))
}

fn execute_search(state: &AppState, params: &PageParams) -> Result<SearchPage, String> {
    let limit = params.top_k.unwrap_or(DEFAULT_TOP_K);
    let page = params.page.unwrap_or(1);
    let offset = page.saturating_sub(1).saturating_mul(limit);
    let query = params.query.trim();
    if query.is_empty() {
        return Err("enter a search query".to_string());
    }
    let plan = build_search_plan(
        &state.index,
        &state.ui.corpus,
        &default_collections(&state.ui.collection),
        query,
    )
    .map_err(|error| error.to_string())?;
    let broad_limit = offset
        .saturating_add(limit.saturating_mul(8))
        .saturating_add(1)
        .clamp(64, 512);
    let mut candidates = match &plan.root {
        Some(SearchRoot::Sha256(sha256)) => {
            info!(
                "search root=sha256 sha256={} corpora={:?} collections={:?} architectures={:?} top_k={}",
                sha256, plan.corpora, plan.collections, plan.architectures, limit
            );
            state
                .index
                .exact_search_page(
                    &plan.corpora,
                    sha256,
                    Some(&plan.collections),
                    &plan.architectures,
                    0,
                    broad_limit,
                )
                .map_err(|error| error.to_string())?
        }
        Some(SearchRoot::Embedding(embedding)) => {
            info!(
                "search root=embedding embedding={} corpora={:?} collections={:?} architectures={:?} top_k={} page={}",
                embedding, plan.corpora, plan.collections, plan.architectures, limit, page
            );
            state
                .index
                .embedding_search_page(
                    &plan.corpora,
                    embedding,
                    Some(&plan.collections),
                    &plan.architectures,
                    0,
                    broad_limit,
                )
                .map_err(|error| error.to_string())?
        }
        Some(SearchRoot::Vector(vector)) => {
            info!(
                "search root=vector dims={} corpora={:?} collections={:?} architectures={:?} top_k={} page={}",
                vector.len(),
                plan.corpora,
                plan.collections,
                plan.architectures,
                limit,
                page
            );
            state
                .index
                .search_page(
                    &plan.corpora,
                    vector,
                    Some(&plan.collections),
                    &plan.architectures,
                    0,
                    broad_limit,
                )
                .map_err(|error| error.to_string())?
        }
        None => {
            info!(
                "search root=scan corpora={:?} collections={:?} architectures={:?} top_k={} page={}",
                plan.corpora, plan.collections, plan.architectures, limit, page
            );
            state
                .index
                .scan_search_page(
                    &plan.corpora,
                    Some(&plan.collections),
                    &plan.architectures,
                    0,
                    broad_limit,
                )
                .map_err(|error| error.to_string())?
        }
    };

    candidates.retain(|result| search_expr_matches(result, plan.query.expr(), &plan.root));
    candidates.sort_by(|lhs, rhs| rhs.score().total_cmp(&lhs.score()));
    let has_next = candidates.len() > offset.saturating_add(limit);
    candidates = candidates.into_iter().skip(offset).take(limit).collect();
    Ok(SearchPage {
        items: candidates,
        has_next,
    })
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
        page: form.page,
        ..PageParams::default()
    };
    clamp_top_k(&mut params);
    clamp_page(&mut params);

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

    let graph = match state.client.analyze_bytes_with_corpora(
        &form.bytes,
        magic_override,
        architecture_override,
        &corpora,
    ) {
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

    if state.ui.index.local.enabled {
        if let Err(error) = state.index.graph_many(
            &corpora,
            &sha256,
            &graph,
            &[],
            Some("processors.embeddings.vector"),
            Some(&selected),
        ) {
            warn!("upload local index stage failed error={}", error);
            params.error = Some(format!("failed to stage local index entry: {}", error));
            return Err(params);
        }
        if let Err(error) = state.index.commit() {
            warn!("upload local index commit failed error={}", error);
            params.error = Some(format!("failed to commit local index entry: {}", error));
            return Err(params);
        }
        info!(
            "upload indexed locally sha256={} corpora={:?} collections={:?}",
            sha256, corpora, selected
        );
    } else {
        info!(
            "upload analysis completed without local indexing sha256={} corpora={:?} collections={:?}",
            sha256, corpora, selected
        );
    }

    params.uploaded_sha256 = Some(sha256.clone());
    let filename = form.filename.unwrap_or_else(|| "sample".to_string());
    params.message = Some(format!("uploaded {} ({})", filename, sha256));
    Ok(params)
}

fn upload_corpora_for_query(state: &AppState, query: &str) -> Vec<String> {
    match build_search_plan(
        &state.index,
        &state.ui.corpus,
        &default_collections(&state.ui.collection),
        query,
    ) {
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

fn clamp_top_k(params: &mut PageParams) {
    params.top_k = Some(params.top_k.unwrap_or(DEFAULT_TOP_K).clamp(1, MAX_TOP_K));
}

fn clamp_page(params: &mut PageParams) {
    params.page = Some(params.page.unwrap_or(1).max(1));
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
        Collection::Block => serde_json::to_value(
            binlex::controlflow::Block::new(address, &graph)
                .ok()?
                .process(),
        )
        .ok(),
        Collection::Function => serde_json::to_value(
            binlex::controlflow::Function::new(address, &graph)
                .ok()?
                .process(),
        )
        .ok(),
    }
}

fn create_encrypted_sample_zip(
    sha256: &str,
    sample: &[u8],
    password: &str,
) -> Result<Vec<u8>, Error> {
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
    let cursor = writer
        .finish()
        .map_err(|error| Error::other(error.to_string()))?;
    Ok(cursor.into_inner())
}

fn create_encrypted_samples_zip(
    index: &LocalIndex,
    hashes: &[String],
    password: &str,
) -> Result<Vec<u8>, Error> {
    let cursor = Cursor::new(Vec::<u8>::new());
    let mut writer = ZipWriter::new(cursor);
    let options = FileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o600)
        .with_deprecated_encryption(password.as_bytes());
    for sha256 in hashes {
        let sample = index.get(sha256).map_err(|error| Error::other(error.to_string()))?;
        writer
            .start_file(format!("{}.bin", sha256), options)
            .map_err(|error| Error::other(error.to_string()))?;
        std::io::Write::write_all(&mut writer, &sample).map_err(Error::other)?;
    }
    let cursor = writer
        .finish()
        .map_err(|error| Error::other(error.to_string()))?;
    Ok(cursor.into_inner())
}

fn unique_sha256_list(values: &[String]) -> Result<Vec<String>, AppError> {
    let mut unique = std::collections::BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if !is_sha256(trimmed) {
            return Err(AppError(format!("invalid sha256 {}", trimmed)));
        }
        unique.insert(trimmed.to_string());
    }
    Ok(unique.into_iter().collect())
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
