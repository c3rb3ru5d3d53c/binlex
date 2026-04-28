#[derive(Parser)]
struct Args {
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    server: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebConfigFile {
    #[serde(default, rename = "binlex-web")]
    binlex_web: BinlexWebConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BinlexWebConfig {
    #[serde(default = "default_listen_string")]
    listen: String,
    #[serde(default = "default_port")]
    port: u16,
    #[serde(default = "default_url_string")]
    url: String,
    #[serde(default = "default_server_url_string")]
    server_url: String,
    #[serde(default)]
    index: WebIndexConfig,
    #[serde(default)]
    compare: WebCompareConfig,
    #[serde(default)]
    upload: WebUploadConfig,
    #[serde(default)]
    download: WebDownloadConfig,
    #[serde(default)]
    api: WebApiConfig,
    #[serde(default)]
    auth: WebAuthConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebAuthConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_true")]
    allow_guest: bool,
    #[serde(default, rename = "2fa")]
    two_factor: WebTwoFactorConfig,
    #[serde(default)]
    registration: WebRegistrationConfig,
    #[serde(default = "default_session_ttl_seconds")]
    session_ttl_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebTwoFactorConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_true")]
    required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebRegistrationConfig {
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebCompareConfig {
    #[serde(default = "default_compare_limit")]
    limit: usize,
    #[serde(default = "default_compare_ascending_limit")]
    ascending_limit: usize,
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
    #[serde(default = "default_vector_selector")]
    selector: String,
    #[serde(default = "default_corpus_string")]
    default_corpus: String,
    #[serde(default)]
    instructions: bool,
    #[serde(default = "default_true")]
    blocks: bool,
    #[serde(default = "default_true")]
    functions: bool,
    #[serde(default = "default_true")]
    lock_corpora: bool,
    #[serde(default = "default_upload_corpora")]
    default_corpora: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebRemoteIndexConfig {
    #[serde(default)]
    enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebUploadConfig {
    #[serde(default)]
    sample: WebUploadSampleConfig,
    #[serde(default, rename = "project_files")]
    project_files: WebUploadProjectFilesConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebUploadSampleConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_sample_upload_max_bytes")]
    max_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebUploadProjectFilesConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_project_upload_max_bytes")]
    max_bytes: usize,
    #[serde(default = "default_project_upload_allowed_types")]
    allowed_types: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebDownloadSampleConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_sample_download_max_bytes")]
    max_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebDownloadConfig {
    #[serde(default)]
    sample: WebDownloadSampleConfig,
    #[serde(default)]
    samples: WebDownloadSamplesConfig,
    #[serde(default)]
    json: WebDownloadJsonConfig,
    #[serde(default, rename = "project_files")]
    project_files: WebDownloadProjectFilesConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebDownloadSamplesConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_sample_download_password")]
    password: String,
    #[serde(default = "default_batch_sample_download_max_count")]
    max_count: usize,
    #[serde(default = "default_batch_sample_download_max_total_bytes")]
    max_total_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebDownloadJsonConfig {
    #[serde(default = "default_download_json_max_bytes")]
    max_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebDownloadProjectFilesConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_project_download_max_bytes")]
    max_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct WebApiConfig {
    #[serde(default)]
    corpora: WebApiCorporaConfig,
    #[serde(default)]
    tags: WebApiTagsConfig,
    #[serde(default)]
    symbols: WebApiSymbolsConfig,
    #[serde(default)]
    comments: WebApiCommentsConfig,
    #[serde(default)]
    projects: WebApiProjectsConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebApiCorporaConfig {
    #[serde(default = "default_api_corpora_max_query_length")]
    max_query_length: usize,
    #[serde(default = "default_api_corpora_max_results")]
    max_results: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebApiTagsConfig {
    #[serde(default = "default_api_tags_max_query_length")]
    max_query_length: usize,
    #[serde(default = "default_api_tags_max_results")]
    max_results: usize,
    #[serde(default = "default_api_tags_default_page_size")]
    default_page_size: usize,
    #[serde(default = "default_api_tags_max_page_size")]
    max_page_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebApiSymbolsConfig {
    #[serde(default = "default_api_symbols_max_query_length")]
    max_query_length: usize,
    #[serde(default = "default_api_symbols_max_results")]
    max_results: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebApiCommentsConfig {
    #[serde(default = "default_api_comments_default_page_size")]
    default_page_size: usize,
    #[serde(default = "default_api_comments_max_page_size")]
    max_page_size: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebApiProjectsConfig {
    #[serde(default = "default_api_projects_default_page_size")]
    default_page_size: usize,
    #[serde(default = "default_api_projects_max_page_size")]
    max_page_size: usize,
    #[serde(default = "default_api_projects_max_query_length")]
    max_query_length: usize,
}

impl Default for WebConfigFile {
    fn default() -> Self {
        Self {
            binlex_web: BinlexWebConfig::default(),
        }
    }
}

impl Default for BinlexWebConfig {
    fn default() -> Self {
        Self {
            listen: default_listen_string(),
            port: default_port(),
            url: default_url_string(),
            server_url: default_server_url_string(),
            index: WebIndexConfig::default(),
            compare: WebCompareConfig::default(),
            upload: WebUploadConfig::default(),
            download: WebDownloadConfig::default(),
            api: WebApiConfig::default(),
            auth: WebAuthConfig::default(),
        }
    }
}

impl Default for WebAuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            allow_guest: default_true(),
            two_factor: WebTwoFactorConfig::default(),
            registration: WebRegistrationConfig::default(),
            session_ttl_seconds: default_session_ttl_seconds(),
        }
    }
}

impl Default for WebTwoFactorConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            required: default_true(),
        }
    }
}

impl Default for WebRegistrationConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
        }
    }
}

impl Default for WebCompareConfig {
    fn default() -> Self {
        Self {
            limit: default_compare_limit(),
            ascending_limit: default_compare_ascending_limit(),
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
            selector: default_vector_selector(),
            default_corpus: default_corpus_string(),
            instructions: false,
            blocks: true,
            functions: true,
            lock_corpora: true,
            default_corpora: default_upload_corpora(),
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
            sample: WebUploadSampleConfig::default(),
            project_files: WebUploadProjectFilesConfig::default(),
        }
    }
}

impl Default for WebUploadSampleConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_bytes: default_sample_upload_max_bytes(),
        }
    }
}

impl Default for WebUploadProjectFilesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_bytes: default_project_upload_max_bytes(),
            allowed_types: default_project_upload_allowed_types(),
        }
    }
}

impl Default for WebDownloadConfig {
    fn default() -> Self {
        Self {
            sample: WebDownloadSampleConfig::default(),
            samples: WebDownloadSamplesConfig::default(),
            json: WebDownloadJsonConfig::default(),
            project_files: WebDownloadProjectFilesConfig::default(),
        }
    }
}

impl Default for WebDownloadSamplesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            password: default_sample_download_password(),
            max_count: default_batch_sample_download_max_count(),
            max_total_bytes: default_batch_sample_download_max_total_bytes(),
        }
    }
}

impl Default for WebDownloadJsonConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_download_json_max_bytes(),
        }
    }
}

impl Default for WebDownloadSampleConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_bytes: default_sample_download_max_bytes(),
        }
    }
}

impl Default for WebDownloadProjectFilesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_bytes: default_project_download_max_bytes(),
        }
    }
}

impl Default for WebApiCorporaConfig {
    fn default() -> Self {
        Self {
            max_query_length: default_api_corpora_max_query_length(),
            max_results: default_api_corpora_max_results(),
        }
    }
}

impl Default for WebApiTagsConfig {
    fn default() -> Self {
        Self {
            max_query_length: default_api_tags_max_query_length(),
            max_results: default_api_tags_max_results(),
            default_page_size: default_api_tags_default_page_size(),
            max_page_size: default_api_tags_max_page_size(),
        }
    }
}

impl Default for WebApiSymbolsConfig {
    fn default() -> Self {
        Self {
            max_query_length: default_api_symbols_max_query_length(),
            max_results: default_api_symbols_max_results(),
        }
    }
}

impl Default for WebApiCommentsConfig {
    fn default() -> Self {
        Self {
            default_page_size: default_api_comments_default_page_size(),
            max_page_size: default_api_comments_max_page_size(),
        }
    }
}

impl Default for WebApiProjectsConfig {
    fn default() -> Self {
        Self {
            default_page_size: default_api_projects_default_page_size(),
            max_page_size: default_api_projects_max_page_size(),
            max_query_length: default_api_projects_max_query_length(),
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
        .join("indexing")
        .to_string_lossy()
        .into_owned()
}

fn default_sample_download_password() -> String {
    "infected".to_string()
}

fn default_sample_upload_max_bytes() -> usize {
    200 * 1024 * 1024
}

fn default_upload_corpora() -> Vec<String> {
    vec![
        "default".to_string(),
        "goodware".to_string(),
        "malware".to_string(),
    ]
}

fn default_project_upload_allowed_types() -> Vec<String> {
    vec![
        "i64".to_string(),
        "idb".to_string(),
        "bndb".to_string(),
        "gbf".to_string(),
        "gzf".to_string(),
    ]
}

fn default_sample_download_max_bytes() -> usize {
    200 * 1024 * 1024
}

fn default_project_upload_max_bytes() -> usize {
    512 * 1024 * 1024
}

fn default_project_download_max_bytes() -> usize {
    200 * 1024 * 1024
}

fn default_batch_sample_download_max_count() -> usize {
    64
}

fn default_batch_sample_download_max_total_bytes() -> usize {
    default_sample_download_max_bytes().saturating_mul(default_batch_sample_download_max_count())
}

fn default_vector_selector() -> String {
    "embeddings.llvm.vector".to_string()
}

fn default_download_json_max_bytes() -> usize {
    50 * 1024 * 1024
}

fn default_api_corpora_max_query_length() -> usize {
    64
}

fn default_api_corpora_max_results() -> usize {
    16
}

fn default_api_tags_max_query_length() -> usize {
    64
}

fn default_api_tags_max_results() -> usize {
    64
}

fn default_api_tags_default_page_size() -> usize {
    50
}

fn default_api_tags_max_page_size() -> usize {
    50
}

fn default_api_symbols_max_query_length() -> usize {
    64
}

fn default_api_symbols_max_results() -> usize {
    64
}

fn default_api_comments_default_page_size() -> usize {
    20
}

fn default_api_comments_max_page_size() -> usize {
    50
}

fn default_api_projects_default_page_size() -> usize {
    4
}

fn default_api_projects_max_page_size() -> usize {
    25
}

fn default_api_projects_max_query_length() -> usize {
    64
}

fn default_compare_limit() -> usize {
    100_000
}

fn default_compare_ascending_limit() -> usize {
    4_096
}

fn default_session_ttl_seconds() -> u64 {
    60 * 60 * 24 * 30
}

fn default_page() -> usize {
    1
}

fn default_limit() -> usize {
    25
}
