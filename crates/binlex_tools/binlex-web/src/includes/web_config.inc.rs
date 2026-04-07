#[derive(Parser)]
struct Args {
    #[arg(long)]
    listen: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long, default_value_t = false)]
    lock_corpora: bool,
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
    #[serde(default = "default_corpus_string")]
    corpus: String,
    #[serde(default, rename = "binlex-server")]
    binlex_server: WebBinlexServerConfig,
    #[serde(default)]
    collection: WebCollectionConfig,
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
    #[serde(default)]
    token: WebTokenConfig,
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
    #[serde(default = "default_auth_rules")]
    rules: Vec<WebAuthRuleConfig>,
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
struct WebAuthRuleConfig {
    path: String,
    enabled: bool,
    #[serde(default)]
    roles: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebTokenConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_token_ttl_seconds")]
    ttl_seconds: u64,
    #[serde(default = "default_token_rules")]
    rules: Vec<WebTokenRuleConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebTokenRuleConfig {
    path: String,
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
struct WebBinlexServerConfig {
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
    #[serde(default = "default_vector_selector")]
    selector: String,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebUploadSampleConfig {
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default = "default_sample_upload_max_bytes")]
    max_bytes: usize,
    #[serde(default)]
    corpora: WebUploadSampleCorporaConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebUploadSampleCorporaConfig {
    #[serde(default)]
    lock: bool,
    #[serde(default = "default_upload_corpora")]
    default: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct WebApiConfig {
    #[serde(default)]
    corpora: WebApiCorporaConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct WebApiCorporaConfig {
    #[serde(default = "default_api_corpora_max_query_length")]
    max_query_length: usize,
    #[serde(default = "default_api_corpora_max_results")]
    max_results: usize,
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
            corpus: default_corpus_string(),
            binlex_server: WebBinlexServerConfig::default(),
            collection: WebCollectionConfig::default(),
            index: WebIndexConfig::default(),
            compare: WebCompareConfig::default(),
            upload: WebUploadConfig::default(),
            download: WebDownloadConfig::default(),
            api: WebApiConfig::default(),
            auth: WebAuthConfig::default(),
            token: WebTokenConfig::default(),
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
            rules: default_auth_rules(),
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

impl Default for WebTokenConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: default_token_ttl_seconds(),
            rules: default_token_rules(),
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

impl Default for WebBinlexServerConfig {
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
            block: true,
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
            selector: default_vector_selector(),
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
        }
    }
}

impl Default for WebUploadSampleConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_bytes: default_sample_upload_max_bytes(),
            corpora: WebUploadSampleCorporaConfig::default(),
        }
    }
}

impl Default for WebUploadSampleCorporaConfig {
    fn default() -> Self {
        Self {
            lock: false,
            default: default_upload_corpora(),
        }
    }
}

impl Default for WebDownloadConfig {
    fn default() -> Self {
        Self {
            sample: WebDownloadSampleConfig::default(),
            samples: WebDownloadSamplesConfig::default(),
            json: WebDownloadJsonConfig::default(),
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

impl Default for WebApiCorporaConfig {
    fn default() -> Self {
        Self {
            max_query_length: default_api_corpora_max_query_length(),
            max_results: default_api_corpora_max_results(),
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

fn default_sample_download_max_bytes() -> usize {
    200 * 1024 * 1024
}

fn default_batch_sample_download_max_count() -> usize {
    64
}

fn default_batch_sample_download_max_total_bytes() -> usize {
    default_sample_download_max_bytes().saturating_mul(default_batch_sample_download_max_count())
}

fn default_vector_selector() -> String {
    "processors.embeddings.vector".to_string()
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

fn default_auth_rules() -> Vec<WebAuthRuleConfig> {
    vec![
        WebAuthRuleConfig {
            path: "/api/v1/index/graph".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/index/function".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/index/block".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/index/instruction".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/index/commit".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/index/clear".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/upload/sample".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/corpora/add".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/corpora/collection/add".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/corpora/collection/remove".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/tags/add".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/tags/collection/add".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/tags/collection/remove".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/tags/collection/replace".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/symbols/add".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/symbols/collection/add".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/symbols/collection/remove".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/symbols/collection/replace".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/password".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/2fa/setup".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/2fa/enable".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/2fa/disable".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/picture".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/key/regenerate".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/recovery/regenerate".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/profile/delete".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/auth/password/reset".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/create".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/role".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/enabled".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/password/reset".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/key/regenerate".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/picture/delete".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/2fa/require".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/2fa/disable".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/2fa/reset".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/users/delete".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/corpora/delete".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/tags/delete".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/symbols/delete".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/admin/comments".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/comments/add".to_string(),
            enabled: true,
            roles: vec!["admin".to_string(), "user".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/comments/".to_string(),
            enabled: true,
            roles: vec!["admin".to_string()],
        },
        WebAuthRuleConfig {
            path: "/api/v1/search".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/corpora".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/upload/status".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/download/sample".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/download/samples".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/download/json".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/docs".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/openapi.json".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/version".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/auth/bootstrap".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/auth/login".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/auth/logout".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/auth/register".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/auth/me".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/token".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
        WebAuthRuleConfig {
            path: "/api/v1/token/clear".to_string(),
            enabled: false,
            roles: Vec::new(),
        },
    ]
}

fn default_token_ttl_seconds() -> u64 {
    900
}

fn default_token_rules() -> Vec<WebTokenRuleConfig> {
    vec![
        WebTokenRuleConfig {
            path: "/".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/version".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/token".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/token/clear".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/index/graph".to_string(),
            enabled: true,
        },
        WebTokenRuleConfig {
            path: "/api/v1/index/function".to_string(),
            enabled: true,
        },
        WebTokenRuleConfig {
            path: "/api/v1/index/block".to_string(),
            enabled: true,
        },
        WebTokenRuleConfig {
            path: "/api/v1/index/instruction".to_string(),
            enabled: true,
        },
        WebTokenRuleConfig {
            path: "/api/v1/index/commit".to_string(),
            enabled: true,
        },
        WebTokenRuleConfig {
            path: "/api/v1/index/clear".to_string(),
            enabled: true,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/sample".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/sample/add".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/sample/remove".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/sample/replace".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/collection".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/collection/add".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/collection/remove".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/collection/replace".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/search/sample".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/tags/search/collection".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/search".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/corpora".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/upload/sample".to_string(),
            enabled: true,
        },
        WebTokenRuleConfig {
            path: "/api/v1/upload/status".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/download/sample".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/download/samples".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/download/json".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/docs".to_string(),
            enabled: false,
        },
        WebTokenRuleConfig {
            path: "/api/v1/openapi.json".to_string(),
            enabled: false,
        },
    ]
}
