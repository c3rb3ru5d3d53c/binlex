use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::http::header::{ContentDisposition, DispositionParam, DispositionType};
use actix_web::{HttpResponse, web};
use binlex::hashing::SHA256;
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::DynError;

const DEFAULT_MAX_UPLOAD_SIZE_BYTES: usize = 256 * 1024 * 1024;
const UPLOAD_TTL_SECONDS: u64 = 900;

#[derive(Clone, Debug, Serialize)]
pub struct McpSamplesConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
    #[serde(default = "default_max_upload_size_bytes")]
    pub max_upload_size_bytes: usize,
}

impl Default for McpSamplesConfig {
    fn default() -> Self {
        Self {
            directory: None,
            max_upload_size_bytes: default_max_upload_size_bytes(),
        }
    }
}

impl<'de> Deserialize<'de> for McpSamplesConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum McpSamplesConfigRepr {
            Path(String),
            Config {
                #[serde(default)]
                directory: Option<String>,
                #[serde(default = "default_max_upload_size_bytes")]
                max_upload_size_bytes: usize,
            },
        }

        Ok(match McpSamplesConfigRepr::deserialize(deserializer)? {
            McpSamplesConfigRepr::Path(path) => Self {
                directory: Some(path),
                max_upload_size_bytes: default_max_upload_size_bytes(),
            },
            McpSamplesConfigRepr::Config {
                directory,
                max_upload_size_bytes,
            } => Self {
                directory,
                max_upload_size_bytes,
            },
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SampleMetadata {
    pub sha256: String,
    pub filename: String,
    pub size: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct SamplePutResponse {
    pub filename: String,
    pub method: String,
    pub upload_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_url: Option<String>,
    pub max_upload_size_bytes: usize,
    pub instruction: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SampleGetResponse {
    pub sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,
    pub method: String,
    pub download_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SamplePutRequest {
    pub filename: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SampleGetRequest {
    pub sha256: String,
}

#[derive(Clone)]
struct UploadSession {
    filename: String,
    expires_at_epoch_seconds: u64,
}

pub struct SampleStore {
    root: PathBuf,
    max_upload_size_bytes: usize,
    uploads: Mutex<HashMap<String, UploadSession>>,
}

impl SampleStore {
    pub fn new(root: PathBuf, max_upload_size_bytes: usize) -> Result<Self, DynError> {
        let samples_dir = root.join("samples");
        let metadata_dir = root.join("metadata");
        fs::create_dir_all(&samples_dir)?;
        fs::create_dir_all(&metadata_dir)?;
        Ok(Self {
            root,
            max_upload_size_bytes,
            uploads: Mutex::new(HashMap::new()),
        })
    }

    pub fn create_upload(&self, filename: String) -> Result<SamplePutResponse, DynError> {
        if filename.trim().is_empty() {
            return Err("filename must not be empty".into());
        }

        let token = issue_token(&filename);
        let session = UploadSession {
            filename: sanitize_filename(&filename),
            expires_at_epoch_seconds: now_epoch_seconds() + UPLOAD_TTL_SECONDS,
        };
        self.uploads
            .lock()
            .map_err(|_| "upload session lock poisoned")?
            .insert(token.clone(), session);

        Ok(SamplePutResponse {
            filename: sanitize_filename(&filename),
            method: "PUT".to_string(),
            upload_path: format!("/samples/uploads/{}", token),
            upload_url: None,
            max_upload_size_bytes: self.max_upload_size_bytes,
            instruction:
                "Upload the sample bytes with an HTTP PUT to upload_url outside the sandbox."
                    .to_string(),
        })
    }

    pub fn get_download(&self, sha256: &str) -> Result<SampleGetResponse, DynError> {
        validate_sha256(sha256)?;
        let metadata = self.sample_metadata(sha256)?;
        Ok(SampleGetResponse {
            sha256: metadata.sha256,
            filename: Some(metadata.filename),
            size: Some(metadata.size),
            method: "GET".to_string(),
            download_path: format!("/samples/{}", sha256),
            download_url: None,
        })
    }

    pub fn upload_bytes(&self, token: &str, bytes: &[u8]) -> Result<SampleMetadata, DynError> {
        let session = {
            let mut uploads = self
                .uploads
                .lock()
                .map_err(|_| "upload session lock poisoned")?;
            let session = uploads
                .remove(token)
                .ok_or_else(|| format!("unknown upload token: {}", token))?;
            if session.expires_at_epoch_seconds < now_epoch_seconds() {
                return Err("upload token expired".into());
            }
            session
        };

        if bytes.len() > self.max_upload_size_bytes {
            return Err(format!(
                "upload size {} exceeds max upload size {}",
                bytes.len(),
                self.max_upload_size_bytes
            )
            .into());
        }
        let sha256 = SHA256::new(bytes)
            .hexdigest()
            .ok_or("failed to compute sha256")?;
        if self.sample_path(&sha256).is_file() {
            return self.sample_metadata(&sha256);
        }

        let metadata = SampleMetadata {
            sha256: sha256.clone(),
            filename: session.filename,
            size: bytes.len(),
        };

        fs::write(self.sample_path(&sha256), bytes)?;
        self.write_metadata(&metadata)?;
        Ok(metadata)
    }

    pub fn download_response(&self, sha256: &str) -> Result<HttpResponse, DynError> {
        validate_sha256(sha256)?;
        let metadata = self.sample_metadata(sha256)?;
        let bytes = fs::read(self.sample_path(sha256))?;
        Ok(HttpResponse::Ok()
            .insert_header(("content-type", "application/octet-stream"))
            .insert_header(("x-binlex-sha256", metadata.sha256.clone()))
            .insert_header(("x-binlex-size", metadata.size.to_string()))
            .insert_header(ContentDisposition {
                disposition: DispositionType::Attachment,
                parameters: vec![DispositionParam::Filename(metadata.filename)],
            })
            .body(bytes))
    }

    fn sample_path(&self, sha256: &str) -> PathBuf {
        self.root.join("samples").join(format!("{}.bin", sha256))
    }

    fn metadata_path(&self, sha256: &str) -> PathBuf {
        self.root.join("metadata").join(format!("{}.json", sha256))
    }

    fn sample_metadata(&self, sha256: &str) -> Result<SampleMetadata, DynError> {
        let path = self.metadata_path(sha256);
        if path.is_file() {
            let content = fs::read_to_string(path)?;
            return Ok(serde_json::from_str(&content)?);
        }
        let sample_path = self.sample_path(sha256);
        if !sample_path.is_file() {
            return Err(format!("unknown sample sha256: {}", sha256).into());
        }
        let size = fs::metadata(sample_path)?.len() as usize;
        Ok(SampleMetadata {
            sha256: sha256.to_string(),
            filename: format!("{}.bin", sha256),
            size,
        })
    }

    fn write_metadata(&self, metadata: &SampleMetadata) -> Result<(), DynError> {
        fs::write(
            self.metadata_path(&metadata.sha256),
            serde_json::to_string_pretty(metadata)?,
        )?;
        Ok(())
    }
}

pub async fn upload_bytes(
    store: web::Data<SampleStore>,
    path: web::Path<String>,
    body: web::Bytes,
) -> HttpResponse {
    match store.upload_bytes(&path.into_inner(), &body) {
        Ok(metadata) => HttpResponse::Ok().json(metadata),
        Err(error) => error_response(error),
    }
}

pub async fn download_bytes(
    store: web::Data<SampleStore>,
    path: web::Path<String>,
) -> HttpResponse {
    match store.download_response(&path.into_inner()) {
        Ok(response) => response,
        Err(error) => error_response(error),
    }
}

fn error_response(error: Box<dyn std::error::Error + Send + Sync>) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": error.to_string(),
    }))
}

fn default_max_upload_size_bytes() -> usize {
    DEFAULT_MAX_UPLOAD_SIZE_BYTES
}

fn sanitize_filename(filename: &str) -> String {
    Path::new(filename)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("sample.bin")
        .to_string()
}

fn validate_sha256(sha256: &str) -> Result<(), DynError> {
    if sha256.len() != 64 || !sha256.chars().all(|char| char.is_ascii_hexdigit()) {
        return Err("sha256 must be a 64-character hexadecimal string".into());
    }
    Ok(())
}

fn issue_token(filename: &str) -> String {
    let seed = format!("{}:{}", filename, now_epoch_nanos());
    SHA256::new(seed.as_bytes())
        .hexdigest()
        .unwrap_or_else(|| format!("upload-{}", now_epoch_nanos()))
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn now_epoch_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
}
