use crate::controlflow::{Graph, GraphSnapshot};
use crate::server::dto::{
    AnalyzeRequest, ErrorResponse, HealthResponse, LZ4_CONTENT_ENCODING, OCTET_STREAM_CONTENT_TYPE,
};
use base64::Engine;
use reqwest::blocking::{Client as HttpClient, Response};
use reqwest::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fmt;
use std::path::Path;

#[derive(Clone)]
pub struct Client {
    config: crate::Config,
    url: String,
    verify: bool,
    compression: bool,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    Io(String),
    Http(u16, String),
    Serialization(String),
    Compression(String),
    Graph(String),
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "server client configuration error: {}", message)
            }
            Self::Io(message) => write!(f, "server client io error: {}", message),
            Self::Http(status, message) => write!(f, "server http error {}: {}", status, message),
            Self::Serialization(message) => write!(f, "server serialization error: {}", message),
            Self::Compression(message) => write!(f, "server compression error: {}", message),
            Self::Graph(message) => write!(f, "server graph hydration error: {}", message),
            Self::Protocol(message) => write!(f, "server protocol error: {}", message),
        }
    }
}

impl std::error::Error for Error {}

impl Client {
    pub fn new(
        config: crate::Config,
        url: Option<String>,
        verify: Option<bool>,
        compression: Option<bool>,
    ) -> Result<Self, Error> {
        let url = normalize_url(url.unwrap_or_else(|| default_url(&config)))?;
        let compression = compression.unwrap_or(config_processors_compression(&config));
        Ok(Self {
            config,
            url,
            verify: verify.unwrap_or(true),
            compression,
        })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn verify(&self) -> bool {
        self.verify
    }

    pub fn compression(&self) -> bool {
        self.compression
    }

    pub fn health(&self) -> Result<HealthResponse, Error> {
        let client = self.http_client()?;
        let response = client
            .get(format!("{}/health", self.url))
            .header(ACCEPT, "application/json")
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        decode_response(response)
    }

    pub fn analyze_file(
        &self,
        path: impl AsRef<Path>,
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
    ) -> Result<Graph, Error> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|error| Error::Io(error.to_string()))?;
        let name = path
            .file_name()
            .map(|value| value.to_string_lossy().into_owned());
        self.analyze_bytes(&data, magic, architecture, name.as_deref())
    }

    pub fn analyze_bytes(
        &self,
        data: &[u8],
        magic: Option<crate::Magic>,
        architecture: Option<crate::Architecture>,
        name: Option<&str>,
    ) -> Result<Graph, Error> {
        let request = AnalyzeRequest {
            name: name.map(ToString::to_string),
            data: base64::engine::general_purpose::STANDARD.encode(data),
            magic: magic.map(|value| value.to_string()),
            architecture: architecture.map(|value| value.to_string()),
            config: Some(self.config.clone()),
        };
        let client = self.http_client()?;
        let body = encode_request(&request, self.compression)?;
        let mut builder = client
            .post(format!("{}/analyze", self.url))
            .header(
                CONTENT_TYPE,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            )
            .header(
                ACCEPT,
                if self.compression {
                    OCTET_STREAM_CONTENT_TYPE
                } else {
                    "application/json"
                },
            );
        if self.compression {
            builder = builder.header(CONTENT_ENCODING, LZ4_CONTENT_ENCODING);
        }
        let response = builder
            .body(body)
            .send()
            .map_err(|error| Error::Io(error.to_string()))?;
        let snapshot: GraphSnapshot = decode_response(response)?;
        Graph::from_snapshot(snapshot, self.config.clone())
            .map_err(|error| Error::Graph(error.to_string()))
    }

    fn http_client(&self) -> Result<HttpClient, Error> {
        HttpClient::builder()
            .danger_accept_invalid_certs(!self.verify)
            .user_agent(format!("binlex/{}", crate::VERSION))
            .build()
            .map_err(|error| Error::Protocol(error.to_string()))
    }
}

fn default_url(config: &crate::Config) -> String {
    let bind = config.server.bind.trim();
    if bind.starts_with("http://") || bind.starts_with("https://") {
        bind.to_string()
    } else {
        format!("http://{}", bind)
    }
}

fn config_processors_compression(config: &crate::Config) -> bool {
    config.processors.compression
}

fn normalize_url(url: String) -> Result<String, Error> {
    let url = url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return Err(Error::InvalidConfiguration("url must not be empty"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(Error::InvalidConfiguration(
            "url must start with http:// or https://",
        ));
    }
    Ok(url)
}

fn encode_request<T: Serialize>(request: &T, compression: bool) -> Result<Vec<u8>, Error> {
    let json =
        serde_json::to_vec(request).map_err(|error| Error::Serialization(error.to_string()))?;
    if !compression {
        return Ok(json);
    }
    let compressed = lz4::block::compress(&json, None, false)
        .map_err(|error| Error::Compression(error.to_string()))?;
    let mut payload = Vec::with_capacity(4 + compressed.len());
    payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
    payload.extend_from_slice(&compressed);
    Ok(payload)
}

fn decode_response<T: DeserializeOwned>(response: Response) -> Result<T, Error> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .map_err(|error| Error::Io(error.to_string()))?;

    if !status.is_success() {
        let message = if let Ok(error) = serde_json::from_slice::<ErrorResponse>(&body) {
            error.error
        } else {
            String::from_utf8_lossy(&body).into_owned()
        };
        return Err(Error::Http(status.as_u16(), message));
    }

    let decoded = if headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(LZ4_CONTENT_ENCODING))
    {
        if body.len() < 4 {
            return Err(Error::Compression(
                "compressed response missing size prefix".to_string(),
            ));
        }
        let uncompressed_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as i32;
        lz4::block::decompress(&body[4..], Some(uncompressed_len))
            .map_err(|error| Error::Compression(error.to_string()))?
    } else {
        body.to_vec()
    };

    serde_json::from_slice(&decoded).map_err(|error| Error::Serialization(error.to_string()))
}
