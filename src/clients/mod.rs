use crate::server::dto::{ErrorResponse, LZ4_CONTENT_ENCODING};
use crate::server::request_id::X_REQUEST_ID;
use reqwest::blocking::Response;
use reqwest::header::{CONTENT_ENCODING, HeaderName};
use serde::de::DeserializeOwned;
use std::fmt;

pub mod server;
pub mod web;

pub use server::Server;
pub use server::ServerVersionResponse;
pub use web::Web;
pub use web::WebAdminCommentsResponse;
pub use web::WebAdminPasswordResetResponse;
pub use web::WebAdminUserCreateResponse;
pub use web::WebAuthSessionResponse;
pub use web::WebAuthUserResponse;
pub use web::WebCaptchaResponse;
pub use web::WebCollectionTagSearchItemResponse;
pub use web::WebCollectionTagSearchResponse;
pub use web::WebCorporaCatalogResponse;
pub use web::WebCorporaResponse;
pub use web::WebEntityCommentResponse;
pub use web::WebEntityCommentsResponse;
pub use web::WebError;
pub use web::WebIndexActionResponse;
pub use web::WebKeyRegenerateResponse;
pub use web::WebMetadataItemResponse;
pub use web::WebMetadataUserResponse;
pub use web::WebQueryResult;
pub use web::WebRecoveryCodesResponse;
pub use web::WebResult;
pub use web::WebSearchDetailResponse;
pub use web::WebSearchRequest;
pub use web::WebSearchResponse;
pub use web::WebSearchRowResponse;
pub use web::WebSymbolsCatalogResponse;
pub use web::WebSymbolsResponse;
pub use web::WebTagsActionResponse;
pub use web::WebTagsCatalogResponse;
pub use web::WebTagsResponse;
pub use web::WebTwoFactorSetupResponse;
pub use web::WebUploadResponse;
pub use web::WebUploadStatusResponse;
pub use web::WebUsernameCheckResponse;
pub use web::WebUsersListResponse;
pub use web::WebVersionResponse;
pub use web::WebYaraItemRequest;

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

pub(crate) fn normalize_url(url: String) -> Result<String, Error> {
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

pub(crate) fn decode_response<T: DeserializeOwned>(response: Response) -> Result<T, Error> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .bytes()
        .map_err(|error| Error::Io(error.to_string()))?;

    if !status.is_success() {
        let header_request_id = headers
            .get(HeaderName::from_static(X_REQUEST_ID))
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let message = if let Ok(error) = serde_json::from_slice::<ErrorResponse>(&body) {
            match error.request_id.or(header_request_id) {
                Some(request_id) => format!("{} (request_id={})", error.error, request_id),
                None => error.error,
            }
        } else {
            match header_request_id {
                Some(request_id) => {
                    format!(
                        "{} (request_id={})",
                        String::from_utf8_lossy(&body),
                        request_id
                    )
                }
                None => String::from_utf8_lossy(&body).into_owned(),
            }
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
