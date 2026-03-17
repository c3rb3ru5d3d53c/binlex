use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::Path;
use axum::extract::State;
use axum::http::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::server::auth;
use crate::server::dto::{
    HealthResponse, LZ4_CONTENT_ENCODING, OCTET_STREAM_CONTENT_TYPE, ProcessorHttpRequest,
};
use crate::server::error::ServerError;
use crate::server::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/processors/{processor}", post(processor_execute))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(HealthResponse { status: "ok" })
}

async fn processor_execute(
    State(state): State<AppState>,
    Path(processor): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    state.debug_log(format!(
        "request start processor={} bytes={} content_encoding={:?} accept={:?}",
        processor,
        body.len(),
        headers
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
        headers.get(ACCEPT).and_then(|value| value.to_str().ok()),
    ));

    if !auth::authorize(&headers) {
        state.debug_log(format!("request unauthorized processor={}", processor));
        return Err(ServerError::Processor("unauthorized".to_string()));
    }

    let request: ProcessorHttpRequest = match decode_request(&headers, &body) {
        Ok(request) => request,
        Err(error) => {
            state.debug_log(format!(
                "request decode failed processor={} error={:?}",
                processor, error
            ));
            return Err(error);
        }
    };

    state.debug_log(format!("request decoded processor={}", processor));

    let response = match crate::server::service::processors::execute(&state, &processor, request) {
        Ok(response) => response,
        Err(error) => {
            state.debug_log(format!(
                "processor execution failed processor={} error={:?}",
                processor, error
            ));
            return Err(error);
        }
    };

    state.debug_log(format!("processor execution complete processor={}", processor));

    let encoded = match encode_response(state.config.processors.compression, &headers, &response) {
        Ok(response) => response,
        Err(error) => {
            state.debug_log(format!(
                "response encode failed processor={} error={:?}",
                processor, error
            ));
            return Err(error);
        }
    };

    state.debug_log(format!("request complete processor={}", processor));
    Ok(encoded)
}

fn decode_request<T: serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<T, ServerError> {
    if is_lz4_encoded(headers) {
        if body.len() < 4 {
            return Err(ServerError::Processor(
                "request decompression failed: compressed payload missing size prefix".to_string(),
            ));
        }
        let uncompressed_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as i32;
        let json = lz4::block::decompress(&body[4..], Some(uncompressed_len)).map_err(|error| {
            ServerError::Processor(format!("request decompression failed: {}", error))
        })?;
        serde_json::from_slice(&json).map_err(ServerError::json)
    } else {
        serde_json::from_slice(body).map_err(ServerError::json)
    }
}

fn encode_response(
    compression_enabled: bool,
    headers: &HeaderMap,
    value: &serde_json::Value,
) -> Result<Response, ServerError> {
    if compression_enabled && accepts_lz4(headers) {
        let json = serde_json::to_vec(value).map_err(ServerError::json)?;
        let compressed = lz4::block::compress(&json, None, false).map_err(|error| {
            ServerError::Processor(format!("response compression failed: {}", error))
        })?;
        let mut payload = Vec::with_capacity(4 + compressed.len());
        payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
        payload.extend_from_slice(&compressed);
        let mut response_headers = HeaderMap::new();
        response_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(OCTET_STREAM_CONTENT_TYPE),
        );
        response_headers.insert(
            CONTENT_ENCODING,
            HeaderValue::from_static(LZ4_CONTENT_ENCODING),
        );
        Ok((StatusCode::OK, response_headers, payload).into_response())
    } else {
        Ok((StatusCode::OK, Json(value.clone())).into_response())
    }
}

fn is_lz4_encoded(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(LZ4_CONTENT_ENCODING))
}

fn accepts_lz4(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|entry| entry.eq_ignore_ascii_case(OCTET_STREAM_CONTENT_TYPE))
        })
}
