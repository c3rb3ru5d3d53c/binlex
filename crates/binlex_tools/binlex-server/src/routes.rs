use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::ConnectInfo;
use axum::extract::DefaultBodyLimit;
use axum::extract::Extension;
use axum::extract::Path;
use axum::extract::State;
use axum::http::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use tracing::info;
use utoipa::openapi::InfoBuilder;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{IntoParams, Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use binlex::server::auth;
use binlex::server::dto::{
    AnalyzeRequest, HealthResponse, LZ4_CONTENT_ENCODING, OCTET_STREAM_CONTENT_TYPE,
    ProcessEntityRequest, ProcessGraphRequest, ProcessorHttpRequest,
};
use binlex::server::error::ServerError;
use binlex::server::request_id::RequestId;
use binlex::server::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/version", get(version))
        .route("/api/v1/health", get(health))
        .route("/api/v1/analyze", post(analyze))
        .route("/api/v1/process", post(process_graph))
        .route("/api/v1/process/entity", post(process_entity))
        .route("/api/v1/processors/{processor}", post(processor_execute))
        .merge(SwaggerUi::new("/api/v1/docs").url("/api/v1/openapi.json", ApiDoc::openapi()))
        .layer(middleware::from_fn(binlex::server::request_id::middleware))
        .layer(DefaultBodyLimit::disable())
        .with_state(state)
}

#[derive(OpenApi)]
#[openapi(
    paths(version, health, analyze, process_graph, process_entity, processor_execute),
    components(schemas(
        VersionResponse,
        HealthResponseDoc,
        ApiErrorResponseDoc,
        AnalyzeRequestDoc,
        ProcessGraphRequestDoc,
        ProcessEntityRequestDoc,
        ProcessorHttpRequestDoc
    )),
    modifiers(&ApiDocSecurity),
    tags(
        (name = "System", description = "Version and health endpoints."),
        (name = "Analysis", description = "Byte-level analysis endpoints."),
        (name = "Processing", description = "Graph and entity processing endpoints."),
        (name = "Processors", description = "Direct processor execution endpoints.")
    ),
    info(
        title = "Binlex Server API",
        version = "v1",
        description = "Compute-only API for binlex-server. It analyzes inputs and executes processors, but does not own indexing, search, tags, uploads, or downloads."
    )
)]
struct ApiDoc;

struct ApiDocSecurity;

impl Modify for ApiDocSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        openapi.info = InfoBuilder::from(openapi.info.clone())
            .description(Some("Compute-only API for binlex-server. It analyzes inputs and executes processors, but does not own indexing, search, tags, uploads, or downloads.".to_string()))
            .build();

        let bearer = SecurityScheme::Http(
            HttpBuilder::new()
                .scheme(HttpAuthScheme::Bearer)
                .bearer_format("API Key")
                .description(Some(
                    "Reserved for future server-side auth. Current builds may run without enforcing this.".to_string(),
                ))
                .build(),
        );

        openapi.components = Some(
            openapi
                .components
                .clone()
                .map(utoipa::openapi::ComponentsBuilder::from)
                .unwrap_or_else(utoipa::openapi::ComponentsBuilder::new)
                .security_scheme("bearer_auth", bearer)
                .build(),
        );
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
struct VersionResponse {
    version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
struct HealthResponseDoc {
    status: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
struct ApiErrorResponseDoc {
    error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
struct AnalyzeRequestDoc {
    data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    magic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    corpora: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
struct ProcessGraphRequestDoc {
    graph: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ProcessEntityRequestDoc {
    Function { function: Value },
    Block { block: Value },
    Instruction { instruction: Value },
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
struct ProcessorHttpRequestDoc {
    binlex_version: String,
    requires: String,
    data: Value,
}

#[derive(Deserialize, IntoParams)]
#[allow(dead_code)]
struct ProcessorExecuteParams {
    processor: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/version",
    tag = "System",
    responses((status = 200, description = "Current binlex version.", body = VersionResponse))
)]
async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: binlex::VERSION.to_string(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "System",
    responses((status = 200, description = "Service health status.", body = HealthResponseDoc))
)]
async fn health(
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Extension(request_id): Extension<RequestId>,
) -> impl IntoResponse {
    info!(
        "request complete route=/api/v1/health request_id={} remote_addr={} remote_port={} status=200",
        request_id,
        remote.ip(),
        remote.port()
    );
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/analyze",
    tag = "Analysis",
    request_body(content = AnalyzeRequestDoc, content_type = "application/json", description = "Analyze raw bytes and return a processed graph snapshot."),
    responses(
        (status = 200, description = "Processed graph snapshot."),
        (status = 415, description = "Unsupported or unrecognized input format.", body = ApiErrorResponseDoc),
        (status = 502, description = "Analysis failure.", body = ApiErrorResponseDoc)
    )
)]
async fn analyze(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    state.log(format!(
        "request start route=/api/v1/analyze request_id={} remote_addr={} remote_port={} bytes={}",
        request_id,
        remote.ip(),
        remote.port(),
        body.len()
    ));
    state.debug_log(format!(
        "request start analyze bytes={} content_encoding={:?}",
        body.len(),
        headers
            .get(CONTENT_ENCODING)
            .and_then(|value| value.to_str().ok()),
    ));

    if !auth::authorize(&headers) {
        state.debug_log("request unauthorized analyze".to_string());
        return Err(ServerError::processor("unauthorized").with_request_id(request_id.to_string()));
    }

    let request: AnalyzeRequest = decode_request(&headers, &body)
        .map_err(|error| error.with_request_id(request_id.to_string()))?;
    let response = match binlex::server::analyze::execute(&state.config, request) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/analyze request_id={} remote_addr={} remote_port={} status={} error={:?}",
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };
    let encoded = match encode_response(state.config.processors.compression, &headers, &response) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/analyze request_id={} remote_addr={} remote_port={} status={} error={:?}",
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };
    state.log(format!(
        "request complete route=/api/v1/analyze request_id={} remote_addr={} remote_port={} status=200",
        request_id,
        remote.ip(),
        remote.port()
    ));
    Ok(encoded)
}

#[utoipa::path(
    post,
    path = "/api/v1/processors/{processor}",
    tag = "Processors",
    params(ProcessorExecuteParams),
    request_body(content = ProcessorHttpRequestDoc, content_type = "application/json", description = "Execute a named processor directly."),
    responses(
        (status = 200, description = "Processor response payload."),
        (status = 502, description = "Processor failure.", body = ApiErrorResponseDoc)
    )
)]
async fn processor_execute(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Extension(request_id): Extension<RequestId>,
    Path(processor): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    state.log(format!(
        "request start route=/api/v1/processors/{} request_id={} remote_addr={} remote_port={} bytes={}",
        processor,
        request_id,
        remote.ip(),
        remote.port(),
        body.len()
    ));
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
        return Err(ServerError::processor("unauthorized").with_request_id(request_id.to_string()));
    }

    let request: ProcessorHttpRequest = match decode_request(&headers, &body) {
        Ok(request) => request,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/processors/{} request_id={} remote_addr={} remote_port={} status={} error={:?}",
                processor,
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            state.debug_log(format!(
                "request decode failed processor={} error={:?}",
                processor, error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };

    state.debug_log(format!("request decoded processor={}", processor));

    let response = match binlex::server::processors::execute(&state, &processor, request) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/processors/{} request_id={} remote_addr={} remote_port={} status={} error={:?}",
                processor,
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            state.debug_log(format!(
                "processor execution failed processor={} error={:?}",
                processor, error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };

    state.debug_log(format!(
        "processor execution complete processor={}",
        processor
    ));

    let encoded = match encode_response(state.config.processors.compression, &headers, &response) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/processors/{} request_id={} remote_addr={} remote_port={} status={} error={:?}",
                processor,
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            state.debug_log(format!(
                "response encode failed processor={} error={:?}",
                processor, error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };

    state.debug_log(format!("request complete processor={}", processor));
    state.log(format!(
        "request complete route=/api/v1/processors/{} request_id={} remote_addr={} remote_port={} status=200",
        processor,
        request_id,
        remote.ip(),
        remote.port()
    ));
    Ok(encoded)
}

#[utoipa::path(
    post,
    path = "/api/v1/process",
    tag = "Processing",
    request_body(content = ProcessGraphRequestDoc, content_type = "application/json", description = "Process an existing graph snapshot."),
    responses(
        (status = 200, description = "Processed graph snapshot."),
        (status = 502, description = "Processing failure.", body = ApiErrorResponseDoc)
    )
)]
async fn process_graph(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    state.log(format!(
        "request start route=/api/v1/process request_id={} remote_addr={} remote_port={} bytes={}",
        request_id,
        remote.ip(),
        remote.port(),
        body.len()
    ));

    if !auth::authorize(&headers) {
        return Err(ServerError::processor("unauthorized").with_request_id(request_id.to_string()));
    }

    let request: ProcessGraphRequest = decode_request(&headers, &body)
        .map_err(|error| error.with_request_id(request_id.to_string()))?;
    let response = match binlex::server::process::execute(&state.config, request) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/process request_id={} remote_addr={} remote_port={} status={} error={:?}",
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };
    let encoded = match encode_response(state.config.processors.compression, &headers, &response) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/process request_id={} remote_addr={} remote_port={} status={} error={:?}",
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };
    state.log(format!(
        "request complete route=/api/v1/process request_id={} remote_addr={} remote_port={} status=200",
        request_id,
        remote.ip(),
        remote.port()
    ));
    Ok(encoded)
}

#[utoipa::path(
    post,
    path = "/api/v1/process/entity",
    tag = "Processing",
    request_body(content = ProcessEntityRequestDoc, content_type = "application/json", description = "Process a single function, block, or instruction entity."),
    responses(
        (status = 200, description = "Processed entity payload."),
        (status = 502, description = "Processing failure.", body = ApiErrorResponseDoc)
    )
)]
async fn process_entity(
    State(state): State<AppState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ServerError> {
    state.log(format!(
        "request start route=/api/v1/process/entity request_id={} remote_addr={} remote_port={} bytes={}",
        request_id,
        remote.ip(),
        remote.port(),
        body.len()
    ));

    if !auth::authorize(&headers) {
        return Err(ServerError::processor("unauthorized").with_request_id(request_id.to_string()));
    }

    let request: ProcessEntityRequest = decode_request(&headers, &body)
        .map_err(|error| error.with_request_id(request_id.to_string()))?;
    let response = match binlex::server::process::execute_entity(&state, request) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/process/entity request_id={} remote_addr={} remote_port={} status={} error={:?}",
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };
    let encoded = match encode_response(state.config.processors.compression, &headers, &response) {
        Ok(response) => response,
        Err(error) => {
            state.log(format!(
                "request complete route=/api/v1/process/entity request_id={} remote_addr={} remote_port={} status={} error={:?}",
                request_id,
                remote.ip(),
                remote.port(),
                error.status_code().as_u16(),
                error
            ));
            return Err(error.with_request_id(request_id.to_string()));
        }
    };
    state.log(format!(
        "request complete route=/api/v1/process/entity request_id={} remote_addr={} remote_port={} status=200",
        request_id,
        remote.ip(),
        remote.port()
    ));
    Ok(encoded)
}

fn decode_request<T: serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<T, ServerError> {
    if is_lz4_encoded(headers) {
        if body.len() < 4 {
            return Err(ServerError::processor(
                "request decompression failed: compressed payload missing size prefix".to_string(),
            ));
        }
        let uncompressed_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as i32;
        let json = lz4::block::decompress(&body[4..], Some(uncompressed_len)).map_err(|error| {
            ServerError::processor(format!("request decompression failed: {}", error))
        })?;
        serde_json::from_slice(&json).map_err(ServerError::json)
    } else {
        serde_json::from_slice(body).map_err(ServerError::json)
    }
}

fn encode_response<T: serde::Serialize>(
    compression: bool,
    headers: &HeaderMap,
    value: &T,
) -> Result<Response, ServerError> {
    if compression && accepts_lz4(headers) {
        let json = serde_json::to_vec(value).map_err(ServerError::json)?;
        let compressed = lz4::block::compress(&json, None, false).map_err(|error| {
            ServerError::processor(format!("response compression failed: {}", error))
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
        let value = serde_json::to_value(value).map_err(ServerError::json)?;
        Ok((StatusCode::OK, Json(value)).into_response())
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
        .is_some_and(|value| value.eq_ignore_ascii_case(OCTET_STREAM_CONTENT_TYPE))
}
