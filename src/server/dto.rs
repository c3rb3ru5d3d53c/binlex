use serde_json::Value;

pub const LZ4_CONTENT_ENCODING: &str = "lz4";
pub const OCTET_STREAM_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProcessorHttpRequest {
    pub data: Value,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}
