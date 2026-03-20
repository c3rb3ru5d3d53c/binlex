use serde_json::Value;

pub const LZ4_CONTENT_ENCODING: &str = "lz4";
pub const OCTET_STREAM_CONTENT_TYPE: &str = "application/octet-stream";

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ProcessorHttpRequest {
    pub binlex_version: String,
    pub requires: String,
    pub data: Value,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalyzeRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<crate::Config>,
}
