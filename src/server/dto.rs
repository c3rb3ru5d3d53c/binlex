use serde_json::Value;

use crate::controlflow::{BlockJson, FunctionJson, GraphSnapshot, InstructionJson};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AnalyzeRequest {
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub magic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corpora: Vec<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessGraphRequest {
    pub graph: GraphSnapshot,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProcessEntityRequest {
    Function { function: FunctionJson },
    Block { block: BlockJson },
    Instruction { instruction: InstructionJson },
}
