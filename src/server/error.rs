use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::server::dto::ErrorResponse;

#[derive(Debug)]
pub enum ServerError {
    Processor(String),
    NotImplemented(&'static str),
}

impl ServerError {
    pub fn json(error: serde_json::Error) -> Self {
        Self::Processor(format!("json error: {}", error))
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Processor(message) => (StatusCode::BAD_GATEWAY, message),
            Self::NotImplemented(message) => (StatusCode::NOT_IMPLEMENTED, message.to_string()),
        };
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

impl From<crate::runtime::error::ProcessorError> for ServerError {
    fn from(error: crate::runtime::error::ProcessorError) -> Self {
        Self::Processor(error.to_string())
    }
}
