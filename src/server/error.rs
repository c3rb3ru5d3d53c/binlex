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

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Processor(_) => StatusCode::BAD_GATEWAY,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let message = match self {
            Self::Processor(message) => message,
            Self::NotImplemented(message) => message.to_string(),
        };
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

impl From<crate::runtime::error::ProcessorError> for ServerError {
    fn from(error: crate::runtime::error::ProcessorError) -> Self {
        Self::Processor(error.to_string())
    }
}
