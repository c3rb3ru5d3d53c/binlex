use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::server::dto::ErrorResponse;

#[derive(Debug)]
pub enum ServerError {
    Processor {
        message: String,
        request_id: Option<String>,
    },
    UnsupportedMedia {
        message: String,
        request_id: Option<String>,
    },
    NotImplemented {
        message: &'static str,
        request_id: Option<String>,
    },
}

impl ServerError {
    pub fn processor(message: impl Into<String>) -> Self {
        Self::Processor {
            message: message.into(),
            request_id: None,
        }
    }

    pub fn unsupported_media(message: impl Into<String>) -> Self {
        Self::UnsupportedMedia {
            message: message.into(),
            request_id: None,
        }
    }

    pub fn not_implemented(message: &'static str) -> Self {
        Self::NotImplemented {
            message,
            request_id: None,
        }
    }

    pub fn json(error: serde_json::Error) -> Self {
        Self::processor(format!("json error: {}", error))
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        let request_id = Some(request_id.into());
        match &mut self {
            Self::Processor {
                request_id: current,
                ..
            } => *current = request_id,
            Self::UnsupportedMedia {
                request_id: current,
                ..
            } => *current = request_id,
            Self::NotImplemented {
                request_id: current,
                ..
            } => *current = request_id,
        }
        self
    }

    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Processor { .. } => StatusCode::BAD_GATEWAY,
            Self::UnsupportedMedia { .. } => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::NotImplemented { .. } => StatusCode::NOT_IMPLEMENTED,
        }
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let (message, request_id) = match self {
            Self::Processor {
                message,
                request_id,
            } => (message, request_id),
            Self::UnsupportedMedia {
                message,
                request_id,
            } => (message, request_id),
            Self::NotImplemented {
                message,
                request_id,
            } => (message.to_string(), request_id),
        };
        (
            status,
            Json(ErrorResponse {
                error: message,
                request_id,
            }),
        )
            .into_response()
    }
}

impl From<crate::runtime::error::ProcessorError> for ServerError {
    fn from(error: crate::runtime::error::ProcessorError) -> Self {
        Self::Processor {
            message: error.to_string(),
            request_id: None,
        }
    }
}
