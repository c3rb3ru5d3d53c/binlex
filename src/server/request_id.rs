use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderMap;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use rand::RngCore;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

pub const X_REQUEST_ID: &str = "x-request-id";

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestId(String);

impl RequestId {
    pub fn from_headers(headers: &HeaderMap) -> Self {
        if let Some(value) = headers
            .get(header_name())
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Self(value.to_string());
        }
        Self(generate_request_id())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub async fn middleware(mut request: Request<Body>, next: Next) -> axum::response::Response {
    let request_id = RequestId::from_headers(request.headers());
    request.extensions_mut().insert(request_id.clone());
    let mut response = next.run(request).await;
    attach_header(response.headers_mut(), request_id.as_str());
    response
}

pub fn attach_header(headers: &mut HeaderMap, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert(header_name(), value);
    }
}

pub fn header_name() -> HeaderName {
    HeaderName::from_static(X_REQUEST_ID)
}

fn generate_request_id() -> String {
    let millis = chrono::Utc::now().timestamp_millis() as u64;
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut rng = rand::thread_rng();
    let random = rng.next_u64();
    format!("req_{millis:013x}_{counter:08x}_{random:016x}")
}
