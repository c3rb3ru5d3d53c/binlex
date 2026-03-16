use axum::http::HeaderMap;

pub fn authorize(_headers: &HeaderMap) -> bool {
    true
}
