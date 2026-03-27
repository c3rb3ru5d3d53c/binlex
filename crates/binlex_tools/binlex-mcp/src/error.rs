pub type DynError = Box<dyn std::error::Error + Send + Sync>;

pub fn internal_error(message: impl Into<String>) -> rmcp::ErrorData {
    rmcp::ErrorData::internal_error(message.into(), None)
}
