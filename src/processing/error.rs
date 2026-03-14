use std::fmt;
use std::io;

#[derive(Debug)]
pub enum ProcessorError {
    Io(io::Error),
    Protocol(String),
    Serialization(String),
    Compression(String),
    Spawn(String),
    BinaryNotFound(String),
    UnexpectedResponse(String),
    RequestTooLarge(usize),
}

impl fmt::Display for ProcessorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessorError::Io(err) => write!(f, "processor io error: {}", err),
            ProcessorError::Protocol(err) => write!(f, "processor protocol error: {}", err),
            ProcessorError::Serialization(err) => {
                write!(f, "processor serialization error: {}", err)
            }
            ProcessorError::Compression(err) => write!(f, "processor compression error: {}", err),
            ProcessorError::Spawn(err) => write!(f, "processor spawn error: {}", err),
            ProcessorError::BinaryNotFound(err) => write!(f, "processor binary not found: {}", err),
            ProcessorError::UnexpectedResponse(err) => {
                write!(f, "processor unexpected response: {}", err)
            }
            ProcessorError::RequestTooLarge(size) => {
                write!(
                    f,
                    "processor request exceeds maximum payload bytes: {}",
                    size
                )
            }
        }
    }
}

impl From<io::Error> for ProcessorError {
    fn from(value: io::Error) -> Self {
        ProcessorError::Io(value)
    }
}

impl From<postcard::Error> for ProcessorError {
    fn from(value: postcard::Error) -> Self {
        ProcessorError::Serialization(value.to_string())
    }
}

impl std::error::Error for ProcessorError {}
