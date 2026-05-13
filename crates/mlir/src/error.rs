use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
pub enum Error {
    NullHandle(&'static str),
    ParseFailed,
    VerificationFailed,
    Utf8(std::str::Utf8Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NullHandle(kind) => write!(f, "mlir returned a null {}", kind),
            Self::ParseFailed => write!(f, "mlir parse failed"),
            Self::VerificationFailed => write!(f, "mlir verification failed"),
            Self::Utf8(error) => write!(f, "utf8 conversion failed: {}", error),
        }
    }
}

impl StdError for Error {}

impl From<std::str::Utf8Error> for Error {
    fn from(error: std::str::Utf8Error) -> Self {
        Self::Utf8(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
