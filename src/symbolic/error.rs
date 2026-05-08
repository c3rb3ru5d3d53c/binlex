use std::fmt;

#[derive(Debug, Clone)]
pub enum Error {
    InvalidBits(u16),
    UnsupportedArchitecture(String),
    UnsupportedCpu(String),
    InvalidCpu(String),
    UnsupportedExpression(&'static str),
    UnsupportedEffect(&'static str),
    UnsupportedTerminator(&'static str),
    MissingRegister(String),
    MissingFlag(String),
    MissingTemporary(u32),
    Solver(String),
    Unsatisfiable,
}

impl Error {
    pub(crate) fn invalid_bits(bits: u16) -> Self {
        Self::InvalidBits(bits)
    }

    pub(crate) fn solver(message: impl Into<String>) -> Self {
        Self::Solver(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBits(bits) => write!(f, "invalid symbolic bit width: {bits}"),
            Self::UnsupportedArchitecture(name) => {
                write!(f, "unsupported symbolic architecture: {name}")
            }
            Self::UnsupportedCpu(name) => write!(f, "unsupported semantic CPU: {name}"),
            Self::InvalidCpu(message) => write!(f, "invalid semantic CPU: {message}"),
            Self::UnsupportedExpression(kind) => {
                write!(f, "unsupported symbolic expression: {kind}")
            }
            Self::UnsupportedEffect(kind) => write!(f, "unsupported symbolic effect: {kind}"),
            Self::UnsupportedTerminator(kind) => {
                write!(f, "unsupported symbolic terminator: {kind}")
            }
            Self::MissingRegister(name) => write!(f, "register {name} is not available"),
            Self::MissingFlag(name) => write!(f, "flag {name} is not available"),
            Self::MissingTemporary(id) => write!(f, "temporary {id} is not available"),
            Self::Solver(message) => write!(f, "symbolic solver error: {message}"),
            Self::Unsatisfiable => write!(f, "symbolic constraints are unsatisfiable"),
        }
    }
}

impl std::error::Error for Error {}
