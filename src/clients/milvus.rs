use serde_json::Value;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldType {
    VarChar,
    Int64,
    Bool,
    FloatVector { dimensions: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldSchema {
    pub name: String,
    pub kind: FieldType,
    pub primary_key: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Client {
    uri: String,
    token: Option<String>,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "milvus backend configuration error: {}", message)
            }
        }
    }
}

impl std::error::Error for Error {}

impl Client {
    pub fn new(uri: impl Into<String>, token: Option<String>) -> Result<Self, Error> {
        let uri = uri.into();
        if uri.trim().is_empty() {
            return Err(Error::InvalidConfiguration("uri must not be empty"));
        }
        Ok(Self { uri, token })
    }

    pub fn uri(&self) -> &str {
        &self.uri
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn ensure_collection(
        &self,
        database: &str,
        collection: &str,
        _fields: &[FieldSchema],
    ) -> Result<(), Error> {
        if database.trim().is_empty() {
            return Err(Error::InvalidConfiguration("database must not be empty"));
        }
        if collection.trim().is_empty() {
            return Err(Error::InvalidConfiguration("collection must not be empty"));
        }
        Ok(())
    }

    pub fn upsert(&self, database: &str, collection: &str, _row: &Value) -> Result<(), Error> {
        if database.trim().is_empty() {
            return Err(Error::InvalidConfiguration("database must not be empty"));
        }
        if collection.trim().is_empty() {
            return Err(Error::InvalidConfiguration("collection must not be empty"));
        }
        Ok(())
    }
}
