use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MinIO {
    endpoint: String,
    access_key: String,
    secret_key: String,
    secure: bool,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "minio backend configuration error: {}", message)
            }
        }
    }
}

impl std::error::Error for Error {}

impl MinIO {
    pub fn new(
        endpoint: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        secure: bool,
    ) -> Result<Self, Error> {
        let endpoint = endpoint.into();
        if endpoint.trim().is_empty() {
            return Err(Error::InvalidConfiguration("endpoint must not be empty"));
        }
        Ok(Self {
            endpoint,
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            secure,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    pub fn secret_key(&self) -> &str {
        &self.secret_key
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn ensure_bucket(&self, bucket: &str) -> Result<(), Error> {
        if bucket.trim().is_empty() {
            return Err(Error::InvalidConfiguration("bucket must not be empty"));
        }
        Ok(())
    }

    pub fn put_object(
        &self,
        bucket: &str,
        key: &str,
        _payload: &[u8],
        _content_type: &str,
    ) -> Result<(), Error> {
        if bucket.trim().is_empty() {
            return Err(Error::InvalidConfiguration("bucket must not be empty"));
        }
        if key.trim().is_empty() {
            return Err(Error::InvalidConfiguration("key must not be empty"));
        }
        Ok(())
    }
}
