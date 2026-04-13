use crate::Config;
use crate::hashing::SHA256;
use crate::storage::object_store;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Clone)]
pub struct LocalStore {
    object_store: object_store::ObjectStore,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    ObjectStore(String),
    Serialization(String),
    NotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "local store configuration error: {}", message)
            }
            Self::ObjectStore(message) => write!(f, "local store object store error: {}", message),
            Self::Serialization(message) => {
                write!(f, "local store serialization error: {}", message)
            }
            Self::NotFound(message) => write!(f, "local store not found: {}", message),
        }
    }
}

impl std::error::Error for Error {}

impl LocalStore {
    pub fn new(config: Config) -> Result<Self, Error> {
        Self::with_root(config.storage.local.directory.clone())
    }

    pub fn with_root(root: impl Into<PathBuf>) -> Result<Self, Error> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(Error::InvalidConfiguration("root must not be empty"));
        }
        Ok(Self {
            object_store: object_store::ObjectStore::new(root)
                .map_err(|error| Error::ObjectStore(error.to_string()))?,
        })
    }

    pub fn root(&self) -> &Path {
        self.object_store.root()
    }

    pub fn object_put(&self, path: &str, payload: &[u8]) -> Result<(), Error> {
        self.object_store
            .put(path, payload)
            .map_err(|error| Error::ObjectStore(error.to_string()))
    }

    pub fn object_get(&self, path: &str) -> Result<Vec<u8>, Error> {
        self.object_store.get(path).map_err(|error| match error {
            object_store::Error::NotFound(path) => Error::NotFound(path),
            other => Error::ObjectStore(other.to_string()),
        })
    }

    pub fn object_exists(&self, path: &str) -> Result<bool, Error> {
        self.object_store
            .exists(path)
            .map_err(|error| Error::ObjectStore(error.to_string()))
    }

    pub fn object_put_json<T: Serialize>(&self, path: &str, value: &T) -> Result<(), Error> {
        let payload =
            serde_json::to_vec(value).map_err(|error| Error::Serialization(error.to_string()))?;
        self.object_put(path, &payload)
    }

    pub fn object_get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let payload = self.object_get(path)?;
        serde_json::from_slice(&payload).map_err(|error| Error::Serialization(error.to_string()))
    }

    pub fn object_list_json<T: DeserializeOwned>(&self, prefix: &str) -> Result<Vec<T>, Error> {
        let paths = self.object_list(prefix)?;
        let mut values = Vec::with_capacity(paths.len());
        for path in paths {
            let payload = self.object_get(&path)?;
            let value = serde_json::from_slice(&payload)
                .map_err(|error| Error::Serialization(error.to_string()))?;
            values.push(value);
        }
        Ok(values)
    }

    pub fn object_list(&self, prefix: &str) -> Result<Vec<String>, Error> {
        self.object_store
            .list_prefix(prefix)
            .map_err(|error| Error::ObjectStore(error.to_string()))
    }

    pub fn object_delete(&self, path: &str) -> Result<(), Error> {
        self.object_store
            .delete(path)
            .map_err(|error| Error::ObjectStore(error.to_string()))
    }

    pub fn object_delete_prefix(&self, prefix: &str) -> Result<(), Error> {
        self.object_store
            .delete_prefix(prefix)
            .map_err(|error| Error::ObjectStore(error.to_string()))
    }

    pub fn sample_put(&self, data: &[u8]) -> Result<String, Error> {
        let sha256 = digest_hex(data);
        let path = sample_data_path(&sha256);
        if self.object_exists(&path)? {
            return Ok(sha256);
        }
        self.object_put(&path, data)?;
        Ok(sha256)
    }

    pub fn sample_get(&self, sha256: &str) -> Result<Vec<u8>, Error> {
        self.object_get(&sample_data_path(sha256))
    }

    pub fn sample_exists(&self, sha256: &str) -> Result<bool, Error> {
        self.object_exists(&sample_data_path(sha256))
    }

    pub fn sample_json_put<T: Serialize>(
        &self,
        sha256: &str,
        name: &str,
        value: &T,
    ) -> Result<(), Error> {
        self.object_put_json(&sample_json_path(sha256, name), value)
    }

    pub fn sample_json_get<T: DeserializeOwned>(
        &self,
        sha256: &str,
        name: &str,
    ) -> Result<T, Error> {
        self.object_get_json(&sample_json_path(sha256, name))
    }
}
fn digest_hex(data: &[u8]) -> String {
    SHA256::new(data)
        .hexdigest()
        .expect("sha256 should be computable for local store samples")
}

fn sample_data_path(sha256: &str) -> String {
    format!("samples/{0}/{0}", sha256)
}

fn sample_json_path(sha256: &str, name: &str) -> String {
    format!("samples/{0}/{0}.{1}.json", sha256, name)
}
