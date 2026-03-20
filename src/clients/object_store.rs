use futures::TryStreamExt;
use object_store::ObjectStore;
use object_store::ObjectStoreExt;
use object_store::PutPayload;
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use serde::{Serialize, de::DeserializeOwned};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

#[derive(Clone)]
pub struct Client {
    root: PathBuf,
    store: Arc<dyn ObjectStore>,
    runtime: Arc<Runtime>,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    InvalidPath(String),
    Io(String),
    Serialization(String),
    NotFound(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(message) => {
                write!(f, "object store configuration error: {}", message)
            }
            Self::InvalidPath(message) => write!(f, "object store invalid path: {}", message),
            Self::Io(message) => write!(f, "object store io error: {}", message),
            Self::Serialization(message) => {
                write!(f, "object store serialization error: {}", message)
            }
            Self::NotFound(message) => write!(f, "object store not found: {}", message),
        }
    }
}

impl std::error::Error for Error {}

impl Client {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, Error> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(Error::InvalidConfiguration("root must not be empty"));
        }
        std::fs::create_dir_all(&root).map_err(|error| Error::Io(error.to_string()))?;
        let store = LocalFileSystem::new_with_prefix(&root)
            .map_err(|error| Error::Io(error.to_string()))?;
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| Error::Io(error.to_string()))?;
        Ok(Self {
            root,
            store: Arc::new(store),
            runtime: Arc::new(runtime),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put_bytes(&self, key: &str, payload: &[u8]) -> Result<(), Error> {
        let path = object_path(key)?;
        self.runtime
            .block_on(
                self.store
                    .put(&path, PutPayload::from_bytes(payload.to_vec().into())),
            )
            .map(|_| ())
            .map_err(|error| Error::Io(error.to_string()))
    }

    pub fn get_bytes(&self, key: &str) -> Result<Vec<u8>, Error> {
        let path = object_path(key)?;
        let result = self
            .runtime
            .block_on(self.store.get(&path))
            .map_err(|error| match error {
                object_store::Error::NotFound { .. } => Error::NotFound(key.to_string()),
                other => Error::Io(other.to_string()),
            })?;
        let bytes = self
            .runtime
            .block_on(result.bytes())
            .map_err(|error| Error::Io(error.to_string()))?;
        Ok(bytes.to_vec())
    }

    pub fn exists(&self, key: &str) -> Result<bool, Error> {
        let path = object_path(key)?;
        match self.runtime.block_on(self.store.head(&path)) {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(error) => Err(Error::Io(error.to_string())),
        }
    }

    pub fn put_json<T: Serialize>(&self, key: &str, value: &T) -> Result<(), Error> {
        let payload =
            serde_json::to_vec(value).map_err(|error| Error::Serialization(error.to_string()))?;
        self.put_bytes(key, &payload)
    }

    pub fn get_json<T: DeserializeOwned>(&self, key: &str) -> Result<T, Error> {
        let payload = self.get_bytes(key)?;
        serde_json::from_slice(&payload).map_err(|error| Error::Serialization(error.to_string()))
    }

    pub fn delete_prefix(&self, prefix: &str) -> Result<(), Error> {
        let path = object_path(prefix)?;
        let stream = self.store.list(Some(&path));
        let objects = self
            .runtime
            .block_on(stream.try_collect::<Vec<_>>())
            .map_err(|error| Error::Io(error.to_string()))?;
        for meta in objects {
            self.runtime
                .block_on(self.store.delete(&meta.location))
                .map_err(|error| Error::Io(error.to_string()))?;
        }
        Ok(())
    }
}

fn object_path(key: &str) -> Result<ObjectPath, Error> {
    ObjectPath::parse(key).map_err(|error| Error::InvalidPath(error.to_string()))
}
