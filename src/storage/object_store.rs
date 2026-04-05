use futures::TryStreamExt;
use object_store::ObjectStore as ObjectStoreApi;
use object_store::ObjectStoreExt;
use object_store::PutPayload;
use object_store::local::LocalFileSystem;
use object_store::path::Path as ObjectPath;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

#[derive(Clone)]
pub struct ObjectStore {
    root: PathBuf,
    store: Arc<dyn ObjectStoreApi>,
    runtime: Arc<Runtime>,
}

#[derive(Debug)]
pub enum Error {
    InvalidConfiguration(&'static str),
    InvalidPath(String),
    Io(String),
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
            Self::NotFound(message) => write!(f, "object store not found: {}", message),
        }
    }
}

impl std::error::Error for Error {}

impl ObjectStore {
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

    pub fn put(&self, path: &str, payload: &[u8]) -> Result<(), Error> {
        let path = object_path(path)?;
        self.runtime
            .block_on(
                self.store
                    .put(&path, PutPayload::from_bytes(payload.to_vec().into())),
            )
            .map(|_| ())
            .map_err(|error| Error::Io(error.to_string()))
    }

    pub fn get(&self, path: &str) -> Result<Vec<u8>, Error> {
        let location = object_path(path)?;
        let result =
            self.runtime
                .block_on(self.store.get(&location))
                .map_err(|error| match error {
                    object_store::Error::NotFound { .. } => Error::NotFound(path.to_string()),
                    other => Error::Io(other.to_string()),
                })?;
        let bytes = self
            .runtime
            .block_on(result.bytes())
            .map_err(|error| Error::Io(error.to_string()))?;
        Ok(bytes.to_vec())
    }

    pub fn exists(&self, path: &str) -> Result<bool, Error> {
        let location = object_path(path)?;
        match self.runtime.block_on(self.store.head(&location)) {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(error) => Err(Error::Io(error.to_string())),
        }
    }

    pub fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, Error> {
        let location = object_path(prefix)?;
        let stream = self.store.list(Some(&location));
        let objects = self
            .runtime
            .block_on(stream.try_collect::<Vec<_>>())
            .map_err(|error| Error::Io(error.to_string()))?;
        Ok(objects
            .into_iter()
            .map(|meta| meta.location.to_string())
            .collect())
    }

    pub fn delete(&self, path: &str) -> Result<(), Error> {
        let location = object_path(path)?;
        self.runtime
            .block_on(self.store.delete(&location))
            .map_err(|error| Error::Io(error.to_string()))
    }

    pub fn delete_prefix(&self, prefix: &str) -> Result<(), Error> {
        let location = object_path(prefix)?;
        let stream = self.store.list(Some(&location));
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

fn object_path(path: &str) -> Result<ObjectPath, Error> {
    ObjectPath::parse(path).map_err(|error| Error::InvalidPath(error.to_string()))
}
