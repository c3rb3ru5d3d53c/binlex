use std::env;
use std::path::PathBuf;

use crate::ConfigProcessors;
use serde::{Deserialize, Serialize};

use crate::processing::error::ProcessorError;

pub trait Processor: Send + Sync + Default + 'static {
    const NAME: &'static str;
    type Request: Serialize + for<'de> Deserialize<'de>;
    type Response: Serialize + for<'de> Deserialize<'de>;

    fn request(&self, request: Self::Request) -> Result<Self::Response, ProcessorError>;

    fn execute(request: Self::Request) -> Result<Self::Response, ProcessorError>
    where
        Self: Sized,
    {
        Self::default().request(request)
    }

    fn filename() -> String {
        "binlex-processor".to_string()
    }

    fn path(config: &ConfigProcessors) -> Result<PathBuf, ProcessorError> {
        resolve_processor_path(&Self::filename(), config.path.as_deref())
    }

    fn process(&self, payload: &[u8]) -> Result<Vec<u8>, ProcessorError> {
        let request: Self::Request = postcard::from_bytes(payload)?;
        let response = self.request(request)?;
        Ok(postcard::to_allocvec(&response)?)
    }
}

pub trait ProcessorDispatch: Send + Sync {
    fn process(&self, payload: &[u8]) -> Result<Vec<u8>, ProcessorError>;
}

impl<T: Processor> ProcessorDispatch for T {
    fn process(&self, payload: &[u8]) -> Result<Vec<u8>, ProcessorError> {
        Processor::process(self, payload)
    }
}

fn resolve_processor_path(
    filename: &str,
    configured_directory: Option<&str>,
) -> Result<PathBuf, ProcessorError> {
    if let Some(path) = configured_directory {
        if let Some(candidate) = find_in_directory(PathBuf::from(path), filename) {
            return Ok(candidate);
        }
    }

    if let Ok(path) = env::var("PATH") {
        for path_entry in env::split_paths(&path) {
            if let Some(candidate) = find_in_directory(path_entry, filename) {
                return Ok(candidate);
            }
        }
    }

    let current_exe = env::current_exe().map_err(ProcessorError::Io)?;
    if let Some(directory) = current_exe.parent() {
        if let Some(candidate) = find_in_directory(directory.to_path_buf(), filename) {
            return Ok(candidate);
        }
    }

    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        for directory in [
            PathBuf::from(manifest_dir).join("target/release"),
            PathBuf::from(manifest_dir).join("target/debug"),
        ] {
            if let Some(candidate) = find_in_directory(directory, filename) {
                return Ok(candidate);
            }
        }
    }

    Err(ProcessorError::BinaryNotFound(filename.to_string()))
}

fn find_in_directory(directory: PathBuf, filename: &str) -> Option<PathBuf> {
    for candidate in [
        directory.join(filename),
        directory.join(format!("{}.exe", filename)),
    ] {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}
