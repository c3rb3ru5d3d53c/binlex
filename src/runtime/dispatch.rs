use std::env;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};

use crate::config::ConfigProcessors;
use serde::{Deserialize, Serialize};

use crate::runtime::error::ProcessorError;

const PROCESSOR_BACKEND_PREFIX: &str = "binlex-processor-";
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostRuntime {
    Native,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkerLaunch {
    Binary(PathBuf),
    Command(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRuntimeError {
    Conflict {
        current: HostRuntime,
        attempted: HostRuntime,
    },
}

impl std::fmt::Display for HostRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Conflict { current, attempted } => write!(
                f,
                "host runtime already registered as {:?}, cannot replace with {:?}",
                current, attempted
            ),
        }
    }
}

impl std::error::Error for HostRuntimeError {}

static HOST_RUNTIME: LazyLock<RwLock<HostRuntime>> =
    LazyLock::new(|| RwLock::new(HostRuntime::Native));

pub trait Processor: Send + Sync + Default + 'static {
    const NAME: &'static str;
    type Request: Serialize + for<'de> Deserialize<'de>;
    type Response: Serialize + for<'de> Deserialize<'de>;

    fn execute(&self, request: Self::Request) -> Result<Self::Response, ProcessorError>;

    fn execute_owned(request: Self::Request) -> Result<Self::Response, ProcessorError>
    where
        Self: Sized,
    {
        Self::default().execute(request)
    }

    fn filename() -> String {
        processor_backend_filename(Self::NAME)
    }

    fn launches(config: &ConfigProcessors) -> Result<Vec<WorkerLaunch>, ProcessorError> {
        resolve_worker_launches(&Self::filename(), config.path.as_deref())
    }

    fn process(&self, payload: &[u8]) -> Result<Vec<u8>, ProcessorError> {
        let request: Self::Request = postcard::from_bytes(payload)?;
        let response = self.execute(request)?;
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

pub fn register_host_runtime(runtime: HostRuntime) -> Result<(), HostRuntimeError> {
    let mut current = HOST_RUNTIME
        .write()
        .map_err(|_| HostRuntimeError::Conflict {
            current: HostRuntime::Native,
            attempted: runtime.clone(),
        })?;
    if *current == runtime {
        return Ok(());
    }
    if matches!(&*current, HostRuntime::Native) {
        *current = runtime;
        return Ok(());
    }
    Err(HostRuntimeError::Conflict {
        current: current.clone(),
        attempted: runtime,
    })
}

pub fn host_runtime() -> HostRuntime {
    HOST_RUNTIME
        .read()
        .map(|runtime| runtime.clone())
        .unwrap_or(HostRuntime::Native)
}

pub fn processor_backend_filename(processor_name: &str) -> String {
    format!("{}{}", PROCESSOR_BACKEND_PREFIX, processor_name)
}

pub fn resolve_worker_launches(
    filename: &str,
    configured_directory: Option<&str>,
) -> Result<Vec<WorkerLaunch>, ProcessorError> {
    resolve_worker_launches_for_runtime(filename, configured_directory, &host_runtime())
}

fn resolve_worker_launches_for_runtime(
    filename: &str,
    configured_directory: Option<&str>,
    runtime: &HostRuntime,
) -> Result<Vec<WorkerLaunch>, ProcessorError> {
    let mut launches = Vec::new();
    if let Some(command) = preferred_worker_command(filename, runtime) {
        launches.push(WorkerLaunch::Command(command));
    }

    let default_directory = crate::Config::default_processor_directory();

    if let Some(path) = configured_directory.filter(|path| *path != default_directory) {
        if let Some(candidate) = find_in_directory(PathBuf::from(path), filename) {
            launches.push(WorkerLaunch::Binary(candidate));
            return Ok(launches);
        }
    }

    let current_exe = env::current_exe().map_err(ProcessorError::Io)?;
    if let Some(directory) = current_exe.parent() {
        if let Some(candidate) = find_in_directory(directory.to_path_buf(), filename) {
            launches.push(WorkerLaunch::Binary(candidate));
            return Ok(launches);
        }
    }

    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        for directory in [
            PathBuf::from(manifest_dir).join("target/release"),
            PathBuf::from(manifest_dir).join("target/debug"),
        ] {
            if let Some(candidate) = find_in_directory(directory, filename) {
                launches.push(WorkerLaunch::Binary(candidate));
                return Ok(launches);
            }
        }
    }

    if let Some(path) = configured_directory.filter(|path| *path == default_directory) {
        if let Some(candidate) = find_in_directory(PathBuf::from(path), filename) {
            launches.push(WorkerLaunch::Binary(candidate));
            return Ok(launches);
        }
    }

    if let Ok(path) = env::var("PATH") {
        for path_entry in env::split_paths(&path) {
            if let Some(candidate) = find_in_directory(path_entry, filename) {
                launches.push(WorkerLaunch::Binary(candidate));
                return Ok(launches);
            }
        }
    }

    if launches.is_empty() {
        Err(ProcessorError::BinaryNotFound(filename.to_string()))
    } else {
        Ok(launches)
    }
}

fn preferred_worker_command(filename: &str, runtime: &HostRuntime) -> Option<Vec<String>> {
    let _ = filename;
    let _ = runtime;
    None
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

#[cfg(test)]
mod tests {
    use std::sync::{LazyLock, Mutex};

    use super::{HostRuntime, WorkerLaunch, resolve_worker_launches_for_runtime};

    static PATH_ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn configured_directory_is_used_when_present() {
        let tempdir =
            std::env::temp_dir().join(format!("binlex-dispatch-test-{}", std::process::id()));
        std::fs::create_dir_all(&tempdir).expect("tempdir should exist");
        let processor = tempdir.join("binlex-processor-embeddings");
        std::fs::write(&processor, b"stub").expect("processor stub should be written");

        let launches = resolve_worker_launches_for_runtime(
            "binlex-processor-embeddings",
            Some(tempdir.to_string_lossy().as_ref()),
            &HostRuntime::Native,
        )
        .expect("configured directory should resolve launch candidates");

        assert_eq!(
            launches.first(),
            Some(&WorkerLaunch::Binary(processor.clone()))
        );
        assert!(launches.contains(&WorkerLaunch::Binary(processor)));
        let _ = std::fs::remove_dir_all(tempdir);
    }

    #[test]
    fn missing_configured_directory_falls_back_to_available_search_locations() {
        let _path_lock = PATH_ENV_LOCK
            .lock()
            .expect("path environment lock should not be poisoned");
        let tempdir = std::env::temp_dir().join(format!(
            "binlex-dispatch-fallback-test-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&tempdir).expect("tempdir should exist");
        let processor = tempdir.join("binlex-processor-embeddings");
        std::fs::write(&processor, b"stub").expect("processor stub should be written");

        let original_path = std::env::var_os("PATH");
        // PATH mutation is process-global, so guard it with a test-only mutex.
        unsafe {
            std::env::set_var("PATH", &tempdir);
        }

        let launches = resolve_worker_launches_for_runtime(
            "binlex-processor-embeddings",
            Some("/definitely/missing/binlex/processors"),
            &HostRuntime::Native,
        )
        .expect("path fallback should still resolve launch candidates");

        assert!(
            !launches.is_empty(),
            "fallback search should resolve at least one launch candidate"
        );
        match launches.first() {
            Some(WorkerLaunch::Binary(path)) => {
                assert!(
                    path.exists(),
                    "resolved fallback binary should exist: {}",
                    path.display()
                );
                assert_eq!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("binlex-processor-embeddings")
                );
            }
            other => panic!("expected binary launch candidate, got {other:?}"),
        }

        match original_path {
            Some(path) => unsafe {
                std::env::set_var("PATH", path);
            },
            None => unsafe {
                std::env::remove_var("PATH");
            },
        }
        let _ = std::fs::remove_dir_all(tempdir);
    }
}
