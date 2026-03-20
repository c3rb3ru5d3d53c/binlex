use std::env;
use std::path::PathBuf;
use std::sync::{LazyLock, RwLock};

use crate::config::ConfigProcessors;
use serde::{Deserialize, Serialize};

use crate::runtime::error::ProcessorError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostRuntime {
    Native,
    Python { executable: PathBuf },
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

    fn launches(config: &ConfigProcessors) -> Result<Vec<WorkerLaunch>, ProcessorError> {
        resolve_worker_launches(&Self::filename(), config.path.as_deref())
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
    if let Some(path) = configured_directory {
        if let Some(candidate) = find_in_directory(PathBuf::from(path), filename) {
            return Ok(vec![WorkerLaunch::Binary(candidate)]);
        }
        return Err(ProcessorError::BinaryNotFound(filename.to_string()));
    }

    let mut launches = Vec::new();
    if let Some(command) = preferred_worker_command(filename, runtime) {
        launches.push(WorkerLaunch::Command(command));
    }

    if let Ok(path) = env::var("PATH") {
        for path_entry in env::split_paths(&path) {
            if let Some(candidate) = find_in_directory(path_entry, filename) {
                launches.push(WorkerLaunch::Binary(candidate));
                return Ok(launches);
            }
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

    if launches.is_empty() {
        Err(ProcessorError::BinaryNotFound(filename.to_string()))
    } else {
        Ok(launches)
    }
}

fn preferred_worker_command(filename: &str, runtime: &HostRuntime) -> Option<Vec<String>> {
    match runtime {
        HostRuntime::Native => None,
        HostRuntime::Python { executable } if filename == "binlex-processor" => {
            let executable = executable.to_string_lossy().into_owned();
            if executable.is_empty() {
                return None;
            }
            Some(vec![
                executable,
                "-m".to_string(),
                "binlex._processor".to_string(),
            ])
        }
        HostRuntime::Python { .. } => None,
    }
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
    use super::{
        HostRuntime, WorkerLaunch, preferred_worker_command, resolve_worker_launches_for_runtime,
    };
    use std::path::PathBuf;

    #[test]
    fn python_runtime_prefers_module_worker_command() {
        let launches = resolve_worker_launches_for_runtime(
            "binlex-processor",
            None,
            &HostRuntime::Python {
                executable: PathBuf::from("/usr/bin/python3"),
            },
        )
        .expect("python runtime should resolve at least the module worker command");

        assert!(matches!(
            launches.first(),
            Some(WorkerLaunch::Command(command))
                if command == &[
                    "/usr/bin/python3".to_string(),
                    "-m".to_string(),
                    "binlex._processor".to_string()
                ]
        ));
    }

    #[test]
    fn configured_directory_overrides_python_runtime_command() {
        let tempdir =
            std::env::temp_dir().join(format!("binlex-dispatch-test-{}", std::process::id()));
        std::fs::create_dir_all(&tempdir).expect("tempdir should exist");
        let processor = tempdir.join("binlex-processor");
        std::fs::write(&processor, b"stub").expect("processor stub should be written");

        let launches = resolve_worker_launches_for_runtime(
            "binlex-processor",
            Some(tempdir.to_string_lossy().as_ref()),
            &HostRuntime::Python {
                executable: PathBuf::from("/usr/bin/python3"),
            },
        )
        .expect("configured directory should resolve the processor binary");

        assert_eq!(launches, vec![WorkerLaunch::Binary(processor)]);
        let _ = std::fs::remove_dir_all(tempdir);
    }

    #[test]
    fn python_runtime_only_prefers_module_for_processor_worker() {
        assert_eq!(
            preferred_worker_command(
                "binlex-server",
                &HostRuntime::Python {
                    executable: PathBuf::from("/usr/bin/python3"),
                }
            ),
            None
        );
    }
}
