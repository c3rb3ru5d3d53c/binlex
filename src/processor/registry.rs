use crate::Config;
use crate::config::{ConfigProcessor, ConfigProcessors};
use crate::controlflow::{Block, Function, Instruction};
use crate::io::stderr::Stderr;
use crate::processor::{ProcessorArchitecture, ProcessorOs, ProcessorTarget, ProcessorTransport};
use crate::runtime::ProcessorError;
use crate::server::error::ServerError;
use once_cell::sync::Lazy;
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
pub struct ProcessorRegistration {
    pub name: String,
    pub backend_name: String,
    pub requires: String,
    pub operating_systems: Vec<ProcessorOs>,
    pub architectures: Vec<ProcessorArchitecture>,
    pub transports: Vec<ProcessorTransport>,
    pub default_config: ConfigProcessor,
}

#[derive(Clone)]
pub struct RegisteredProcessor {
    pub id: u16,
    pub registration: ProcessorRegistration,
}

impl RegisteredProcessor {
    pub fn name(&self) -> &str {
        &self.registration.name
    }

    pub fn configured_transport(&self, config: &Config) -> ProcessorTransport {
        configured_graph_transport(&self.registration, config).unwrap_or(ProcessorTransport::Ipc)
    }

    pub fn process_block(&self, block: &Block<'_>) -> Option<Value> {
        if !self
            .registration
            .supports_architecture(block.architecture())
        {
            return None;
        }
        let data = serde_json::to_value(block.process_base()).ok()?;
        execute_graph_transport(&self.registration, data, &block.cfg.config).ok()
    }

    pub fn process_instruction(&self, instruction: &Instruction) -> Option<Value> {
        if !self
            .registration
            .supports_architecture(instruction.architecture)
        {
            return None;
        }
        let data = serde_json::to_value(instruction.process_base()).ok()?;
        execute_graph_transport(&self.registration, data, &instruction.config).ok()
    }

    pub fn process_function(&self, function: &Function<'_>) -> Option<Value> {
        if !self
            .registration
            .supports_architecture(function.architecture())
        {
            return None;
        }
        let data = function_processor_input(function).ok()?;
        execute_graph_transport(&self.registration, data, &function.cfg.config).ok()
    }
}

impl ProcessorRegistration {
    pub fn supported_on_current_os(&self) -> bool {
        self.operating_systems.contains(&ProcessorOs::current())
    }

    pub fn supports_architecture(&self, architecture: ProcessorArchitecture) -> bool {
        self.architectures.contains(&architecture)
    }

    pub fn supports_transport(&self, transport: &str) -> bool {
        self.transports
            .iter()
            .any(|supported| supported.as_str() == transport)
    }
}

static REGISTRATIONS: Lazy<Mutex<HashMap<Option<String>, Vec<ProcessorRegistration>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn config_key(configured_directory: Option<&str>) -> Option<String> {
    configured_directory.map(str::to_string)
}

fn cached_registrations(configured_directory: Option<&str>) -> Vec<ProcessorRegistration> {
    let key = config_key(configured_directory);
    let mut registrations = REGISTRATIONS.lock().unwrap();
    if let Some(registrations) = registrations.get(&key) {
        return registrations.clone();
    }
    let discovered = discover_processor_registrations(configured_directory);
    if !discovered.is_empty() {
        registrations.insert(key, discovered.clone());
    }
    discovered
}

fn discover_processor_registrations(
    configured_directory: Option<&str>,
) -> Vec<ProcessorRegistration> {
    let mut registrations = Vec::new();
    for candidate in processor_binary_candidates(configured_directory) {
        let Ok(output) = Command::new(&candidate).arg("--describe").output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let Ok(registration) = serde_json::from_slice::<ProcessorRegistration>(&output.stdout)
        else {
            continue;
        };
        if registration.name.is_empty() || registration.backend_name.is_empty() {
            continue;
        }
        registrations.push(registration);
    }
    registrations.sort_by(|left, right| left.name.cmp(&right.name));
    registrations.dedup_by(|left, right| left.name == right.name);
    registrations
}

fn processor_binary_candidates(configured_directory: Option<&str>) -> Vec<PathBuf> {
    let mut directories = Vec::new();
    if let Some(directory) = configured_directory {
        directories.push(PathBuf::from(directory));
    }
    directories.push(PathBuf::from(Config::default_processor_directory()));
    if let Ok(path) = env::var("PATH") {
        directories.extend(env::split_paths(&path));
    }
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            directories.push(parent.to_path_buf());
        }
    }
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        directories.push(PathBuf::from(manifest_dir).join("target/debug"));
        directories.push(PathBuf::from(manifest_dir).join("target/release"));
    }

    let mut seen = BTreeSet::new();
    let mut candidates = Vec::new();
    for directory in directories {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(filename) = filename_string(&path) else {
                continue;
            };
            if !filename.starts_with("binlex-processor-") {
                continue;
            }
            if seen.insert(path.clone()) {
                candidates.push(path);
            }
        }
    }
    candidates
}

fn filename_string(path: &Path) -> Option<String> {
    path.file_name()
        .and_then(|value| value.to_str())
        .map(|value| value.to_string())
}

fn configured_transport(
    processor: &ConfigProcessor,
    supported: &[ProcessorTransport],
) -> Result<ProcessorTransport, ProcessorError> {
    if processor.transport.ipc.enabled && supported.contains(&ProcessorTransport::Ipc) {
        return Ok(ProcessorTransport::Ipc);
    }
    if processor.transport.http.enabled && supported.contains(&ProcessorTransport::Http) {
        return Ok(ProcessorTransport::Http);
    }
    Err(ProcessorError::Protocol(
        "processor has no supported enabled transport".to_string(),
    ))
}

fn parse_version_requirement(requires: &str) -> Result<VersionReq, ProcessorError> {
    VersionReq::parse(requires)
        .or_else(|_| {
            let normalized = requires.split_whitespace().collect::<Vec<_>>().join(", ");
            VersionReq::parse(&normalized)
        })
        .map_err(|error| {
            ProcessorError::Protocol(format!(
                "invalid processor version requirement {}: {}",
                requires, error
            ))
        })
}

pub fn version_matches_requirement(version: &str, requires: &str) -> Result<bool, ProcessorError> {
    let version = Version::parse(version).map_err(|error| {
        ProcessorError::Protocol(format!("invalid binlex version {}: {}", version, error))
    })?;
    let requirement = parse_version_requirement(requires)?;
    Ok(requirement.matches(&version))
}

pub fn ensure_version_requirement(version: &str, requires: &str) -> Result<(), ProcessorError> {
    if version_matches_requirement(version, requires)? {
        return Ok(());
    }
    Err(ProcessorError::Protocol(format!(
        "binlex version {} does not satisfy processor requirement {}",
        version, requires
    )))
}

pub fn ensure_registration_host_compatibility(
    registration: &ProcessorRegistration,
) -> Result<(), ProcessorError> {
    ensure_version_requirement(crate::VERSION, &registration.requires)
}

pub fn registered_processor_registrations() -> Vec<ProcessorRegistration> {
    cached_registrations(None)
        .into_iter()
        .filter(ProcessorRegistration::supported_on_current_os)
        .collect()
}

pub fn registered_processor_registrations_for_config(
    config: &ConfigProcessors,
) -> Vec<ProcessorRegistration> {
    cached_registrations(config.path.as_deref())
        .into_iter()
        .filter(ProcessorRegistration::supported_on_current_os)
        .collect()
}

pub fn default_processor_configs() -> BTreeMap<String, ConfigProcessor> {
    registered_processor_registrations()
        .into_iter()
        .map(|registration| (registration.name.clone(), registration.default_config))
        .collect()
}

pub fn default_processor_config(name: &str) -> Option<ConfigProcessor> {
    processor_registration_by_name(name)
        .map(|registration| registration.registration.default_config)
}

pub fn processor_registration_by_name(name: &str) -> Option<RegisteredProcessor> {
    registered_processor_registrations()
        .into_iter()
        .find(|registration| registration.name == name)
        .map(|registration| RegisteredProcessor {
            id: 1,
            registration,
        })
}

pub fn processor_registration_by_name_for_config(
    config: &ConfigProcessors,
    name: &str,
) -> Option<RegisteredProcessor> {
    registered_processor_registrations_for_config(config)
        .into_iter()
        .find(|registration| registration.name == name)
        .map(|registration| RegisteredProcessor {
            id: 1,
            registration,
        })
}

pub fn enabled_processors_for_target(
    config: &Config,
    target: ProcessorTarget,
) -> Vec<RegisteredProcessor> {
    registered_processor_registrations_for_config(&config.processors)
        .into_iter()
        .filter(|registration| {
            config.processors.enabled
                && config
                    .processors
                    .processor(&registration.name)
                    .is_some_and(|processor| {
                        processor.enabled
                            && match target {
                                ProcessorTarget::Instruction => processor.instructions.enabled,
                                ProcessorTarget::Block => processor.blocks.enabled,
                                ProcessorTarget::Function => processor.functions.enabled,
                            }
                    })
        })
        .map(|registration| RegisteredProcessor {
            id: 1,
            registration,
        })
        .collect()
}

fn report_transport_error(config: &Config, processor_name: &str, error: &ProcessorError) {
    if config.general.debug {
        Stderr::print_debug(
            config,
            format!("processor {} transport error: {}", processor_name, error),
        );
    }
}

fn fail_transport(config: &Config, processor_name: &str, error: &ProcessorError) {
    report_transport_error(config, processor_name, error);
    eprintln!("processor {} transport error: {}", processor_name, error);
}

fn should_fail_transport(error: &ProcessorError) -> bool {
    matches!(
        error,
        ProcessorError::Io(_)
            | ProcessorError::Spawn(_)
            | ProcessorError::BinaryNotFound(_)
            | ProcessorError::Timeout(_)
            | ProcessorError::Protocol(_)
    )
}

fn configured_graph_transport(
    registration: &ProcessorRegistration,
    config: &Config,
) -> Result<ProcessorTransport, ProcessorError> {
    let Some(processor) = config.processors.processor(&registration.name) else {
        return Ok(ProcessorTransport::Ipc);
    };
    configured_transport(processor, &registration.transports).map_err(|error| {
        ProcessorError::Protocol(format!(
            "processor {} transport selection failed: {}",
            registration.name, error
        ))
    })
}

fn execute_graph_transport(
    registration: &ProcessorRegistration,
    data: Value,
    config: &Config,
) -> Result<Value, ProcessorError> {
    ensure_payload_architecture_supported(registration, &data)?;
    match configured_graph_transport(registration, config)? {
        ProcessorTransport::Ipc => crate::runtime::transports::ipc::execute_external(
            &registration.name,
            &config.processors,
            data,
        ),
        ProcessorTransport::Http => {
            let processor = config
                .processors
                .processor(&registration.name)
                .ok_or_else(|| {
                    ProcessorError::Protocol(format!(
                        "processor {} is not configured",
                        registration.name
                    ))
                })?;
            crate::runtime::transports::http::execute(&registration.name, data, config, processor)
        }
    }
    .map_err(|error| {
        if should_fail_transport(&error) {
            fail_transport(config, &registration.name, &error);
            return error;
        }
        report_transport_error(config, &registration.name, &error);
        error
    })
}

fn payload_architecture(data: &Value) -> Result<Option<ProcessorArchitecture>, ProcessorError> {
    let Some(architecture) = data.get("architecture").and_then(Value::as_str) else {
        return Ok(None);
    };
    ProcessorArchitecture::from_string(architecture)
        .map(Some)
        .map_err(|error| ProcessorError::Protocol(error.to_string()))
}

pub(crate) fn ensure_payload_architecture_supported(
    registration: &ProcessorRegistration,
    data: &Value,
) -> Result<(), ProcessorError> {
    let Some(architecture) = payload_architecture(data)? else {
        return Ok(());
    };
    if registration.supports_architecture(architecture) {
        return Ok(());
    }
    Err(ProcessorError::Protocol(format!(
        "processor {} does not support architecture {}",
        registration.name, architecture
    )))
}

pub(crate) fn ensure_payload_architecture_supported_server(
    registration: &ProcessorRegistration,
    data: &Value,
) -> Result<(), ServerError> {
    ensure_payload_architecture_supported(registration, data).map_err(ServerError::from)
}

pub fn external_processor_registration(
    name: &str,
    requires: &str,
    operating_systems: &[ProcessorOs],
    architectures: &[ProcessorArchitecture],
    transports: &[ProcessorTransport],
    default_config: ConfigProcessor,
) -> ProcessorRegistration {
    ProcessorRegistration {
        name: name.to_string(),
        backend_name: crate::runtime::dispatch::processor_backend_filename(name),
        requires: requires.to_string(),
        operating_systems: operating_systems.to_vec(),
        architectures: architectures.to_vec(),
        transports: transports.to_vec(),
        default_config,
    }
}

fn function_processor_input(function: &Function<'_>) -> Result<Value, serde_json::Error> {
    let mut data = serde_json::to_value(function.process_base())?;
    let cfg_blocks = function
        .blocks()
        .into_iter()
        .map(|block| {
            let instructions = block.instructions();
            json!({
                "address": block.address(),
                "chromosome": block.chromosome_json(),
                "entropy": block.entropy(),
                "size": block.size(),
                "edges": block.edges(),
                "number_of_instructions": block.number_of_instructions(),
                "call_count": instructions.iter().filter(|instruction| instruction.is_call).count(),
                "direct_call_count": instructions
                    .iter()
                    .filter(|instruction| instruction.is_call && !instruction.has_indirect_target)
                    .count(),
                "indirect_call_count": instructions
                    .iter()
                    .filter(|instruction| instruction.is_call && instruction.has_indirect_target)
                    .count(),
                "conditional": block.terminator.is_conditional,
                "is_return": block.terminator.is_return,
                "is_trap": block.terminator.is_trap,
                "contiguous": block.contiguous(),
                "next": block.next(),
                "to": block.to().into_iter().collect::<Vec<_>>(),
                "blocks": block.blocks().into_iter().collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();
    if let Value::Object(ref mut map) = data {
        map.insert("cfg_blocks".to_string(), serde_json::to_value(cfg_blocks)?);
    }
    Ok(data)
}
