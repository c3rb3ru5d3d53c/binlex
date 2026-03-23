use crate::Config;
use crate::config::ConfigProcessor;
use crate::controlflow::{Block, Function, Instruction};
use crate::io::stderr::Stderr;
use crate::processor::{ProcessorArchitecture, ProcessorOs, ProcessorTarget, ProcessorTransport};
use crate::processors::embeddings;
#[cfg(not(target_os = "windows"))]
use crate::processors::vex;
use crate::runtime::{Processor, ProcessorDispatch, ProcessorError, ProcessorPool};
use crate::server::error::ServerError;
use crate::server::state::AppState;
use once_cell::sync::Lazy;
use semver::{Version, VersionReq};
use serde_json::Value;
use std::collections::BTreeMap;
use std::process;
use std::sync::Arc;

pub struct ProcessorRegistration {
    pub name: &'static str,
    pub requires: &'static str,
    pub operating_systems: &'static [ProcessorOs],
    pub architectures: &'static [ProcessorArchitecture],
    pub transports: &'static [ProcessorTransport],
    pub make_pool:
        fn(&crate::config::ConfigProcessors) -> Result<Arc<ProcessorPool>, ProcessorError>,
    pub make_dispatch: fn() -> Box<dyn ProcessorDispatch>,
    pub config_default: fn() -> ConfigProcessor,
    pub enabled_for_target: fn(&Config, ProcessorTarget) -> bool,
    pub execute_graph_value: Option<fn(&Config, Value) -> Result<Value, ProcessorError>>,
    pub execute_value: Option<fn(&AppState, Value) -> Result<Value, ServerError>>,
    pub instruction_json: Option<fn(&Instruction) -> Option<Value>>,
    pub block_json: Option<fn(&Block<'_>) -> Option<Value>>,
    pub function_json: Option<fn(&Function<'_>) -> Option<Value>>,
    pub process_instruction: Option<fn(&Instruction) -> Option<Value>>,
    pub process_block: Option<fn(&Block<'_>) -> Option<Value>>,
    pub process_function: Option<fn(&Function<'_>) -> Option<Value>>,
}

pub struct RegisteredProcessor<'a> {
    pub id: u16,
    pub registration: &'a ProcessorRegistration,
}

impl<'a> RegisteredProcessor<'a> {
    pub fn name(&self) -> &'static str {
        self.registration.name
    }

    pub fn configured_transport(&self, config: &Config) -> ProcessorTransport {
        configured_graph_transport(self.registration, config).unwrap_or(ProcessorTransport::Inline)
    }

    pub fn process_block(&self, block: &Block<'_>) -> Option<Value> {
        if !self
            .registration
            .supports_architecture(block.architecture())
        {
            return None;
        }
        if let Some(data) = self
            .registration
            .block_json
            .and_then(|serialize| serialize(block))
        {
            match execute_graph_transport(self.registration, data, &block.cfg.config) {
                Ok(Some(data)) => return Some(data),
                Ok(None) => {}
                Err(error) => {
                    if should_fail_transport(&error) {
                        fail_transport(&block.cfg.config, self.name(), &error);
                    }
                    report_transport_error(&block.cfg.config, self.name(), &error);
                    return None;
                }
            }
        }
        self.registration
            .process_block
            .and_then(|process| process(block))
    }

    pub fn process_instruction(&self, instruction: &Instruction) -> Option<Value> {
        if !self
            .registration
            .supports_architecture(instruction.architecture)
        {
            return None;
        }
        if let Some(data) = self
            .registration
            .instruction_json
            .and_then(|serialize| serialize(instruction))
        {
            match execute_graph_transport(self.registration, data, &instruction.config) {
                Ok(Some(data)) => return Some(data),
                Ok(None) => {}
                Err(error) => {
                    if should_fail_transport(&error) {
                        fail_transport(&instruction.config, self.name(), &error);
                    }
                    report_transport_error(&instruction.config, self.name(), &error);
                    return None;
                }
            }
        }
        self.registration
            .process_instruction
            .and_then(|process| process(instruction))
    }

    pub fn process_function(&self, function: &Function<'_>) -> Option<Value> {
        if !self
            .registration
            .supports_architecture(function.architecture())
        {
            return None;
        }
        if let Some(data) = self
            .registration
            .function_json
            .and_then(|serialize| serialize(function))
        {
            match execute_graph_transport(self.registration, data, &function.cfg.config) {
                Ok(Some(data)) => return Some(data),
                Ok(None) => {}
                Err(error) => {
                    if should_fail_transport(&error) {
                        fail_transport(&function.cfg.config, self.name(), &error);
                    }
                    report_transport_error(&function.cfg.config, self.name(), &error);
                    return None;
                }
            }
        }
        self.registration
            .process_function
            .and_then(|process| process(function))
    }

    pub fn into_dispatch(self) -> RegisteredProcessorDispatch {
        RegisteredProcessorDispatch {
            id: self.id,
            dispatch: (self.registration.make_dispatch)(),
        }
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

pub struct RegisteredProcessorDispatch {
    pub id: u16,
    pub dispatch: Box<dyn ProcessorDispatch>,
}

pub fn default_transport(
    supported: &[ProcessorTransport],
    inline_enabled: bool,
    ipc_enabled: bool,
    http_enabled: bool,
) -> ProcessorTransport {
    if inline_enabled && supported.contains(&ProcessorTransport::Inline) {
        return ProcessorTransport::Inline;
    }
    if ipc_enabled && supported.contains(&ProcessorTransport::Ipc) {
        return ProcessorTransport::Ipc;
    }
    if http_enabled && supported.contains(&ProcessorTransport::Http) {
        return ProcessorTransport::Http;
    }
    supported
        .first()
        .copied()
        .unwrap_or(ProcessorTransport::Inline)
}

fn configured_transport(
    processor: &ConfigProcessor,
    supported: &[ProcessorTransport],
) -> Result<ProcessorTransport, ProcessorError> {
    let transport = default_transport(
        supported,
        processor.transport.inline.enabled,
        processor.transport.ipc.enabled,
        processor.transport.http.enabled,
    );
    if !supported.contains(&transport) {
        return Err(ProcessorError::Protocol(
            "processor has no supported enabled transport".to_string(),
        ));
    }
    if !processor.transport(transport).enabled {
        return Err(ProcessorError::Protocol(
            "processor has no enabled transport".to_string(),
        ));
    }
    Ok(transport)
}

#[macro_export]
macro_rules! processor {
    (@value { $($key:ident : $value:tt),* $(,)? }) => {
        $crate::config::ConfigProcessorValue::Table(std::collections::BTreeMap::from([
            $(
                (
                    stringify!($key).to_string(),
                    $crate::processor!(@value $value),
                )
            ),*
        ]))
    };
    (@value [ $($value:tt),* $(,)? ]) => {
        $crate::config::ConfigProcessorValue::Array(vec![
            $(
                $crate::processor!(@value $value)
            ),*
        ])
    };
    (@value $value:expr) => {
        $crate::config::ConfigProcessorValue::from($value)
    };
    ($processor:path {
        requires: $requires:expr,
        operating_systems: [$($supported_os:expr),+ $(,)?],
        architectures: [$($supported_architecture:expr),+ $(,)?],
        enabled: $processor_enabled:expr,
        transports: [$($processor_transport:expr),+ $(,)?],
        instructions: { enabled: $instructions_enabled:expr },
        blocks: { enabled: $blocks_enabled:expr },
        functions: { enabled: $functions_enabled:expr },
        inline: {
            enabled: $inline_enabled:expr
            $(, options: { $($inline_option_key:ident : $inline_option_value:tt),* $(,)? })?
        },
        ipc: {
            enabled: $ipc_enabled:expr
            $(, options: { $($ipc_option_key:ident : $ipc_option_value:tt),* $(,)? })?
        },
        http: {
            enabled: $http_enabled:expr
            $(, options: { $($http_option_key:ident : $http_option_value:tt),* $(,)? })?
        }
        $(,)?
    }) => {
        $crate::processor!($processor {
            requires: $requires,
            operating_systems: [$($supported_os),+],
            architectures: [$($supported_architecture),+],
            enabled: $processor_enabled,
            transports: [$($processor_transport),+],
            instructions: { enabled: $instructions_enabled },
            blocks: { enabled: $blocks_enabled },
            functions: { enabled: $functions_enabled },
            options: {},
            inline: {
                enabled: $inline_enabled
                $(, options: { $($inline_option_key : $inline_option_value),* })?
            },
            ipc: {
                enabled: $ipc_enabled
                $(, options: { $($ipc_option_key : $ipc_option_value),* })?
            },
            http: {
                enabled: $http_enabled
                $(, options: { $($http_option_key : $http_option_value),* })?
            }
        });
    };
    ($processor:path {
        requires: $requires:expr,
        operating_systems: [$($supported_os:expr),+ $(,)?],
        architectures: [$($supported_architecture:expr),+ $(,)?],
        enabled: $processor_enabled:expr,
        transports: [$($processor_transport:expr),+ $(,)?],
        instructions: { enabled: $instructions_enabled:expr },
        blocks: { enabled: $blocks_enabled:expr },
        functions: { enabled: $functions_enabled:expr },
        options: { $($option_key:ident : $option_value:tt),* $(,)? },
        inline: {
            enabled: $inline_enabled:expr
            $(, options: { $($inline_option_key:ident : $inline_option_value:tt),* $(,)? })?
        },
        ipc: {
            enabled: $ipc_enabled:expr
            $(, options: { $($ipc_option_key:ident : $ipc_option_value:tt),* $(,)? })?
        },
        http: {
            enabled: $http_enabled:expr
            $(, options: { $($http_option_key:ident : $http_option_value:tt),* $(,)? })?
        }
        $(,)?
    }) => {
        pub(crate) fn config_default() -> $crate::config::ConfigProcessor {
            $crate::config::ConfigProcessor {
                enabled: $processor_enabled,
                instructions: $crate::config::ConfigProcessorTarget {
                    enabled: $instructions_enabled,
                    options: std::collections::BTreeMap::new(),
                },
                blocks: $crate::config::ConfigProcessorTarget {
                    enabled: $blocks_enabled,
                    options: std::collections::BTreeMap::new(),
                },
                functions: $crate::config::ConfigProcessorTarget {
                    enabled: $functions_enabled,
                    options: std::collections::BTreeMap::new(),
                },
                options: std::collections::BTreeMap::from([
                    $(
                        (
                            stringify!($option_key).to_string(),
                            $crate::processor!(@value $option_value),
                        )
                    ),*
                ]),
                transport: $crate::config::ConfigProcessorTransports {
                    inline: $crate::config::ConfigProcessorTransport {
                        enabled: $inline_enabled,
                        options: std::collections::BTreeMap::from([
                            $(
                                $(
                                    (
                                        stringify!($inline_option_key).to_string(),
                                        $crate::processor!(@value $inline_option_value),
                                    )
                                ),*
                            )?
                        ]),
                    },
                    ipc: $crate::config::ConfigProcessorTransport {
                        enabled: $ipc_enabled,
                        options: std::collections::BTreeMap::from([
                            $(
                                $(
                                    (
                                        stringify!($ipc_option_key).to_string(),
                                        $crate::processor!(@value $ipc_option_value),
                                    )
                                ),*
                            )?
                        ]),
                    },
                    http: $crate::config::ConfigProcessorTransport {
                        enabled: $http_enabled,
                        options: std::collections::BTreeMap::from([
                            $(
                                $(
                                    (
                                        stringify!($http_option_key).to_string(),
                                        $crate::processor!(@value $http_option_value),
                                    )
                                ),*
                            )?
                        ]),
                    },
                },
            }
        }

        pub(crate) fn registration() -> $crate::processor::ProcessorRegistration {
            $crate::processor::ProcessorRegistration {
                name: <$processor as $crate::runtime::dispatch::Processor>::NAME,
                requires: $requires,
                operating_systems: &[$($supported_os),+],
                architectures: &[$($supported_architecture),+],
                transports: &[$($processor_transport),+],
                make_pool: |config| $crate::runtime::transports::ipc::pool::ProcessorPool::for_processor::<$processor>(config),
                make_dispatch: || Box::new($processor),
                config_default,
                enabled_for_target: |config: &$crate::Config,
                                     target: $crate::processor::ProcessorTarget| {
                    config.processors.enabled
                        && config
                            .processors
                            .processor(<$processor as $crate::runtime::dispatch::Processor>::NAME)
                            .is_some_and(|processor| {
                                processor.enabled
                                    && match target {
                                        $crate::processor::ProcessorTarget::Instruction => {
                                            processor.instructions.enabled
                                        }
                                        $crate::processor::ProcessorTarget::Block => {
                                            processor.blocks.enabled
                                        }
                                        $crate::processor::ProcessorTarget::Function => {
                                            processor.functions.enabled
                                        }
                                    }
                            })
                },
                execute_graph_value: Some(<$processor as $crate::processor::JsonProcessor>::execute_ipc_value as fn(&$crate::Config, serde_json::Value) -> Result<serde_json::Value, $crate::runtime::error::ProcessorError>),
                execute_value: Some($crate::server::processors::execute_value::<$processor> as fn(&$crate::server::state::AppState, serde_json::Value) -> Result<serde_json::Value, $crate::server::error::ServerError>),
                instruction_json: Some(
                    <$processor as $crate::processor::GraphProcessor>::instruction_json
                        as fn(&$crate::controlflow::Instruction) -> Option<serde_json::Value>,
                ),
                block_json: Some(
                    <$processor as $crate::processor::GraphProcessor>::block_json
                        as fn(&$crate::controlflow::Block<'_>) -> Option<serde_json::Value>,
                ),
                function_json: Some(
                    <$processor as $crate::processor::GraphProcessor>::function_json
                        as fn(&$crate::controlflow::Function<'_>) -> Option<serde_json::Value>,
                ),
                process_instruction: Some(
                    <$processor as $crate::processor::GraphProcessor>::instruction
                        as fn(&$crate::controlflow::Instruction) -> Option<serde_json::Value>,
                ),
                process_block: Some(
                    <$processor as $crate::processor::GraphProcessor>::block
                        as fn(&$crate::controlflow::Block<'_>) -> Option<serde_json::Value>,
                ),
                process_function: Some(
                    <$processor as $crate::processor::GraphProcessor>::function
                        as fn(&$crate::controlflow::Function<'_>) -> Option<serde_json::Value>,
                ),
            }
        }
    };
    ($processor:path {
        requires: $requires:expr,
        operating_systems: [$($supported_os:expr),+ $(,)?],
        architectures: [$($supported_architecture:expr),+ $(,)?],
        enabled: $processor_enabled:expr,
        transports: [$($processor_transport:expr),+ $(,)?],
        instructions: { enabled: $instructions_enabled:expr },
        blocks: { enabled: $blocks_enabled:expr },
        functions: { enabled: $functions_enabled:expr },
        options: { $($option_key:ident : $option_value:tt),* $(,)? },
        inline: { enabled: $inline_enabled:expr },
        ipc: { enabled: $ipc_enabled:expr },
        http: {
            enabled: $http_enabled:expr
            $(, options: { $($http_option_key:ident : $http_option_value:tt),* $(,)? })?
        }
        $(,)?
    }) => {
        $crate::processor!($processor {
            requires: $requires,
            operating_systems: [$($supported_os),+],
            architectures: [$($supported_architecture),+],
            enabled: $processor_enabled,
            transports: [$($processor_transport),+],
            instructions: { enabled: $instructions_enabled },
            blocks: { enabled: $blocks_enabled },
            functions: { enabled: $functions_enabled },
            options: { $($option_key : $option_value),* },
            inline: { enabled: $inline_enabled },
            ipc: { enabled: $ipc_enabled },
            http: {
                enabled: $http_enabled
                $(, options: { $($http_option_key : $http_option_value),* })?
            }
        });
    };
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
    ensure_version_requirement(crate::VERSION, registration.requires)
}

#[cfg(not(target_os = "windows"))]
static PROCESSOR_REGISTRATIONS: Lazy<Vec<ProcessorRegistration>> =
    Lazy::new(|| vec![vex::registration(), embeddings::registration()]);

#[cfg(target_os = "windows")]
static PROCESSOR_REGISTRATIONS: Lazy<Vec<ProcessorRegistration>> =
    Lazy::new(|| vec![embeddings::registration()]);

fn processor_registrations() -> &'static [ProcessorRegistration] {
    PROCESSOR_REGISTRATIONS.as_slice()
}

pub fn registered_processor_registrations() -> &'static [ProcessorRegistration] {
    processor_registrations()
}

pub fn default_processor_configs() -> BTreeMap<String, ConfigProcessor> {
    processor_registrations()
        .iter()
        .filter(|registration| registration.supported_on_current_os())
        .map(|registration| {
            (
                registration.name.to_string(),
                (registration.config_default)(),
            )
        })
        .collect()
}

pub fn default_processor_config(name: &str) -> Option<ConfigProcessor> {
    processor_registration_by_name(name)
        .map(|registration| (registration.registration.config_default)())
}

pub fn processor_registration_by_name(name: &str) -> Option<RegisteredProcessor<'static>> {
    processor_registrations()
        .iter()
        .enumerate()
        .find(|(_, registration)| {
            registration.name == name && registration.supported_on_current_os()
        })
        .map(|(index, registration)| RegisteredProcessor {
            id: (index + 1) as u16,
            registration,
        })
}

pub(crate) fn processor_registration_by_name_unfiltered(
    name: &str,
) -> Option<RegisteredProcessor<'static>> {
    processor_registrations()
        .iter()
        .enumerate()
        .find(|(_, registration)| registration.name == name)
        .map(|(index, registration)| RegisteredProcessor {
            id: (index + 1) as u16,
            registration,
        })
}

pub fn processor_registration_by_type<P: Processor>() -> Option<RegisteredProcessor<'static>> {
    processor_registration_by_name(P::NAME)
}

pub fn enabled_processors_for_target(
    config: &Config,
    target: ProcessorTarget,
) -> Vec<RegisteredProcessor<'static>> {
    processor_registrations()
        .iter()
        .enumerate()
        .filter(|(_, registration)| {
            registration.supported_on_current_os()
                && (registration.enabled_for_target)(config, target)
        })
        .map(|(index, registration)| RegisteredProcessor {
            id: (index + 1) as u16,
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

fn fail_transport(config: &Config, processor_name: &str, error: &ProcessorError) -> ! {
    report_transport_error(config, processor_name, error);
    eprintln!("processor {} transport error: {}", processor_name, error);
    process::exit(1);
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
    let Some(processor) = config.processors.processor(registration.name) else {
        return Ok(ProcessorTransport::Inline);
    };
    configured_transport(processor, registration.transports).map_err(|error| {
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
) -> Result<Option<Value>, ProcessorError> {
    ensure_payload_architecture_supported(registration, &data)?;
    match configured_graph_transport(registration, config)? {
        ProcessorTransport::Inline => Ok(None),
        ProcessorTransport::Ipc => {
            let execute = registration.execute_graph_value.ok_or_else(|| {
                ProcessorError::Protocol(format!(
                    "processor {} does not implement graph IPC execution",
                    registration.name
                ))
            })?;
            execute(config, data).map(Some)
        }
        ProcessorTransport::Http => {
            let processor = config
                .processors
                .processor(registration.name)
                .ok_or_else(|| {
                    ProcessorError::Protocol(format!(
                        "processor {} is not configured",
                        registration.name
                    ))
                })?;
            crate::runtime::transports::http::execute(registration.name, data, config, processor)
                .map(Some)
        }
    }
}

pub fn dispatch_by_name(name: &str) -> Option<RegisteredProcessorDispatch> {
    processor_registration_by_name(name).map(RegisteredProcessor::into_dispatch)
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

#[cfg(test)]
mod tests {
    use super::{ProcessorArchitecture, ProcessorOs, ProcessorRegistration, ProcessorTransport};
    use crate::config::{
        ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn test_config_default() -> ConfigProcessor {
        ConfigProcessor {
            enabled: false,
            instructions: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            blocks: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            functions: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            options: BTreeMap::new(),
            transport: ConfigProcessorTransports {
                inline: ConfigProcessorTransport {
                    enabled: false,
                    options: BTreeMap::new(),
                },
                ipc: ConfigProcessorTransport {
                    enabled: true,
                    options: BTreeMap::new(),
                },
                http: ConfigProcessorTransport {
                    enabled: false,
                    options: BTreeMap::new(),
                },
            },
        }
    }

    fn test_make_dispatch() -> Box<dyn crate::runtime::dispatch::ProcessorDispatch> {
        panic!("test dispatch should not be constructed")
    }

    fn test_make_pool(
        _: &crate::config::ConfigProcessors,
    ) -> Result<
        Arc<crate::runtime::transports::ipc::pool::ProcessorPool>,
        crate::runtime::error::ProcessorError,
    > {
        panic!("test pool should not be constructed")
    }

    #[test]
    fn current_os_is_in_registration_filter_set() {
        #[cfg(target_os = "linux")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Linux];
        #[cfg(target_os = "macos")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Macos];
        #[cfg(target_os = "windows")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Windows];

        let registration = ProcessorRegistration {
            name: "test",
            requires: ">=0.0.0",
            operating_systems: &SUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64],
            transports: &[ProcessorTransport::Ipc],
            make_pool: test_make_pool,
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            enabled_for_target: |_, _| false,
            execute_graph_value: None,
            execute_value: None,
            instruction_json: None,
            block_json: None,
            function_json: None,
            process_instruction: None,
            process_block: None,
            process_function: None,
        };

        assert!(registration.supported_on_current_os());
    }

    #[test]
    fn unsupported_registration_is_filtered_out() {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        static UNSUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Windows];
        #[cfg(target_os = "windows")]
        static UNSUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Linux];

        let registration = ProcessorRegistration {
            name: "test",
            requires: ">=0.0.0",
            operating_systems: &UNSUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64],
            transports: &[ProcessorTransport::Ipc],
            make_pool: test_make_pool,
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            enabled_for_target: |_, _| false,
            execute_graph_value: None,
            execute_value: None,
            instruction_json: None,
            block_json: None,
            function_json: None,
            process_instruction: None,
            process_block: None,
            process_function: None,
        };

        assert!(!registration.supported_on_current_os());
    }

    #[test]
    fn registration_supports_declared_transports() {
        #[cfg(target_os = "linux")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Linux];
        #[cfg(target_os = "macos")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Macos];
        #[cfg(target_os = "windows")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Windows];

        let registration = ProcessorRegistration {
            name: "test",
            requires: ">=0.0.0",
            operating_systems: &SUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64],
            transports: &[
                ProcessorTransport::Inline,
                ProcessorTransport::Ipc,
                ProcessorTransport::Http,
            ],
            make_pool: test_make_pool,
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            enabled_for_target: |_, _| false,
            execute_graph_value: None,
            execute_value: None,
            instruction_json: None,
            block_json: None,
            function_json: None,
            process_instruction: None,
            process_block: None,
            process_function: None,
        };

        assert!(registration.supports_transport("inline"));
        assert!(registration.supports_transport("ipc"));
        assert!(registration.supports_transport("http"));
        assert!(!registration.supports_transport("bogus"));
    }

    #[test]
    fn registration_supports_declared_architectures() {
        #[cfg(target_os = "linux")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Linux];
        #[cfg(target_os = "macos")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Macos];
        #[cfg(target_os = "windows")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Windows];

        let registration = ProcessorRegistration {
            name: "test",
            requires: ">=0.0.0",
            operating_systems: &SUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64, ProcessorArchitecture::I386],
            transports: &[ProcessorTransport::Ipc],
            make_pool: test_make_pool,
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            enabled_for_target: |_, _| false,
            execute_graph_value: None,
            execute_value: None,
            instruction_json: None,
            block_json: None,
            function_json: None,
            process_instruction: None,
            process_block: None,
            process_function: None,
        };

        assert!(registration.supports_architecture(ProcessorArchitecture::AMD64));
        assert!(registration.supports_architecture(ProcessorArchitecture::I386));
        assert!(!registration.supports_architecture(ProcessorArchitecture::CIL));
    }
}
