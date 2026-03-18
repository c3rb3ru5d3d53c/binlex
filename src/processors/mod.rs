pub mod embeddings;
#[cfg(not(target_os = "windows"))]
pub mod vex;

use crate::Config;
use crate::controlflow::{Block, Function, Instruction};
use crate::global::config::{ConfigProcessor, ConfigProcessors};
use crate::io::stderr::Stderr;
use crate::processing::processor::{Processor, ProcessorDispatch};
use crate::server::dto::{
    ErrorResponse, LZ4_CONTENT_ENCODING, OCTET_STREAM_CONTENT_TYPE, ProcessorHttpRequest,
};
use crate::server::error::ServerError;
use crate::server::state::AppState;
use clap::ValueEnum;
use once_cell::sync::Lazy;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, CONTENT_ENCODING, CONTENT_TYPE};
use serde_json::Value;
use std::collections::BTreeMap;
use std::process;
use std::sync::Arc;

pub use crate::global::Architecture as ProcessorArchitecture;
pub use crate::global::OperatingSystem as ProcessorOs;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, ValueEnum)]
pub enum ProcessorSelection {
    Embeddings,
    Vex,
}

impl ProcessorSelection {
    pub fn to_vec() -> Vec<String> {
        vec![
            ProcessorSelection::Embeddings
                .to_possible_value()
                .unwrap()
                .get_name()
                .to_string(),
            ProcessorSelection::Vex
                .to_possible_value()
                .unwrap()
                .get_name()
                .to_string(),
        ]
    }

    pub fn to_list() -> String {
        ProcessorSelection::to_vec().join(", ")
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProcessorTarget {
    Instruction,
    Block,
    Function,
}

pub use crate::global::Transport as ProcessorMode;

pub type ProcessorOutputs = Vec<(&'static str, Value)>;

pub trait GraphProcessor {
    fn instruction_json(instruction: &Instruction) -> Option<Value> {
        serde_json::to_value(instruction.process()).ok()
    }

    fn block_json(block: &Block<'_>) -> Option<Value> {
        serde_json::to_value(block.process_base()).ok()
    }

    fn function_json(function: &Function<'_>) -> Option<Value> {
        serde_json::to_value(function.process_base()).ok()
    }

    fn instruction(_: &Instruction) -> Option<Value> {
        None
    }

    fn block(_: &Block<'_>) -> Option<Value> {
        None
    }

    fn function(_: &Function<'_>) -> Option<Value> {
        None
    }
}

pub trait ProcessorContext {
    fn processors(&self) -> &ConfigProcessors;

    fn processor(&self, name: &str) -> Option<&ConfigProcessor> {
        self.processors().processor(name)
    }
}

impl ProcessorContext for Config {
    fn processors(&self) -> &ConfigProcessors {
        &self.processors
    }
}

impl ProcessorContext for crate::server::config::ServerConfig {
    fn processors(&self) -> &ConfigProcessors {
        &self.processors
    }
}

pub trait JsonProcessor: Processor {
    fn request<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Self::Request, crate::processing::error::ProcessorError>;

    fn response(
        response: Self::Response,
    ) -> Result<Value, crate::processing::error::ProcessorError>;

    fn execute_ipc_value<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Value, crate::processing::error::ProcessorError>
    where
        Self: Sized,
    {
        if let Some(registration) = crate::processors::processor_registration_by_type::<Self>() {
            ensure_payload_architecture_supported(registration.registration, &data)?;
        }
        let request = <Self as JsonProcessor>::request(context, data)?;
        let pool =
            crate::processing::pool::ProcessorPool::for_processor::<Self>(context.processors())?;
        let response = pool.execute::<Self>(&request)?;
        Self::response(response)
    }

    fn execute_local_value<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Value, crate::processing::error::ProcessorError>
    where
        Self: Sized,
    {
        if let Some(registration) = crate::processors::processor_registration_by_type::<Self>() {
            ensure_payload_architecture_supported(registration.registration, &data)?;
        }
        let request = <Self as JsonProcessor>::request(context, data)?;
        let response = Self::execute(request)?;
        Self::response(response)
    }

    fn execute_server_value(state: &AppState, data: Value) -> Result<Value, ServerError>
    where
        Self: Sized,
    {
        let processor = state
            .config
            .processors
            .processor(Self::NAME)
            .ok_or_else(|| {
                ServerError::Processor(format!("{} processor is not configured", Self::NAME))
            })?;
        let registration = processor_registration_by_name(Self::NAME).ok_or_else(|| {
            ServerError::Processor(format!("{} processor is not registered", Self::NAME))
        })?;
        ensure_payload_architecture_supported_server(registration.registration, &data)?;
        match configured_server_execution_mode(processor, registration.registration.modes)? {
            ProcessorMode::Inline => {
                <Self as JsonProcessor>::execute_local_value(&state.config, data)
                    .map_err(ServerError::from)
            }
            ProcessorMode::Ipc => {
                let response = if let Some(pool) = state.processor_pool(Self::NAME) {
                    let request = <Self as JsonProcessor>::request(&state.config, data)
                        .map_err(ServerError::from)?;
                    let response = pool.execute::<Self>(&request).map_err(ServerError::from)?;
                    <Self as JsonProcessor>::response(response)
                } else {
                    <Self as JsonProcessor>::execute_ipc_value(&state.config, data)
                };
                response.map_err(ServerError::from)
            }
            ProcessorMode::Http => Err(ServerError::Processor(format!(
                "processor {} server mode cannot be http",
                Self::NAME
            ))),
        }
    }
}

pub struct ProcessorRegistration {
    pub name: &'static str,
    pub operating_systems: &'static [ProcessorOs],
    pub architectures: &'static [ProcessorArchitecture],
    pub modes: &'static [ProcessorMode],
    pub make_pool: fn(
        &crate::ConfigProcessors,
    ) -> Result<
        Arc<crate::processing::pool::ProcessorPool>,
        crate::processing::error::ProcessorError,
    >,
    pub make_dispatch: fn() -> Box<dyn ProcessorDispatch>,
    pub config_default: fn() -> ConfigProcessor,
    pub enabled_for_target: fn(&Config, ProcessorTarget) -> bool,
    pub execute_graph_value:
        Option<fn(&Config, Value) -> Result<Value, crate::processing::error::ProcessorError>>,
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

    pub fn configured_mode(&self, config: &Config) -> ProcessorMode {
        configured_graph_mode(self.registration, config).unwrap_or(ProcessorMode::Inline)
    }

    pub fn process_block(&self, block: &Block<'_>) -> Option<Value> {
        if !self.registration.supports_architecture(block.architecture()) {
            return None;
        }
        if let Some(data) = self
            .registration
            .block_json
            .and_then(|serialize| serialize(block))
        {
            match execute_graph_mode(self.registration, data, &block.cfg.config) {
                Ok(Some(data)) => return Some(data),
                Ok(None) => {}
                Err(error) => {
                    if should_fail_transport_mode(&error) {
                        fail_transport_mode(&block.cfg.config, self.name(), &error);
                    }
                    report_transport_mode_error(&block.cfg.config, self.name(), &error);
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
            match execute_graph_mode(self.registration, data, &instruction.config) {
                Ok(Some(data)) => return Some(data),
                Ok(None) => {}
                Err(error) => {
                    if should_fail_transport_mode(&error) {
                        fail_transport_mode(&instruction.config, self.name(), &error);
                    }
                    report_transport_mode_error(&instruction.config, self.name(), &error);
                    return None;
                }
            }
        }
        self.registration
            .process_instruction
            .and_then(|process| process(instruction))
    }

    pub fn process_function(&self, function: &Function<'_>) -> Option<Value> {
        if !self.registration.supports_architecture(function.architecture()) {
            return None;
        }
        if let Some(data) = self
            .registration
            .function_json
            .and_then(|serialize| serialize(function))
        {
            match execute_graph_mode(self.registration, data, &function.cfg.config) {
                Ok(Some(data)) => return Some(data),
                Ok(None) => {}
                Err(error) => {
                    if should_fail_transport_mode(&error) {
                        fail_transport_mode(&function.cfg.config, self.name(), &error);
                    }
                    report_transport_mode_error(&function.cfg.config, self.name(), &error);
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

    pub fn supports_mode(&self, mode: &str) -> bool {
        self.modes
            .iter()
            .any(|supported| supported.as_str() == mode)
    }
}

pub struct RegisteredProcessorDispatch {
    pub id: u16,
    pub dispatch: Box<dyn ProcessorDispatch>,
}

pub fn default_transport_mode(
    supported: &[ProcessorMode],
    inline_enabled: bool,
    ipc_enabled: bool,
    http_enabled: bool,
) -> ProcessorMode {
    if inline_enabled && supported.contains(&ProcessorMode::Inline) {
        return ProcessorMode::Inline;
    }
    if ipc_enabled && supported.contains(&ProcessorMode::Ipc) {
        return ProcessorMode::Ipc;
    }
    if http_enabled && supported.contains(&ProcessorMode::Http) {
        return ProcessorMode::Http;
    }
    supported.first().copied().unwrap_or(ProcessorMode::Inline)
}

fn configured_transport_mode(
    processor: &ConfigProcessor,
    supported: &[ProcessorMode],
) -> Result<ProcessorMode, crate::processing::error::ProcessorError> {
    let mode = default_transport_mode(
        supported,
        processor.inline.enabled,
        processor.ipc.enabled,
        processor.http.enabled,
    );
    if !supported.contains(&mode) {
        return Err(crate::processing::error::ProcessorError::Protocol(
            "processor has no supported enabled transport".to_string(),
        ));
    }
    if !processor.transport(mode).enabled {
        return Err(crate::processing::error::ProcessorError::Protocol(
            "processor has no enabled transport".to_string(),
        ));
    }
    Ok(mode)
}

fn configured_server_transport_mode(
    processor: &ConfigProcessor,
    supported: &[ProcessorMode],
) -> Result<ProcessorMode, ServerError> {
    if processor.inline.enabled && supported.contains(&ProcessorMode::Inline) {
        return Ok(ProcessorMode::Inline);
    }
    if processor.ipc.enabled && supported.contains(&ProcessorMode::Ipc) {
        return Ok(ProcessorMode::Ipc);
    }
    Err(ServerError::Processor(
        "processor has no enabled server execution transport".to_string(),
    ))
}

#[macro_export]
macro_rules! processor {
    (@value { $($key:ident : $value:tt),* $(,)? }) => {
        $crate::global::config::ConfigProcessorValue::Table(std::collections::BTreeMap::from([
            $(
                (
                    stringify!($key).to_string(),
                    $crate::processor!(@value $value),
                )
            ),*
        ]))
    };
    (@value [ $($value:tt),* $(,)? ]) => {
        $crate::global::config::ConfigProcessorValue::Array(vec![
            $(
                $crate::processor!(@value $value)
            ),*
        ])
    };
    (@value $value:expr) => {
        $crate::global::config::ConfigProcessorValue::from($value)
    };
    ($processor:path {
        operating_systems: [$($supported_os:expr),+ $(,)?],
        architectures: [$($supported_architecture:expr),+ $(,)?],
        enabled: $processor_enabled:expr,
        transports: [$($processor_mode:expr),+ $(,)?],
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
            operating_systems: [$($supported_os),+],
            architectures: [$($supported_architecture),+],
            enabled: $processor_enabled,
            transports: [$($processor_mode),+],
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
        operating_systems: [$($supported_os:expr),+ $(,)?],
        architectures: [$($supported_architecture:expr),+ $(,)?],
        enabled: $processor_enabled:expr,
        transports: [$($processor_mode:expr),+ $(,)?],
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
        pub(crate) fn config_default() -> $crate::global::config::ConfigProcessor {
            $crate::global::config::ConfigProcessor {
                enabled: $processor_enabled,
                instructions: $crate::global::config::ConfigProcessorTarget {
                    enabled: $instructions_enabled,
                    options: std::collections::BTreeMap::new(),
                },
                blocks: $crate::global::config::ConfigProcessorTarget {
                    enabled: $blocks_enabled,
                    options: std::collections::BTreeMap::new(),
                },
                functions: $crate::global::config::ConfigProcessorTarget {
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
                inline: $crate::global::config::ConfigProcessorTransport {
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
                ipc: $crate::global::config::ConfigProcessorTransport {
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
                http: $crate::global::config::ConfigProcessorTransport {
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
            }
        }

        pub(crate) fn registration() -> $crate::processors::ProcessorRegistration {
            $crate::processors::ProcessorRegistration {
                name: <$processor as $crate::processing::processor::Processor>::NAME,
                operating_systems: &[$($supported_os),+],
                architectures: &[$($supported_architecture),+],
                modes: &[$($processor_mode),+],
                make_pool: |config| $crate::processing::pool::ProcessorPool::for_processor::<$processor>(config),
                make_dispatch: || Box::new($processor),
                config_default,
                enabled_for_target: |config: &$crate::Config,
                                     target: $crate::processors::ProcessorTarget| {
                    config.processors.enabled
                        && config
                            .processors
                            .processor(<$processor as $crate::processing::processor::Processor>::NAME)
                            .is_some_and(|processor| {
                                processor.enabled
                                    && match target {
                                        $crate::processors::ProcessorTarget::Instruction => {
                                            processor.instructions.enabled
                                        }
                                        $crate::processors::ProcessorTarget::Block => {
                                            processor.blocks.enabled
                                        }
                                        $crate::processors::ProcessorTarget::Function => {
                                            processor.functions.enabled
                                        }
                                    }
                            })
                },
                execute_graph_value: Some(<$processor as $crate::processors::JsonProcessor>::execute_ipc_value as fn(&$crate::Config, serde_json::Value) -> Result<serde_json::Value, $crate::processing::error::ProcessorError>),
                execute_value: Some(<$processor as $crate::processors::JsonProcessor>::execute_server_value as fn(&$crate::server::state::AppState, serde_json::Value) -> Result<serde_json::Value, $crate::server::error::ServerError>),
                instruction_json: Some(
                    <$processor as $crate::processors::GraphProcessor>::instruction_json
                        as fn(&$crate::controlflow::Instruction) -> Option<serde_json::Value>,
                ),
                block_json: Some(
                    <$processor as $crate::processors::GraphProcessor>::block_json
                        as fn(&$crate::controlflow::Block<'_>) -> Option<serde_json::Value>,
                ),
                function_json: Some(
                    <$processor as $crate::processors::GraphProcessor>::function_json
                        as fn(&$crate::controlflow::Function<'_>) -> Option<serde_json::Value>,
                ),
                process_instruction: Some(
                    <$processor as $crate::processors::GraphProcessor>::instruction
                        as fn(&$crate::controlflow::Instruction) -> Option<serde_json::Value>,
                ),
                process_block: Some(
                    <$processor as $crate::processors::GraphProcessor>::block
                        as fn(&$crate::controlflow::Block<'_>) -> Option<serde_json::Value>,
                ),
                process_function: Some(
                    <$processor as $crate::processors::GraphProcessor>::function
                        as fn(&$crate::controlflow::Function<'_>) -> Option<serde_json::Value>,
                ),
            }
        }
    };
    ($processor:path {
        operating_systems: [$($supported_os:expr),+ $(,)?],
        architectures: [$($supported_architecture:expr),+ $(,)?],
        enabled: $processor_enabled:expr,
        transports: [$($processor_mode:expr),+ $(,)?],
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
            operating_systems: [$($supported_os),+],
            architectures: [$($supported_architecture),+],
            enabled: $processor_enabled,
            transports: [$($processor_mode),+],
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

#[cfg(not(target_os = "windows"))]
static PROCESSOR_REGISTRATIONS: Lazy<Vec<ProcessorRegistration>> =
    Lazy::new(|| vec![vex::registration(), embeddings::registration()]);

#[cfg(target_os = "windows")]
static PROCESSOR_REGISTRATIONS: Lazy<Vec<ProcessorRegistration>> = Lazy::new(Vec::new);

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

pub fn apply_output(outputs: &mut BTreeMap<String, Value>, processor_name: &str, output: &Value) {
    outputs.insert(processor_name.to_string(), output.clone());
}

fn report_transport_mode_error(
    config: &Config,
    processor_name: &str,
    error: &crate::processing::error::ProcessorError,
) {
    if config.general.debug {
        Stderr::print_debug(
            config,
            format!("processor {} transport error: {}", processor_name, error),
        );
    }
}

fn fail_transport_mode(
    config: &Config,
    processor_name: &str,
    error: &crate::processing::error::ProcessorError,
) -> ! {
    report_transport_mode_error(config, processor_name, error);
    eprintln!("processor {} transport error: {}", processor_name, error);
    process::exit(1);
}

fn should_fail_transport_mode(error: &crate::processing::error::ProcessorError) -> bool {
    matches!(
        error,
        crate::processing::error::ProcessorError::Io(_)
            | crate::processing::error::ProcessorError::Spawn(_)
            | crate::processing::error::ProcessorError::BinaryNotFound(_)
            | crate::processing::error::ProcessorError::Timeout(_)
            | crate::processing::error::ProcessorError::Protocol(_)
    )
}

fn configured_graph_mode(
    registration: &ProcessorRegistration,
    config: &Config,
) -> Result<ProcessorMode, crate::processing::error::ProcessorError> {
    let Some(processor) = config.processors.processor(registration.name) else {
        return Ok(ProcessorMode::Inline);
    };
    configured_transport_mode(processor, registration.modes).map_err(|error| {
        crate::processing::error::ProcessorError::Protocol(format!(
            "processor {} transport selection failed: {}",
            registration.name, error
        ))
    })
}

pub(crate) fn configured_server_execution_mode(
    processor: &ConfigProcessor,
    supported: &[ProcessorMode],
) -> Result<ProcessorMode, ServerError> {
    configured_server_transport_mode(processor, supported)
}

fn processor_http_url(
    processor_name: &str,
    config: &ConfigProcessor,
) -> Result<String, crate::processing::error::ProcessorError> {
    let base_url = config
        .transport_string(ProcessorMode::Http, "url")
        .ok_or_else(|| {
            crate::processing::error::ProcessorError::Protocol(format!(
                "processor {} http mode requires url option",
                processor_name
            ))
        })?;
    Ok(format!(
        "{}/processors/{}",
        base_url.trim_end_matches('/'),
        processor_name
    ))
}

fn processor_http_verify(config: &ConfigProcessor) -> bool {
    config
        .transport_bool(ProcessorMode::Http, "verify")
        .unwrap_or(true)
}

fn encode_http_request(
    request: &ProcessorHttpRequest,
    compression_enabled: bool,
) -> Result<(Vec<u8>, &'static str), crate::processing::error::ProcessorError> {
    let json = serde_json::to_vec(request).map_err(|error| {
        crate::processing::error::ProcessorError::Serialization(error.to_string())
    })?;
    if !compression_enabled {
        return Ok((json, "application/json"));
    }

    let compressed = lz4::block::compress(&json, None, false).map_err(|error| {
        crate::processing::error::ProcessorError::Compression(error.to_string())
    })?;
    let mut payload = Vec::with_capacity(4 + compressed.len());
    payload.extend_from_slice(&(json.len() as u32).to_le_bytes());
    payload.extend_from_slice(&compressed);
    Ok((payload, OCTET_STREAM_CONTENT_TYPE))
}

fn decode_http_response(
    response: reqwest::blocking::Response,
) -> Result<Value, crate::processing::error::ProcessorError> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().map_err(|error| {
        crate::processing::error::ProcessorError::Io(std::io::Error::other(error.to_string()))
    })?;

    if !status.is_success() {
        if let Ok(error) = serde_json::from_slice::<ErrorResponse>(&body) {
            return Err(crate::processing::error::ProcessorError::RemoteFailure(
                error.error,
            ));
        }
        return Err(crate::processing::error::ProcessorError::RemoteFailure(
            String::from_utf8_lossy(&body).into_owned(),
        ));
    }

    let decoded = if headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case(LZ4_CONTENT_ENCODING))
    {
        if body.len() < 4 {
            return Err(crate::processing::error::ProcessorError::Compression(
                "compressed response missing size prefix".to_string(),
            ));
        }
        let uncompressed_len = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as i32;
        lz4::block::decompress(&body[4..], Some(uncompressed_len)).map_err(|error| {
            crate::processing::error::ProcessorError::Compression(error.to_string())
        })?
    } else {
        body.to_vec()
    };

    serde_json::from_slice(&decoded)
        .map_err(|error| crate::processing::error::ProcessorError::Serialization(error.to_string()))
}

fn execute_http_mode(
    processor_name: &str,
    data: Value,
    config: &Config,
    processor: &ConfigProcessor,
) -> Result<Value, crate::processing::error::ProcessorError> {
    let url = processor_http_url(processor_name, processor)?;
    let verify = processor_http_verify(processor);
    let client = Client::builder()
        .danger_accept_invalid_certs(!verify)
        .build()
        .map_err(|error| crate::processing::error::ProcessorError::Protocol(error.to_string()))?;
    let request = ProcessorHttpRequest { data };
    let (body, content_type) = encode_http_request(&request, config.processors.compression)?;

    let mut builder = client
        .post(url)
        .header(CONTENT_TYPE, content_type)
        .header(ACCEPT, "application/json");

    if config.processors.compression {
        builder = builder
            .header(CONTENT_ENCODING, LZ4_CONTENT_ENCODING)
            .header(ACCEPT, OCTET_STREAM_CONTENT_TYPE);
    }

    let response = builder.body(body).send().map_err(|error| {
        crate::processing::error::ProcessorError::Io(std::io::Error::other(error.to_string()))
    })?;

    decode_http_response(response)
}

fn execute_graph_mode(
    registration: &ProcessorRegistration,
    data: Value,
    config: &Config,
) -> Result<Option<Value>, crate::processing::error::ProcessorError> {
    ensure_payload_architecture_supported(registration, &data)?;
    match configured_graph_mode(registration, config)? {
        ProcessorMode::Inline => Ok(None),
        ProcessorMode::Ipc => {
            let execute = registration.execute_graph_value.ok_or_else(|| {
                crate::processing::error::ProcessorError::Protocol(format!(
                    "processor {} does not implement graph IPC execution",
                    registration.name
                ))
            })?;
            execute(config, data).map(Some)
        }
        ProcessorMode::Http => {
            let processor = config
                .processors
                .processor(registration.name)
                .ok_or_else(|| {
                    crate::processing::error::ProcessorError::Protocol(format!(
                        "processor {} is not configured",
                        registration.name
                    ))
                })?;
            execute_http_mode(registration.name, data, config, processor).map(Some)
        }
    }
}

pub fn http_execute(
    state: &AppState,
    processor_name: &str,
    data: Value,
) -> Result<Value, ServerError> {
    let registration = processor_registration_by_name(processor_name).ok_or_else(|| {
        ServerError::Processor(format!("unsupported HTTP processor: {}", processor_name))
    })?;
    if !registration.registration.supports_mode("http") {
        return Err(ServerError::Processor(format!(
            "processor {} does not support HTTP mode",
            processor_name
        )));
    }
    ensure_payload_architecture_supported_server(registration.registration, &data)?;
    let execute = registration.registration.execute_value.ok_or_else(|| {
        ServerError::Processor(format!(
            "processor {} does not implement value execution",
            processor_name
        ))
    })?;
    execute(state, data)
}

pub fn dispatch_by_name(name: &str) -> Option<RegisteredProcessorDispatch> {
    processor_registration_by_name(name).map(RegisteredProcessor::into_dispatch)
}

fn payload_architecture(
    data: &Value,
) -> Result<Option<ProcessorArchitecture>, crate::processing::error::ProcessorError> {
    let Some(architecture) = data.get("architecture").and_then(Value::as_str) else {
        return Ok(None);
    };
    ProcessorArchitecture::from_string(architecture)
        .map(Some)
        .map_err(|error| crate::processing::error::ProcessorError::Protocol(error.to_string()))
}

fn ensure_payload_architecture_supported(
    registration: &ProcessorRegistration,
    data: &Value,
) -> Result<(), crate::processing::error::ProcessorError> {
    let Some(architecture) = payload_architecture(data)? else {
        return Ok(());
    };
    if registration.supports_architecture(architecture) {
        return Ok(());
    }
    Err(crate::processing::error::ProcessorError::Protocol(
        format!(
            "processor {} does not support architecture {}",
            registration.name, architecture
        ),
    ))
}

fn ensure_payload_architecture_supported_server(
    registration: &ProcessorRegistration,
    data: &Value,
) -> Result<(), ServerError> {
    ensure_payload_architecture_supported(registration, data).map_err(ServerError::from)
}

#[cfg(test)]
mod tests {
    use super::{ProcessorArchitecture, ProcessorMode, ProcessorOs, ProcessorRegistration};
    use crate::global::config::{ConfigProcessor, ConfigProcessorTarget};
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
            inline: crate::global::config::ConfigProcessorTransport {
                enabled: false,
                options: BTreeMap::new(),
            },
            ipc: crate::global::config::ConfigProcessorTransport {
                enabled: true,
                options: BTreeMap::new(),
            },
            http: crate::global::config::ConfigProcessorTransport {
                enabled: false,
                options: BTreeMap::new(),
            },
        }
    }

    fn test_make_dispatch() -> Box<dyn crate::processing::processor::ProcessorDispatch> {
        panic!("test dispatch should not be constructed")
    }

    fn test_make_pool(
        _: &crate::ConfigProcessors,
    ) -> Result<Arc<crate::processing::pool::ProcessorPool>, crate::processing::error::ProcessorError>
    {
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
            operating_systems: &SUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64],
            modes: &[ProcessorMode::Ipc],
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
            operating_systems: &UNSUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64],
            modes: &[ProcessorMode::Ipc],
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
    fn registration_supports_declared_modes() {
        #[cfg(target_os = "linux")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Linux];
        #[cfg(target_os = "macos")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Macos];
        #[cfg(target_os = "windows")]
        static SUPPORTED_OS: [ProcessorOs; 1] = [ProcessorOs::Windows];

        let registration = ProcessorRegistration {
            name: "test",
            operating_systems: &SUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64],
            modes: &[
                ProcessorMode::Inline,
                ProcessorMode::Ipc,
                ProcessorMode::Http,
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

        assert!(registration.supports_mode("inline"));
        assert!(registration.supports_mode("ipc"));
        assert!(registration.supports_mode("http"));
        assert!(!registration.supports_mode("bogus"));
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
            operating_systems: &SUPPORTED_OS,
            architectures: &[ProcessorArchitecture::AMD64, ProcessorArchitecture::I386],
            modes: &[ProcessorMode::Ipc],
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
