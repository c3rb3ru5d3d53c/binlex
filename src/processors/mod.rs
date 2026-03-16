pub mod embeddings;
#[cfg(not(target_os = "windows"))]
pub mod vex;

use crate::Config;
use crate::controlflow::{Block, Function, Instruction};
use crate::global::config::ConfigProcessor;
use crate::processing::processor::{Processor, ProcessorDispatch};
use crate::server::error::ServerError;
use crate::server::state::AppState;
use clap::ValueEnum;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProcessorOs {
    Linux,
    Macos,
    Windows,
}

impl ProcessorOs {
    pub const fn current() -> Self {
        #[cfg(target_os = "linux")]
        {
            return Self::Linux;
        }

        #[cfg(target_os = "macos")]
        {
            return Self::Macos;
        }

        #[cfg(target_os = "windows")]
        {
            return Self::Windows;
        }

        #[allow(unreachable_code)]
        Self::Linux
    }
}

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

#[derive(serde::Serialize, serde::Deserialize, Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ProcessorMode {
    Ipc,
    Http,
}

impl ProcessorMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipc => "ipc",
            Self::Http => "http",
        }
    }
}

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

pub trait JsonProcessor: Processor {
    fn request(state: &AppState, data: Value) -> Result<Self::Request, ServerError>;

    fn response(response: Self::Response) -> Result<Value, ServerError>;

    fn execute_value(state: &AppState, data: Value) -> Result<Value, ServerError>
    where
        Self: Sized,
    {
        let request = <Self as JsonProcessor>::request(state, data)?;
        let pool = state.processor_pool(Self::NAME).ok_or_else(|| {
            ServerError::Processor(format!("{} processor pool is unavailable", Self::NAME))
        })?;
        let response = pool.execute::<Self>(&request)?;
        Self::response(response)
    }
}

pub struct ProcessorRegistration {
    pub name: &'static str,
    pub os: &'static [ProcessorOs],
    pub modes: &'static [ProcessorMode],
    pub make_pool: fn(
        &crate::ConfigProcessors,
    ) -> Result<
        Arc<crate::processing::pool::ProcessorPool>,
        crate::processing::error::ProcessorError,
    >,
    pub make_dispatch: fn() -> Box<dyn ProcessorDispatch>,
    pub config_default: fn() -> ConfigProcessor,
    pub config_server_default:
        fn() -> BTreeMap<String, crate::global::config::ConfigProcessorValue>,
    pub enabled_for_target: fn(&Config, ProcessorTarget) -> bool,
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

    pub fn process_block(&self, block: &Block<'_>) -> Option<Value> {
        if let Some(data) = self
            .registration
            .block_json
            .and_then(|serialize| serialize(block))
            .and_then(|data| mode(self.name(), data, &block.cfg.config))
        {
            return Some(data);
        }
        self.registration
            .process_block
            .and_then(|process| process(block))
    }

    pub fn process_instruction(&self, instruction: &Instruction) -> Option<Value> {
        if let Some(data) = self
            .registration
            .instruction_json
            .and_then(|serialize| serialize(instruction))
            .and_then(|data| mode(self.name(), data, &instruction.config))
        {
            return Some(data);
        }
        self.registration
            .process_instruction
            .and_then(|process| process(instruction))
    }

    pub fn process_function(&self, function: &Function<'_>) -> Option<Value> {
        if let Some(data) = self
            .registration
            .function_json
            .and_then(|serialize| serialize(function))
            .and_then(|data| mode(self.name(), data, &function.cfg.config))
        {
            return Some(data);
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
        self.os.contains(&ProcessorOs::current())
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

#[macro_export]
macro_rules! processor {
    (@supported_os linux) => {
        $crate::processors::ProcessorOs::Linux
    };
    (@supported_os macos) => {
        $crate::processors::ProcessorOs::Macos
    };
    (@supported_os windows) => {
        $crate::processors::ProcessorOs::Windows
    };
    (@mode ipc) => {
        $crate::processors::ProcessorMode::Ipc
    };
    (@mode http) => {
        $crate::processors::ProcessorMode::Http
    };
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
        os: [$($supported_os:ident),+ $(,)?],
        enabled: $processor_enabled:expr,
        modes: [$($processor_mode:ident),+ $(,)?],
        mode: $default_mode:ident,
        instructions: { enabled: $instructions_enabled:expr },
        blocks: { enabled: $blocks_enabled:expr },
        functions: { enabled: $functions_enabled:expr },
        options: { $($option_key:ident : $option_value:tt),* $(,)? },
        server: { $($server_key:ident : $server_value:tt),* $(,)? }
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
                    (
                        "mode".to_string(),
                        $crate::global::config::ConfigProcessorValue::String(
                            $crate::processor!(@mode $default_mode).as_str().to_string(),
                        ),
                    ),
                    $(
                        (
                            stringify!($option_key).to_string(),
                            $crate::processor!(@value $option_value),
                        )
                    ),*
                ]),
                server: std::collections::BTreeMap::new(),
            }
        }

        pub(crate) fn config_server_default() -> std::collections::BTreeMap<String, $crate::global::config::ConfigProcessorValue> {
            std::collections::BTreeMap::from([
                $(
                    (
                        stringify!($server_key).to_string(),
                        $crate::processor!(@value $server_value),
                    )
                ),*
            ])
        }

        pub(crate) fn registration() -> $crate::processors::ProcessorRegistration {
            $crate::processors::ProcessorRegistration {
                name: <$processor as $crate::processing::processor::Processor>::NAME,
                os: &[$($crate::processor!(@supported_os $supported_os)),+],
                modes: &[$($crate::processor!(@mode $processor_mode)),+],
                make_pool: |config| $crate::processing::pool::ProcessorPool::for_processor::<$processor>(config),
                make_dispatch: || Box::new($processor),
                config_default,
                config_server_default,
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
                execute_value: Some(<$processor as $crate::processors::JsonProcessor>::execute_value as fn(&$crate::server::state::AppState, serde_json::Value) -> Result<serde_json::Value, $crate::server::error::ServerError>),
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

pub fn apply_server_defaults(config: &mut crate::ConfigProcessors) {
    for registration in processor_registrations()
        .iter()
        .filter(|registration| registration.supported_on_current_os())
    {
        if let Some(processor) = config.ensure_processor(registration.name) {
            for (key, value) in (registration.config_server_default)() {
                processor.server.entry(key).or_insert(value);
            }
        }
    }
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

pub fn mode(processor_name: &str, data: Value, config: &Config) -> Option<Value> {
    let registration = processor_registration_by_name(processor_name)?;
    if !registration.registration.supports_mode("http") {
        return None;
    }

    let processor = config.processors.processor(processor_name)?;
    if processor.option_string("mode")? != "http" {
        return None;
    }
    let _ = data;
    let _ = config;
    None
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

#[cfg(test)]
mod tests {
    use super::{ProcessorMode, ProcessorOs, ProcessorRegistration};
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
            options: BTreeMap::from([(
                "mode".to_string(),
                crate::global::config::ConfigProcessorValue::String("ipc".to_string()),
            )]),
            server: BTreeMap::new(),
        }
    }

    fn test_make_dispatch() -> Box<dyn crate::processing::processor::ProcessorDispatch> {
        panic!("test dispatch should not be constructed")
    }

    fn test_config_server_default() -> BTreeMap<String, crate::global::config::ConfigProcessorValue>
    {
        BTreeMap::new()
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
            os: &SUPPORTED_OS,
            modes: &[ProcessorMode::Ipc],
            make_pool: test_make_pool,
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            config_server_default: test_config_server_default,
            enabled_for_target: |_, _| false,
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
            os: &UNSUPPORTED_OS,
            modes: &[ProcessorMode::Ipc],
            make_pool: test_make_pool,
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            config_server_default: test_config_server_default,
            enabled_for_target: |_, _| false,
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
            os: &SUPPORTED_OS,
            modes: &[ProcessorMode::Ipc, ProcessorMode::Http],
            make_pool: test_make_pool,
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            config_server_default: test_config_server_default,
            enabled_for_target: |_, _| false,
            execute_value: None,
            instruction_json: None,
            block_json: None,
            function_json: None,
            process_instruction: None,
            process_block: None,
            process_function: None,
        };

        assert!(registration.supports_mode("ipc"));
        assert!(registration.supports_mode("http"));
        assert!(!registration.supports_mode("bogus"));
    }
}
