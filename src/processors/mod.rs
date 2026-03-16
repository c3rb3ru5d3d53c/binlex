#[cfg(not(target_os = "windows"))]
pub mod vex;

use crate::Config;
use crate::controlflow::{Block, Function, Instruction};
use crate::global::config::ConfigProcessor;
use crate::processing::processor::{Processor, ProcessorDispatch};
use clap::ValueEnum;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::collections::BTreeMap;

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
    Vex,
}

impl ProcessorSelection {
    pub fn to_vec() -> Vec<String> {
        vec![ProcessorSelection::Vex.to_possible_value().unwrap().get_name().to_string()]
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

pub type ProcessorOutputs = Vec<(&'static str, Value)>;

pub struct ProcessorRegistration {
    pub name: &'static str,
    pub os: &'static [ProcessorOs],
    pub make_dispatch: fn() -> Box<dyn ProcessorDispatch>,
    pub config_default: fn() -> ConfigProcessor,
    pub enabled_for_target: fn(&Config, ProcessorTarget) -> bool,
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
        self.registration.process_block.and_then(|process| process(block))
    }

    pub fn process_instruction(&self, instruction: &Instruction) -> Option<Value> {
        self.registration
            .process_instruction
            .and_then(|process| process(instruction))
    }

    pub fn process_function(&self, function: &Function<'_>) -> Option<Value> {
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
    ($processor:path {
        os: [$($supported_os:ident),+ $(,)?],
        enabled: $processor_enabled:expr,
        instructions: { enabled: $instructions_enabled:expr },
        blocks: { enabled: $blocks_enabled:expr },
        functions: { enabled: $functions_enabled:expr }
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
                options: std::collections::BTreeMap::new(),
                server: std::collections::BTreeMap::new(),
            }
        }

        pub(crate) fn registration() -> $crate::processors::ProcessorRegistration {
            $crate::processors::ProcessorRegistration {
                name: <$processor as $crate::processing::processor::Processor>::NAME,
                os: &[$($crate::processor!(@supported_os $supported_os)),+],
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
                process_instruction: Some(
                    <$processor>::process_instruction
                        as fn(&$crate::controlflow::Instruction) -> Option<serde_json::Value>,
                ),
                process_block: Some(
                    <$processor>::process_block
                        as fn(&$crate::controlflow::Block<'_>) -> Option<serde_json::Value>,
                ),
                process_function: Some(
                    <$processor>::process_function
                        as fn(&$crate::controlflow::Function<'_>) -> Option<serde_json::Value>,
                ),
            }
        }
    };
}

#[cfg(not(target_os = "windows"))]
static PROCESSOR_REGISTRATIONS: Lazy<Vec<ProcessorRegistration>> =
    Lazy::new(|| vec![vex::registration()]);

#[cfg(target_os = "windows")]
static PROCESSOR_REGISTRATIONS: Lazy<Vec<ProcessorRegistration>> = Lazy::new(Vec::new);

fn processor_registrations() -> &'static [ProcessorRegistration] {
    PROCESSOR_REGISTRATIONS.as_slice()
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

pub fn dispatch_by_name(name: &str) -> Option<RegisteredProcessorDispatch> {
    processor_registration_by_name(name).map(RegisteredProcessor::into_dispatch)
}

#[cfg(test)]
mod tests {
    use super::{ProcessorOs, ProcessorRegistration};
    use crate::global::config::{ConfigProcessor, ConfigProcessorTarget};
    use std::collections::BTreeMap;

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
            server: BTreeMap::new(),
        }
    }

    fn test_make_dispatch() -> Box<dyn crate::processing::processor::ProcessorDispatch> {
        panic!("test dispatch should not be constructed")
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
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            enabled_for_target: |_, _| false,
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
            make_dispatch: test_make_dispatch,
            config_default: test_config_default,
            enabled_for_target: |_, _| false,
            process_instruction: None,
            process_block: None,
            process_function: None,
        };

        assert!(!registration.supported_on_current_os());
    }
}
