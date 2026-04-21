use binlex::config::{
    ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
};
use binlex::controlflow::Graph;
use binlex::core::{Architecture, OperatingSystem, Transport};
use binlex::processor::{
    GraphProcessor, GraphProcessorFanout, OnGraphOptions, external_processor_registration,
};
use binlex::runtime::{Processor, ProcessorError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleRequest {
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub r#type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExampleResponse {
    pub ok: bool,
    pub message: String,
}

#[derive(Default)]
pub struct ExampleProcessor;

impl Processor for ExampleProcessor {
    const NAME: &'static str = "example";
    type Request = ExampleRequest;
    type Response = ExampleResponse;

    fn execute(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        Ok(ExampleResponse {
            ok: true,
            message: request
                .message
                .unwrap_or_else(|| "example processor".to_string()),
        })
    }
}

impl GraphProcessor for ExampleProcessor {
    fn on_graph_options() -> OnGraphOptions {
        OnGraphOptions {
            instructions: false,
            blocks: false,
            functions: false,
        }
    }

    fn on_graph(_: &Graph) -> Option<GraphProcessorFanout> {
        Some(GraphProcessorFanout::default())
    }
}

pub fn registration() -> binlex::processor::ProcessorRegistration {
    external_processor_registration(
        ExampleProcessor::NAME,
        ">=2.0.0 <2.1.0",
        &[
            OperatingSystem::WINDOWS,
            OperatingSystem::LINUX,
            OperatingSystem::MACOS,
        ],
        &[
            Architecture::AMD64,
            Architecture::I386,
            Architecture::ARM64,
            Architecture::CIL,
        ],
        &[Transport::IPC, Transport::HTTP],
        ExampleProcessor::on_graph_options(),
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
            graph: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            complete: ConfigProcessorTarget {
                enabled: false,
                options: BTreeMap::new(),
            },
            options: BTreeMap::from([("message".to_string(), "example".into())]),
            transport: ConfigProcessorTransports {
                ipc: ConfigProcessorTransport {
                    enabled: true,
                    options: BTreeMap::new(),
                },
                http: ConfigProcessorTransport {
                    enabled: false,
                    options: BTreeMap::from([("url".to_string(), "http://127.0.0.1:5000".into())]),
                },
            },
        },
    )
}
