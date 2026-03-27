use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::Write;

use binlex::config::{
    ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
};
use binlex::core::{Architecture, OperatingSystem, Transport};
use binlex::processor::{
    GraphProcessor, OnGraphOptions, ProcessorContext, external_processor_registration,
};
use binlex::runtime::{Processor, ProcessorError};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Clone, Serialize, Deserialize)]
pub struct Request {
    pub path: String,
    pub instruction_count: usize,
    pub block_count: usize,
    pub functions: Vec<Value>,
}

#[derive(Default)]
pub struct CompleteTestProcessor;

impl Processor for CompleteTestProcessor {
    const NAME: &'static str = "complete-test";
    type Request = Request;
    type Response = ();

    fn execute(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        let function_count = request.functions.len();
        let vex_functions = request
            .functions
            .iter()
            .filter(|function| {
                function
                    .get("processors")
                    .and_then(|processors| processors.get("vex"))
                    .is_some()
            })
            .count();
        let summary = json!({
            "stage": "complete",
            "instruction_count": request.instruction_count,
            "block_count": request.block_count,
            "function_count": function_count,
            "vex_functions": vex_functions,
        });
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&request.path)
            .map_err(|error| ProcessorError::Io(std::io::Error::other(error.to_string())))?;
        writeln!(file, "{}", summary)
            .map_err(|error| ProcessorError::Io(std::io::Error::other(error.to_string())))?;
        Ok(())
    }
}

impl GraphProcessor for CompleteTestProcessor {
    fn on_graph_options() -> OnGraphOptions {
        OnGraphOptions {
            instructions: true,
            blocks: true,
            functions: true,
        }
    }

    fn request_message<C: ProcessorContext>(
        context: &C,
        data: Value,
    ) -> Result<Self::Request, ProcessorError> {
        if data.get("stage").and_then(Value::as_str) != Some("complete") {
            return Err(ProcessorError::Protocol(
                "complete-test processor only supports completion-stage requests".to_string(),
            ));
        }
        let path = context
            .processor(Self::NAME)
            .and_then(|processor| processor.option_string("path"))
            .ok_or_else(|| {
                ProcessorError::Protocol(
                    "complete-test processor requires path option".to_string(),
                )
            })?;
        let instruction_count = data
            .get("instructions")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let block_count = data
            .get("blocks")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let functions = data
            .get("functions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(Request {
            path: path.to_string(),
            instruction_count,
            block_count,
            functions,
        })
    }
}

pub fn registration() -> binlex::processor::ProcessorRegistration {
    external_processor_registration(
        CompleteTestProcessor::NAME,
        ">=2.0.0 <2.1.0",
        &[OperatingSystem::LINUX, OperatingSystem::MACOS],
        &[Architecture::AMD64, Architecture::I386],
        &[Transport::IPC, Transport::HTTP],
        CompleteTestProcessor::on_graph_options(),
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
            options: BTreeMap::new(),
            transport: ConfigProcessorTransports {
                ipc: ConfigProcessorTransport {
                    enabled: true,
                    options: BTreeMap::new(),
                },
                http: ConfigProcessorTransport {
                    enabled: false,
                    options: BTreeMap::from([
                        ("url".to_string(), "http://127.0.0.1:5000".into()),
                        ("verify".to_string(), false.into()),
                    ]),
                },
            },
        },
    )
}
