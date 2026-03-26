use std::io::{Error, ErrorKind};

use binlex::config::{
    ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
};
use binlex::controlflow::{Block, Function, Graph, Instruction};
use binlex::core::Architecture;
use binlex::core::{OperatingSystem, Transport};
use binlex::processor::{GraphProcessor, GraphProcessorFanout, external_processor_registration};
use binlex::runtime::{Processor, ProcessorError};
use libvex::{Arch, TranslateArgs, VexEndness};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

const BUFFER_PADDING: usize = 64;

#[derive(Serialize, Deserialize, Clone)]
pub struct Request {
    pub architecture: Architecture,
    pub address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Response {
    pub ir: String,
}

#[derive(Default)]
pub struct VexProcessor;

impl Processor for VexProcessor {
    const NAME: &'static str = "vex";
    type Request = Request;
    type Response = Response;

    fn execute(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        if !matches!(
            request.architecture,
            binlex::Architecture::AMD64 | binlex::Architecture::I386
        ) {
            return Err(ProcessorError::UnexpectedResponse(
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("unsupported VEX architecture: {}", request.architecture),
                )
                .to_string(),
            ));
        }

        let guest_arch = match request.architecture {
            binlex::Architecture::AMD64 => Arch::VexArchAMD64,
            binlex::Architecture::I386 => Arch::VexArchX86,
            binlex::Architecture::CIL | binlex::Architecture::UNKNOWN => unreachable!(
                "unsupported architecture should be rejected by processor registration"
            ),
        };
        let host_arch = if cfg!(target_arch = "aarch64") {
            Arch::VexArchARM64
        } else {
            Arch::VexArchAMD64
        };
        let mut guest_bytes = Vec::with_capacity(request.bytes.len() + BUFFER_PADDING);
        guest_bytes.extend_from_slice(&request.bytes);
        guest_bytes.resize(request.bytes.len() + BUFFER_PADDING, 0);

        let mut translator = TranslateArgs::new(guest_arch, host_arch, VexEndness::VexEndnessLE);
        let ir = translator
            .front_end(guest_bytes.as_ptr(), request.address)
            .map(|irsb| irsb.to_string())
            .map_err(|error| ProcessorError::UnexpectedResponse(format!("{:?}", error)))?;

        Ok(Response { ir })
    }
}

impl GraphProcessor for VexProcessor {
    fn request_message<C: binlex::processor::ProcessorContext>(
        _: &C,
        data: Value,
    ) -> Result<Self::Request, ProcessorError> {
        if let Ok(request) = serde_json::from_value::<Request>(data.clone()) {
            return Ok(request);
        }

        let architecture = data
            .get("architecture")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProcessorError::Serialization(
                    "vex request missing string architecture field".to_string(),
                )
            })
            .and_then(|value| {
                Architecture::from_string(value)
                    .map_err(|error| ProcessorError::Serialization(error.to_string()))
            })?;

        let address = data.get("address").and_then(Value::as_u64).ok_or_else(|| {
            ProcessorError::Serialization("vex request missing u64 address field".to_string())
        })?;

        let bytes_hex = data.get("bytes").and_then(Value::as_str).ok_or_else(|| {
            ProcessorError::Serialization("vex request missing string bytes field".to_string())
        })?;

        let bytes = binlex::hex::decode(bytes_hex).map_err(|error| {
            ProcessorError::Serialization(format!("invalid vex request bytes hex: {error}"))
        })?;

        Ok(Request {
            architecture,
            address,
            bytes,
        })
    }

    fn function_message(function: &Function<'_>) -> Option<Value> {
        let bytes = function.bytes()?;
        serde_json::to_value(Request {
            architecture: function.architecture(),
            address: function.address(),
            bytes,
        })
        .ok()
    }

    fn block_message(block: &Block<'_>) -> Option<Value> {
        serde_json::to_value(Request {
            architecture: block.architecture(),
            address: block.address(),
            bytes: block.bytes(),
        })
        .ok()
    }

    fn instruction_message(instruction: &Instruction) -> Option<Value> {
        serde_json::to_value(Request {
            architecture: instruction.architecture,
            address: instruction.address,
            bytes: instruction.bytes.clone(),
        })
        .ok()
    }

    fn on_function(function: &Function<'_>) -> Option<Value> {
        let bytes = function.bytes()?;
        let response = Self::execute_owned(Request {
            architecture: function.architecture(),
            address: function.address(),
            bytes,
        })
        .ok()?;
        Some(json!({ "ir": response.ir }))
    }

    fn on_block(block: &Block<'_>) -> Option<Value> {
        let response = Self::execute_owned(Request {
            architecture: block.architecture(),
            address: block.address(),
            bytes: block.bytes(),
        })
        .ok()?;
        Some(json!({ "ir": response.ir }))
    }

    fn on_instruction(instruction: &Instruction) -> Option<Value> {
        let response = Self::execute_owned(Request {
            architecture: instruction.architecture,
            address: instruction.address,
            bytes: instruction.bytes.clone(),
        })
        .ok()?;
        Some(json!({ "ir": response.ir }))
    }

    fn on_graph(_: &Graph) -> Option<GraphProcessorFanout> {
        None
    }
}

pub fn registration() -> binlex::processor::ProcessorRegistration {
    external_processor_registration(
        VexProcessor::NAME,
        ">=2.0.0 <2.1.0",
        &[OperatingSystem::LINUX, OperatingSystem::MACOS],
        &[Architecture::AMD64, Architecture::I386],
        &[Transport::IPC, Transport::HTTP],
        VexProcessor::on_graph_options(),
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
                enabled: true,
                options: BTreeMap::new(),
            },
            graph: ConfigProcessorTarget {
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
