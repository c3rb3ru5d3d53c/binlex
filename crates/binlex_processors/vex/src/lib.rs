use std::io::{Error, ErrorKind};

use binlex::config::{
    ConfigProcessor, ConfigProcessorTarget, ConfigProcessorTransport, ConfigProcessorTransports,
};
use binlex::controlflow::{Block, Function, Instruction};
use binlex::core::Architecture;
use binlex::core::{OperatingSystem, Transport};
use binlex::processor::{
    GraphProcessor, JsonProcessor, ProcessorContext, external_processor_registration,
};
use binlex::runtime::{Processor, ProcessorError};
use libvex::{Arch, TranslateArgs, VexEndness};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use binlex::hex;

const BUFFER_PADDING: usize = 64;

#[derive(Serialize, Deserialize, Clone)]
pub struct VexLiftRequest {
    pub architecture: Architecture,
    pub address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct VexLiftResponse {
    pub architecture: Architecture,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub ir: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub enum VexRequest {
    Lift(VexLiftRequest),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum VexResponse {
    Lift(VexLiftResponse),
}

#[derive(Default)]
pub struct VexProcessor;

impl Processor for VexProcessor {
    const NAME: &'static str = "vex";
    type Request = VexRequest;
    type Response = VexResponse;

    fn request(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        match request {
            VexRequest::Lift(request) => self.process_lift(request).map(VexResponse::Lift),
        }
    }
}

impl JsonProcessor for VexProcessor {
    fn request<C: ProcessorContext>(_: &C, data: Value) -> Result<Self::Request, ProcessorError> {
        let kind = data.get("type").and_then(Value::as_str).ok_or_else(|| {
            ProcessorError::Protocol("processor payload is missing type".to_string())
        })?;

        match kind {
            "lift" => {
                let bytes = data.get("bytes").and_then(Value::as_str).ok_or_else(|| {
                    ProcessorError::Protocol("lift payload does not contain bytes".to_string())
                })?;
                let architecture = data
                    .get("architecture")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ProcessorError::Protocol(
                            "lift payload does not contain architecture".to_string(),
                        )
                    })?;
                let address = data.get("address").and_then(Value::as_u64).ok_or_else(|| {
                    ProcessorError::Protocol("lift payload does not contain address".to_string())
                })?;
                Ok(VexRequest::Lift(VexLiftRequest {
                    architecture: Architecture::from_string(architecture)
                        .map_err(|error| ProcessorError::Protocol(error.to_string()))?,
                    address,
                    bytes: hex::decode(bytes)
                        .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
                }))
            }
            "instruction" => {
                let json: binlex::controlflow::InstructionJson = serde_json::from_value(data)
                    .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
                Ok(VexRequest::Lift(VexLiftRequest {
                    architecture: Architecture::from_string(&json.architecture)
                        .map_err(|error| ProcessorError::Protocol(error.to_string()))?,
                    address: json.address,
                    bytes: hex::decode(&json.bytes)
                        .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
                }))
            }
            "block" => {
                let json: binlex::controlflow::BlockJson = serde_json::from_value(data)
                    .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
                Ok(VexRequest::Lift(VexLiftRequest {
                    architecture: Architecture::from_string(&json.architecture)
                        .map_err(|error| ProcessorError::Protocol(error.to_string()))?,
                    address: json.address,
                    bytes: hex::decode(&json.bytes)
                        .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
                }))
            }
            "function" => {
                let json: binlex::controlflow::FunctionJson = serde_json::from_value(data)
                    .map_err(|error| ProcessorError::Serialization(error.to_string()))?;
                let bytes = json.bytes.ok_or_else(|| {
                    ProcessorError::Protocol("function payload does not contain bytes".to_string())
                })?;
                Ok(VexRequest::Lift(VexLiftRequest {
                    architecture: Architecture::from_string(&json.architecture)
                        .map_err(|error| ProcessorError::Protocol(error.to_string()))?,
                    address: json.address,
                    bytes: hex::decode(&bytes)
                        .map_err(|error| ProcessorError::Serialization(error.to_string()))?,
                }))
            }
            other => Err(ProcessorError::Protocol(format!(
                "unsupported processor payload type: {}",
                other
            ))),
        }
    }

    fn response(response: Self::Response) -> Result<Value, ProcessorError> {
        match response {
            VexResponse::Lift(response) => Ok(json!({ "ir": response.ir })),
        }
    }
}

impl GraphProcessor for VexProcessor {
    fn function_json(function: &Function<'_>) -> Option<Value> {
        function.bytes()?;
        serde_json::to_value(function.process_base()).ok()
    }

    fn function(function: &Function<'_>) -> Option<Value> {
        let bytes = function.bytes()?;
        let mut lifter = binlex::lifters::vex::Lifter::new(
            function.architecture(),
            &bytes,
            function.address(),
            function.cfg.config.clone(),
        )
        .ok()?;
        let vex = lifter.process().ok()?;
        Some(json!({ "ir": vex.ir }))
    }

    fn block(block: &Block<'_>) -> Option<Value> {
        let bytes = block.bytes();
        let mut lifter = binlex::lifters::vex::Lifter::new(
            block.architecture(),
            &bytes,
            block.address(),
            block.cfg.config.clone(),
        )
        .ok()?;
        let vex = lifter.process().ok()?;
        Some(json!({ "ir": vex.ir }))
    }

    fn instruction(instruction: &Instruction) -> Option<Value> {
        let mut lifter = binlex::lifters::vex::Lifter::new(
            instruction.architecture,
            &instruction.bytes,
            instruction.address,
            instruction.config.clone(),
        )
        .ok()?;
        let vex = lifter.process().ok()?;
        Some(json!({ "ir": vex.ir }))
    }
}

impl VexProcessor {
    fn process_lift(&self, request: VexLiftRequest) -> Result<VexLiftResponse, ProcessorError> {
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

        Ok(VexLiftResponse {
            architecture: request.architecture,
            address: request.address,
            bytes: request.bytes,
            ir,
        })
    }
}

pub fn registration() -> binlex::processor::ProcessorRegistration {
    external_processor_registration(
        VexProcessor::NAME,
        ">=2.0.0 <2.1.0",
        &[OperatingSystem::LINUX, OperatingSystem::MACOS],
        &[Architecture::AMD64, Architecture::I386],
        &[Transport::IPC, Transport::HTTP],
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
