use std::io::{Error, ErrorKind};

use libvex::{Arch, TranslateArgs, VexEndness};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::controlflow::{Block, Function, Instruction};
use crate::global::Architecture;
use crate::hex;
use crate::lifters::vex::{VexLiftRequest, VexLiftResponse};
use crate::processing::error::ProcessorError;
use crate::processing::processor::Processor;
use crate::global::{OperatingSystem, Transport};
use crate::processors::{GraphProcessor, JsonProcessor};

const BUFFER_PADDING: usize = 64;

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
    fn request<C: crate::processors::ProcessorContext>(
        _: &C,
        data: Value,
    ) -> Result<Self::Request, crate::processing::error::ProcessorError> {
        let kind = data.get("type").and_then(Value::as_str).ok_or_else(|| {
            crate::processing::error::ProcessorError::Protocol(
                "processor payload is missing type".to_string(),
            )
        })?;

        match kind {
            "instruction" => {
                let json: crate::controlflow::InstructionJson = serde_json::from_value(data)
                    .map_err(|error| {
                        crate::processing::error::ProcessorError::Serialization(error.to_string())
                    })?;
                Ok(VexRequest::Lift(VexLiftRequest {
                    architecture: Architecture::from_string(&json.architecture).map_err(
                        |error| {
                            crate::processing::error::ProcessorError::Protocol(error.to_string())
                        },
                    )?,
                    address: json.address,
                    bytes: hex::decode(&json.bytes).map_err(|error| {
                        crate::processing::error::ProcessorError::Serialization(error.to_string())
                    })?,
                }))
            }
            "block" => {
                let json: crate::controlflow::BlockJson =
                    serde_json::from_value(data).map_err(|error| {
                        crate::processing::error::ProcessorError::Serialization(error.to_string())
                    })?;
                Ok(VexRequest::Lift(VexLiftRequest {
                    architecture: Architecture::from_string(&json.architecture).map_err(
                        |error| {
                            crate::processing::error::ProcessorError::Protocol(error.to_string())
                        },
                    )?,
                    address: json.address,
                    bytes: hex::decode(&json.bytes).map_err(|error| {
                        crate::processing::error::ProcessorError::Serialization(error.to_string())
                    })?,
                }))
            }
            "function" => {
                let json: crate::controlflow::FunctionJson =
                    serde_json::from_value(data).map_err(|error| {
                        crate::processing::error::ProcessorError::Serialization(error.to_string())
                    })?;
                let bytes = json.bytes.ok_or_else(|| {
                    crate::processing::error::ProcessorError::Protocol(
                        "function payload does not contain bytes".to_string(),
                    )
                })?;
                Ok(VexRequest::Lift(VexLiftRequest {
                    architecture: Architecture::from_string(&json.architecture).map_err(
                        |error| {
                            crate::processing::error::ProcessorError::Protocol(error.to_string())
                        },
                    )?,
                    address: json.address,
                    bytes: hex::decode(&bytes).map_err(|error| {
                        crate::processing::error::ProcessorError::Serialization(error.to_string())
                    })?,
                }))
            }
            other => Err(crate::processing::error::ProcessorError::Protocol(format!(
                "unsupported processor payload type: {}",
                other
            ))),
        }
    }

    fn response(
        response: Self::Response,
    ) -> Result<Value, crate::processing::error::ProcessorError> {
        match response {
            VexResponse::Lift(response) => Ok(json!({ "ir": response.ir })),
        }
    }
}

impl GraphProcessor for VexProcessor {
    fn function(function: &Function<'_>) -> Option<Value> {
        let bytes = function.bytes()?;
        let mut lifter = crate::lifters::vex::Lifter::new(
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
        let mut lifter = crate::lifters::vex::Lifter::new(
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
        let mut lifter = crate::lifters::vex::Lifter::new(
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
        if !crate::processors::processor_registration_by_type::<Self>()
            .is_some_and(|registration| registration.registration.supports_architecture(request.architecture))
        {
            return Err(ProcessorError::UnexpectedResponse(
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("unsupported VEX architecture: {}", request.architecture),
                )
                .to_string(),
            ));
        }

        let guest_arch = match request.architecture {
            crate::Architecture::AMD64 => Arch::VexArchAMD64,
            crate::Architecture::I386 => Arch::VexArchX86,
            crate::Architecture::CIL | crate::Architecture::UNKNOWN => unreachable!(
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

crate::processor!(VexProcessor {
    operating_systems: [OperatingSystem::LINUX, OperatingSystem::MACOS],
    architectures: [Architecture::AMD64, Architecture::I386],
    enabled: false,
    transports: [Transport::INLINE, Transport::HTTP, Transport::IPC],
    instructions: { enabled: false },
    blocks: { enabled: false },
    functions: { enabled: true },
    inline: { enabled: false },
    ipc: { enabled: true },
    http: {
        enabled: false,
        options: {
            url: "http://127.0.0.1:5000",
            verify: false
        }
    },
});
