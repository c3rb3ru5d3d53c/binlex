use std::io::{Error, ErrorKind};

use libvex::{Arch, TranslateArgs, VexEndness};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::controlflow::{Block, Function};
use crate::lifters::vex::{VexLiftRequest, VexLiftResponse};
use crate::processing::error::ProcessorError;
use crate::processing::processor::Processor;

const BUFFER_PADDING: usize = 64;

#[derive(Serialize, Deserialize, Clone)]
pub enum VexRequest {
    Lift(VexLiftRequest),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum VexResponse {
    Lift(VexLiftResponse),
}

pub struct VexProcessor;

impl Processor for VexProcessor {
    const ID: u16 = 1;
    const NAME: &'static str = "vex";
    type Request = VexRequest;
    type Response = VexResponse;

    fn process_request(&self, request: Self::Request) -> Result<Self::Response, ProcessorError> {
        match request {
            VexRequest::Lift(request) => self.process_lift(request).map(VexResponse::Lift),
        }
    }
}

impl VexProcessor {
    fn process_lift(&self, request: VexLiftRequest) -> Result<VexLiftResponse, ProcessorError> {
        let guest_arch = match request.architecture {
            crate::Architecture::AMD64 => Arch::VexArchAMD64,
            crate::Architecture::I386 => Arch::VexArchX86,
            crate::Architecture::CIL | crate::Architecture::UNKNOWN => {
                return Err(ProcessorError::UnexpectedResponse(
                    Error::new(
                        ErrorKind::InvalidInput,
                        format!("unsupported VEX architecture: {}", request.architecture),
                    )
                    .to_string(),
                ));
            }
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

#[cfg(not(target_os = "windows"))]
pub fn process_function(function: &Function<'_>) -> Option<Value> {
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

#[cfg(not(target_os = "windows"))]
pub fn process_block(block: &Block<'_>) -> Option<Value> {
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
