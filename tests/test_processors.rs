#![cfg(not(target_os = "windows"))]

use binlex::Architecture;
use binlex::runtime::Processor;
use binlex_processor_vex::{VexLiftRequest, VexProcessor, VexRequest, VexResponse};

#[test]
fn test_vex_processor_handles_encoded_lift_request() {
    let processor = VexProcessor;
    let payload = postcard::to_allocvec(&VexRequest::Lift(VexLiftRequest {
        architecture: Architecture::AMD64,
        address: 0x1000,
        bytes: vec![0xC3],
    }))
    .expect("request should serialize");

    let response_payload = processor
        .process(&payload)
        .expect("processor should handle encoded lift request");
    let response: VexResponse =
        postcard::from_bytes(&response_payload).expect("response should deserialize");

    match response {
        VexResponse::Lift(response) => {
            assert_eq!(response.architecture, Architecture::AMD64);
            assert_eq!(response.address, 0x1000);
            assert_eq!(response.bytes, vec![0xC3]);
            assert!(!response.ir.is_empty());
        }
    }
}
