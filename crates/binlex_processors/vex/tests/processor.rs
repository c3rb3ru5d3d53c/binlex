#![cfg(not(target_os = "windows"))]

use binlex::Architecture;
use binlex::runtime::Processor;
use binlex_processor_vex::{Request, Response, VexProcessor};

#[test]
fn handles_encoded_lift_request() {
    let processor = VexProcessor;
    let payload = postcard::to_allocvec(&Request {
        architecture: Architecture::AMD64,
        address: 0x1000,
        bytes: vec![0xC3],
    })
    .expect("request should serialize");

    let response_payload = processor
        .process(&payload)
        .expect("processor should handle encoded lift request");
    let response: Response =
        postcard::from_bytes(&response_payload).expect("response should deserialize");
    assert!(!response.ir.is_empty());
}
