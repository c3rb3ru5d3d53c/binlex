use super::{
    I386Fixture, I386Register, X86RuntimeFixtureSpec, X86RuntimeSample,
    assert_runtime_conformance_cases, assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

use super::super::support::{WideI386Fixture, interpret_amd64_wide_semantics};

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let cases = [
            ("ptest xmm0, xmm1", vec![0x66, 0x0f, 0x38, 0x17, 0xc1]),
            ("vptest xmm0, xmm1", vec![0xc4, 0xe2, 0x79, 0x17, 0xc1]),
        ];

        for (name, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "ptest",
                instruction: name,
                architecture: Architecture::AMD64,
                bytes: (&bytes).to_vec(),
                expected_status: Some(SemanticStatus::Complete),
                semantics_fixture: None,
                roundtrip_fixture: None,
            });
        }
    }
    samples
}

fn conformance_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        let xmm0 = vec128([
            0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x11, 0x22,
        ]);
        let xmm1 = vec128([
            0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
            0x99, 0x88,
        ]);

        samples.push(X86RuntimeSample {
            mnemonic: "ptest",
            instruction: "ptest xmm0, xmm1",
            architecture: Architecture::AMD64,
            bytes: (&[0x66, 0x0f, 0x38, 0x17, 0xc1]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![(I386Register::Xmm0, xmm0), (I386Register::Xmm1, xmm1)],
                eflags: 1 << 1,
                memory: vec![],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn ptest_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn ptest_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn vptest_semantics_wide_regression_stays_stable() {
    let ymm0 = vec![
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
        0x22, 0x01, 0x81, 0x02, 0x82, 0x03, 0x83, 0x04, 0x84, 0x05, 0x85, 0x06, 0x86, 0x07, 0x87,
        0x08, 0x88,
    ];
    let ymm1 = vec![
        0x01, 0xff, 0x02, 0xfe, 0x03, 0xfd, 0x04, 0xfc, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x99,
        0x88, 0xf0, 0x0f, 0xe1, 0x1e, 0xd2, 0x2d, 0xc3, 0x3c, 0xb4, 0x4b, 0xa5, 0x5a, 0x96, 0x69,
        0x87, 0x78,
    ];

    let (_, flags) = interpret_amd64_wide_semantics(
        "vptest ymm0, ymm1",
        &[0xc4, 0xe2, 0x7d, 0x17, 0xc1],
        WideI386Fixture {
            base: I386Fixture {
                registers: vec![],
                eflags: 1 << 1,
                memory: vec![],
            },
            wide_registers: vec![(I386Register::Ymm0, ymm0), (I386Register::Ymm1, ymm1)],
        },
    );

    assert!(!flags.zf, "vptest ymm0, ymm1: zf mismatch");
    assert!(!flags.cf, "vptest ymm0, ymm1: cf mismatch");
}
