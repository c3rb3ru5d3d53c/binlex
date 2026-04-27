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
            ("pmovmskb eax, xmm0", vec![0x66, 0x0f, 0xd7, 0xc0]),
            ("vpmovmskb eax, xmm0", vec![0xc5, 0xf9, 0xd7, 0xc0]),
        ];

        for (name, bytes) in cases {
            samples.push(X86RuntimeSample {
                mnemonic: "pmovmskb",
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

        samples.push(X86RuntimeSample {
            mnemonic: "pmovmskb",
            instruction: "pmovmskb eax, xmm0",
            architecture: Architecture::AMD64,
            bytes: (&[0x66, 0x0f, 0xd7, 0xc0]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![(I386Register::Eax, 0), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn pmovmskb_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn pmovmskb_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}

#[test]
fn vpmovmskb_semantics_wide_regression_stays_stable() {
    let ymm0 = vec![
        0x10, 0x80, 0x20, 0x70, 0x30, 0x60, 0x40, 0x50, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11,
        0x22, 0x01, 0x81, 0x02, 0x82, 0x03, 0x83, 0x04, 0x84, 0x05, 0x85, 0x06, 0x86, 0x07, 0x87,
        0x08, 0x88,
    ];

    let (registers, _) = interpret_amd64_wide_semantics(
        "vpmovmskb eax, ymm0",
        &[0xc5, 0xfd, 0xd7, 0xc0],
        WideI386Fixture {
            base: I386Fixture {
                registers: vec![(I386Register::Eax, 0)],
                eflags: 1 << 1,
                memory: vec![],
            },
            wide_registers: vec![(I386Register::Ymm0, ymm0)],
        },
    );

    assert_eq!(registers.get("eax"), Some(&vec![0x02, 0x3f, 0xaa, 0xaa]));
}
