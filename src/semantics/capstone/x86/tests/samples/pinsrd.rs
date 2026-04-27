use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn vec128(bytes: [u8; 16]) -> u128 {
    u128::from_le_bytes(bytes)
}

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "pinsrd",
            instruction: "pinsrd xmm0, eax, 1",
            architecture: Architecture::AMD64,
            bytes: (&[0x66, 0x0f, 0x3a, 0x22, 0xc0, 0x01]).to_vec(),
            expected_status: Some(SemanticStatus::Complete),
            semantics_fixture: None,
            roundtrip_fixture: None,
        });
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
            mnemonic: "pinsrd",
            instruction: "pinsrd xmm0, eax, 1",
            architecture: Architecture::AMD64,
            bytes: (&[0x66, 0x0f, 0x3a, 0x22, 0xc0, 0x01]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![(I386Register::Eax, 0x1234_5678), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn pinsrd_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn pinsrd_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}
