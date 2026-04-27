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
            mnemonic: "movhpd",
            instruction: "movhpd xmm0, qword ptr [rax]",
            architecture: Architecture::AMD64,
            bytes: (&[0x66, 0x0f, 0x16, 0x00]).to_vec(),
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
        let mem128 = [
            0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57,
            0x9b, 0xdf,
        ];

        samples.push(X86RuntimeSample {
            mnemonic: "movhpd",
            instruction: "movhpd xmm0, qword ptr [rax]",
            architecture: Architecture::AMD64,
            bytes: (&[0x66, 0x0f, 0x16, 0x00]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, xmm0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, mem128[..8].to_vec())],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn movhpd_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn movhpd_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}
