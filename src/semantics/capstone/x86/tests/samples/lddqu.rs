use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "lddqu",
            instruction: "lddqu xmm0, xmmword ptr [rax]",
            architecture: Architecture::AMD64,
            bytes: (&[0xf2, 0x0f, 0xf0, 0x00]).to_vec(),
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
        let mem128 = vec![
            0xde, 0xad, 0xbe, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x13, 0x57,
            0x9b, 0xdf,
        ];

        samples.push(X86RuntimeSample {
            mnemonic: "lddqu",
            instruction: "lddqu xmm0, xmmword ptr [rax]",
            architecture: Architecture::AMD64,
            bytes: (&[0xf2, 0x0f, 0xf0, 0x00]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![(I386Register::Rax, 0x3000), (I386Register::Xmm0, 0)],
                eflags: 1 << 1,
                memory: vec![(0x3000, mem128)],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn lddqu_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn lddqu_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}
