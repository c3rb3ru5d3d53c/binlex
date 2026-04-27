use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "cvtdq2pd",
            instruction: "cvtdq2pd xmm0, xmm1",
            architecture: Architecture::AMD64,
            bytes: (&[0xf3, 0x0f, 0xe6, 0xc1]).to_vec(),
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
        let int_pairs = (10u128) | (u128::from((-2i32 as u32) as u64) << 32);

        samples.push(X86RuntimeSample {
            mnemonic: "cvtdq2pd",
            instruction: "cvtdq2pd xmm0, xmm1",
            architecture: Architecture::AMD64,
            bytes: (&[0xf3, 0x0f, 0xe6, 0xc1]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![(I386Register::Xmm0, 0), (I386Register::Xmm1, int_pairs)],
                eflags: 1 << 1,
                memory: vec![],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn cvtdq2pd_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn cvtdq2pd_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}
