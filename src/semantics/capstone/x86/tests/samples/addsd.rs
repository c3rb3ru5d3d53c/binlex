use super::{
    I386Register, X86RuntimeFixtureSpec, X86RuntimeSample, assert_runtime_conformance_cases,
    assert_runtime_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

fn vec128(low: u64, high: u64) -> u128 {
    (u128::from(high) << 64) | u128::from(low)
}

fn status_samples() -> Vec<X86RuntimeSample> {
    let mut samples = Vec::new();
    {
        samples.push(X86RuntimeSample {
            mnemonic: "addsd",
            instruction: "addsd xmm0, xmm1",
            architecture: Architecture::AMD64,
            bytes: (&[0xf2, 0x0f, 0x58, 0xc1]).to_vec(),
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
        let lhs = 3.5f64.to_bits();
        let rhs = (-1.25f64).to_bits();
        let upper_a = 0x1122_3344_5566_7788u64;
        let upper_b = 0x99aa_bbcc_ddee_ff00u64;

        samples.push(X86RuntimeSample {
            mnemonic: "addsd",
            instruction: "addsd xmm0, xmm1",
            architecture: Architecture::AMD64,
            bytes: (&[0xf2, 0x0f, 0x58, 0xc1]).to_vec(),
            expected_status: None,
            semantics_fixture: Some(X86RuntimeFixtureSpec {
                registers: vec![
                    (I386Register::Xmm0, vec128(lhs, upper_a)),
                    (I386Register::Xmm1, vec128(rhs, upper_b)),
                ],
                eflags: 1 << 1,
                memory: vec![],
            }),
            roundtrip_fixture: None,
        });
    }
    samples
}

#[test]
fn addsd_semantics_regressions_stay_complete() {
    let samples = status_samples();
    assert_runtime_sample_statuses(&samples);
}

#[test]
fn addsd_semantics_match_unicorn_transitions() {
    let samples = conformance_samples();
    assert_runtime_conformance_cases(&samples);
}
