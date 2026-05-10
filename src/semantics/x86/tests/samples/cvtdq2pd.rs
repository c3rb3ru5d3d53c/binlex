use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const INT_PAIRS: u128 = 10u128 | (((-2i32 as u32) as u128) << 32);

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "cvtdq2pd",
    instruction: "cvtdq2pd xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0xf3, 0x0f, 0xe6, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[(I386Register::Xmm0, 0), (I386Register::Xmm1, INT_PAIRS)],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn cvtdq2pd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cvtdq2pd_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
