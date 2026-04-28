use super::{
    I386Register, X86FixtureSpec, X86Sample, assert_conformance_cases, assert_sample_statuses,
};
use crate::{Architecture, semantics::SemanticStatus};

const fn vec128(low: u64, high: u64) -> u128 {
    ((high as u128) << 64) | (low as u128)
}

pub(crate) const SAMPLES: &[X86Sample] = &[X86Sample {
    mnemonic: "ucomiss",
    instruction: "ucomiss xmm0, xmm1",
    architecture: Architecture::AMD64,
    bytes: &[0x0f, 0x2e, 0xc1],
    expected_status: Some(SemanticStatus::Complete),
    semantics_fixture: Some(X86FixtureSpec {
        registers: &[
            (I386Register::Xmm0, vec128(0x0000_0000_3f80_0000, 0x1122_3344_5566_7788)),
            (I386Register::Xmm1, vec128(0x0000_0000_4000_0000, 0x99aa_bbcc_ddee_ff00)),
        ],
        eflags: 1 << 1,
        memory: &[],
    }),
    roundtrip_fixture: None,
}];

#[test]
fn ucomiss_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ucomiss_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
