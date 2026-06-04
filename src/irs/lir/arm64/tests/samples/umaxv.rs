use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "umaxv",
    instruction: "umaxv b5, v0.8b",
    bytes: &[0x05, 0xa8, 0x30, 0x2e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v0", 0x80ff_017f_10f0_7e81u128)],
        memory: &[],
    }),
}];

#[test]
fn umaxv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn umaxv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
