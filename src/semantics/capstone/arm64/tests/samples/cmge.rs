use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cmge",
    instruction: "cmge v0.8b, v1.8b, #0",
    bytes: &[0x20, 0x88, 0x20, 0x2e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v1", 0x05fe_0200_7f01_ff80u128)],
        memory: &[],
    }),
}];

#[test]
fn cmge_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cmge_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
