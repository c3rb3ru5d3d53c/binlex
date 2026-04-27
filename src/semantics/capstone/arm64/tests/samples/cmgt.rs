use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "cmgt",
    instruction: "cmgt v0.8b, v1.8b, #0",
    bytes: &[0x20, 0x88, 0x20, 0x0e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v1", 0x05fe_0200_7f01_ff80u128)],
        memory: &[],
    }),
}];

#[test]
fn cmgt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cmgt_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
