use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ushr",
    instruction: "ushr d0, d1, #2",
    bytes: &[0x20, 0x04, 0x7e, 0x7f],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("d1", 0x8000_0000_0000_0001u128)],
        memory: &[],
    }),
}];

#[test]
fn ushr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ushr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
