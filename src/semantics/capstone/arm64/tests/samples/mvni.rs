use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "mvni",
    instruction: "mvni v1.4h, #0",
    bytes: &[0x01, 0x84, 0x00, 0x2f],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[],
        memory: &[],
    }),
}];

#[test]
fn mvni_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn mvni_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
