use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "not",
    instruction: "not v1.16b, v0.16b",
    bytes: &[0x01, 0x58, 0x20, 0x6e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v0", 0xffee_ddcc_bbaa_9988_7766_5544_3322_1100u128)],
        memory: &[],
    }),
}];

#[test]
fn not_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn not_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
