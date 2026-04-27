use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "nop",
    instruction: "nop",
    bytes: &[0x1f, 0x20, 0x03, 0xd5],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[],
        memory: &[],
    }),
}];

#[test]
fn nop_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn nop_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
