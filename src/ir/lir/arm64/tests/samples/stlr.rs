use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "stlr",
    instruction: "stlr w5, [x3]",
    bytes: &[0x65, 0xfc, 0x9f, 0x88],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("x3", 0x5000), ("w5", 0x1122_3344)],
        memory: &[(0x5000, &[0x00, 0x00, 0x00, 0x00])],
    }),
}];

#[test]
fn stlr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn stlr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
