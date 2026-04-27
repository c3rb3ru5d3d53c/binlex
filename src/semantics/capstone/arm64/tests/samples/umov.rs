use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "umov",
    instruction: "umov w0, v0.B[0]",
    bytes: &[0x00, 0x3c, 0x01, 0x0e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v0", 0x0000_0000_0000_0080u128)],
        memory: &[],
    }),
}];

#[test]
fn umov_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn umov_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
