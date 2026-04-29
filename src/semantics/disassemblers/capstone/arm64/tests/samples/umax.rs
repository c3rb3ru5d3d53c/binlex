use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "umax",
    instruction: "umax v5.8b, v0.8b, v1.8b",
    bytes: &[0x05, 0x64, 0x21, 0x2e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v0", 0x80ff_017f_10f0_7e81u128),
            ("v1", 0x01fe_0280_20e0_7fffu128),
        ],
        memory: &[],
    }),
}];

#[test]
fn umax_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn umax_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
