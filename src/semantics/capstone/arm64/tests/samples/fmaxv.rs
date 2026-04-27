use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fmaxv",
    instruction: "fmaxv s5, v0.4s",
    bytes: &[0x05, 0xf8, 0x30, 0x6e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("v0", 0x4060_0000_bf80_0000_4000_0000_3f80_0000u128)],
        memory: &[],
    }),
}];

#[test]
fn fmaxv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn fmaxv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
