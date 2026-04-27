use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "fcvt",
    instruction: "fcvt s1, d0",
    bytes: &[0x01, 0x40, 0x62, 0x1e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("d0", 0x400a_0000_0000_0000)],
        memory: &[],
    }),
}];

#[test]
fn fcvt_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn fcvt_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
