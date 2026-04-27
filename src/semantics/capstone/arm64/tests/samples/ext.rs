use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ext",
    instruction: "ext v1.16b, v2.16b, v3.16b, #1",
    bytes: &[0x41, 0x08, 0x03, 0x6e],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v2", 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100u128),
            ("v3", 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110u128),
        ],
        memory: &[],
    }),
}];

#[test]
fn ext_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ext_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
