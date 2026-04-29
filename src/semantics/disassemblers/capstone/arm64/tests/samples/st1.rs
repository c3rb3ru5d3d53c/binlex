use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "st1",
    instruction: "st1 {v0.16b, v1.16b}, [x3]",
    bytes: &[0x60, 0xa0, 0x00, 0x4c],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v0", 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100u128),
            ("v1", 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110u128),
            ("x3", 0x5000),
        ],
        memory: &[(0x5000, &[0u8; 32])],
    }),
}];

#[test]
fn st1_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn st1_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
