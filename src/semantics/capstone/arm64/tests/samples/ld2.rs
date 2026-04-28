use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ld2",
    instruction: "ld2 {v0.16b, v1.16b}, [x3], #32",
    bytes: &[0x60, 0x80, 0xdf, 0x4c],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[("x3", 0x5000)],
        memory: &[(
            0x5000,
            &[
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
                0x1c, 0x1d, 0x1e, 0x1f,
            ],
        )],
    }),
}];

#[test]
fn ld2_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ld2_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
