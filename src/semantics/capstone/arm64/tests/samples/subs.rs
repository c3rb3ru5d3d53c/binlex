use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "subs",
    instruction: "subs w9, w0, w1",
    bytes: &[0x09, 0x00, 0x01, 0x6b],
    expected_status: None,
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("w0", 0x10),
            ("w1", 0x01),
            ("n", 0),
            ("z", 0),
            ("c", 0),
            ("v", 0),
        ],
        memory: &[],
    }),
}];

#[test]
fn subs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn subs_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
