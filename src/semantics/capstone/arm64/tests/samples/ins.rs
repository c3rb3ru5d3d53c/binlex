use super::{Arm64Sample, assert_conformance_cases, assert_sample_statuses};
pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "ins",
    instruction: "ins v1.b[3], v2.b[0]",
    bytes: &[0x41, 0x04, 0x07, 0x6e],
    expected_status: None,
    fixture: None,
}];

#[test]
fn ins_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ins_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
