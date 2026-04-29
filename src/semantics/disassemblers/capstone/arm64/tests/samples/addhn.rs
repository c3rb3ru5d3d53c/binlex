use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "addhn",
    instruction: "addhn	v0.8b, v1.8h, v2.8h",
    bytes: &[0x20, 0x40, 0x22, 0x0e],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[
            ("v1", 0x0080_0100_0180_0200_0280_0300_0380_0400),
            ("v2", 0x0080_0100_0180_0200_0280_0300_0380_0400),
        ],
        memory: &[],
    }),
}];

#[test]
fn addhn_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn addhn_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
