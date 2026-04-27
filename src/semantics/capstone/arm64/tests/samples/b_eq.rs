use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "b_eq",
    instruction: "b.eq	#16",
    bytes: &[0x80, 0x00, 0x00, 0x54],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[("z", 0)],
        memory: &[],
    }),
}];

#[test]
fn b_eq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn b_eq_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
