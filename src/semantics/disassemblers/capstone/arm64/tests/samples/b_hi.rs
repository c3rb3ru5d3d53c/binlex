use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "b_hi",
    instruction: "b.hi	#16",
    bytes: &[0x88, 0x00, 0x00, 0x54],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[("c", 0), ("z", 0)],
        memory: &[],
    }),
}];

#[test]
fn b_hi_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn b_hi_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
