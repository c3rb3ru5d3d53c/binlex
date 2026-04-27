use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "b_le",
    instruction: "b.le	#16",
    bytes: &[0x8d, 0x00, 0x00, 0x54],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[("z", 0), ("n", 0), ("v", 0)],
        memory: &[],
    }),
}];

#[test]
fn b_le_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn b_le_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
