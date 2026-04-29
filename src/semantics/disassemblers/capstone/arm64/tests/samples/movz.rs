use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "movz",
    instruction: "mov	x0, #305397760                  // =0x12340000",
    bytes: &[0x80, 0x46, 0xa2, 0xd2],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[],
        memory: &[],
    }),
}];

#[test]
fn movz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movz_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
