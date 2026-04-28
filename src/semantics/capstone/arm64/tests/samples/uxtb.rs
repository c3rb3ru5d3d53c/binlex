use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[Arm64Sample {
    mnemonic: "uxtb",
    instruction: "uxtb w0, w1",
    bytes: &[0x20, 0x1c, 0x00, 0x53],
    expected_status: Some(SemanticStatus::Complete),
    fixture: Some(Arm64FixtureSpec {
        registers: &[("w1", 0x1234_56ab)],
        memory: &[],
    }),
}];

#[test]
fn uxtb_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn uxtb_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
