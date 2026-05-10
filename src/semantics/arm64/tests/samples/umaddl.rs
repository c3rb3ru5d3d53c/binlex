use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "umaddl",
        instruction: "umaddl	x0, w1, w2, x3",
        bytes: &[0x20, 0x0c, 0xa2, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "umaddl",
        instruction: "umaddl	x0, w1, w2, x3",
        bytes: &[0x20, 0x0c, 0xa2, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 7), ("w2", 6), ("x3", 5)],
            memory: &[],
        }),
    },
];

#[test]
fn umaddl_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn umaddl_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
