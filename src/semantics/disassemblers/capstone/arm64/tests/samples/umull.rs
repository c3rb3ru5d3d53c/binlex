use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "umull",
        instruction: "umull	x0, w1, w2",
        bytes: &[0x20, 0x7c, 0xa2, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "umull",
        instruction: "umull	x0, w1, w2",
        bytes: &[0x20, 0x7c, 0xa2, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xffff_ffff), ("w2", 2)],
            memory: &[],
        }),
    },
];

#[test]
fn umull_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn umull_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
