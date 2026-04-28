use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "smull",
        instruction: "smull	x0, w1, w2",
        bytes: &[0x20, 0x7c, 0x22, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "smull",
        instruction: "smull	x0, w1, w2",
        bytes: &[0x20, 0x7c, 0x22, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xffff_fffe), ("w2", 3)],
            memory: &[],
        }),
    },
];

#[test]
fn smull_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn smull_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
