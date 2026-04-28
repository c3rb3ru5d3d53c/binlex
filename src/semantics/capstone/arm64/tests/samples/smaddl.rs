use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "smaddl",
        instruction: "smaddl	x0, w1, w2, x3",
        bytes: &[0x20, 0x0c, 0x22, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "smaddl",
        instruction: "smaddl	x0, w1, w2, x3",
        bytes: &[0x20, 0x0c, 0x22, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xffff_fffe), ("w2", 3), ("x3", 5)],
            memory: &[],
        }),
    },
];

#[test]
fn smaddl_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn smaddl_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
