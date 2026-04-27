use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "mul",
        instruction: "mul	x0, x1, x2",
        bytes: &[0x20, 0x7c, 0x02, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "mul",
        instruction: "mul	x0, x1, x2",
        bytes: &[0x20, 0x7c, 0x02, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 7), ("x2", 6)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mul",
        instruction: "mul	w0, w1, w2",
        bytes: &[0x20, 0x7c, 0x02, 0x1b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 7), ("w2", 6)],
            memory: &[],
        }),
    },
];

#[test]
fn mul_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn mul_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
