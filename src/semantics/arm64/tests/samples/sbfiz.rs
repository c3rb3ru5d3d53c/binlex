use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sbfiz",
        instruction: "sbfiz	x0, x1, #4, #8",
        bytes: &[0x20, 0x1c, 0x7c, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sbfiz",
        instruction: "sbfiz	x0, x1, #4, #8",
        bytes: &[0x20, 0x1c, 0x7c, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0000_0000_0000_00f1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sbfiz",
        instruction: "sbfiz	w0, w1, #4, #8",
        bytes: &[0x20, 0x1c, 0x1c, 0x13],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x0000_00f1)],
            memory: &[],
        }),
    },
];

#[test]
fn sbfiz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sbfiz_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
