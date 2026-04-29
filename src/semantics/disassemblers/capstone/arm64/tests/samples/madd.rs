use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "madd",
        instruction: "madd	x0, x1, x2, x3",
        bytes: &[0x20, 0x0c, 0x02, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "madd",
        instruction: "madd	x0, x1, x2, x3",
        bytes: &[0x20, 0x0c, 0x02, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 7), ("x2", 6), ("x3", 5)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "madd",
        instruction: "madd	w0, w1, w2, w3",
        bytes: &[0x20, 0x0c, 0x02, 0x1b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 7), ("w2", 6), ("w3", 5)],
            memory: &[],
        }),
    },
];

#[test]
fn madd_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn madd_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
