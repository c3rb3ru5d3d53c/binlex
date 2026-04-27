use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "udiv",
        instruction: "udiv	x0, x1, x2",
        bytes: &[0x20, 0x08, 0xc2, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "udiv",
        instruction: "udiv	x0, x1, x2",
        bytes: &[0x20, 0x08, 0xc2, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 100), ("x2", 5)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "udiv",
        instruction: "udiv	w0, w1, w2",
        bytes: &[0x20, 0x08, 0xc2, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 100), ("w2", 5)],
            memory: &[],
        }),
    },
];

#[test]
fn udiv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn udiv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
