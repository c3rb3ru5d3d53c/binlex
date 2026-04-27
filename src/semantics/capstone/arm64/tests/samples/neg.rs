use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "neg",
        instruction: "neg	x0, x1",
        bytes: &[0xe0, 0x03, 0x01, 0xcb],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "neg",
        instruction: "neg	x0, x1",
        bytes: &[0xe0, 0x03, 0x01, 0xcb],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 5)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "neg",
        instruction: "neg	w0, w1",
        bytes: &[0xe0, 0x03, 0x01, 0x4b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 5)],
            memory: &[],
        }),
    },
];

#[test]
fn neg_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn neg_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
