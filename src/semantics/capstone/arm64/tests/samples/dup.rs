use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "dup",
        instruction: "dup	v0.16b, w1",
        bytes: &[0x20, 0x0c, 0x01, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "dup",
        instruction: "dup	v0.2d, x1",
        bytes: &[0x20, 0x0c, 0x08, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "dup",
        instruction: "dup	v0.2d, x1",
        bytes: &[0x20, 0x0c, 0x08, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1122_3344_5566_7788)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "dup",
        instruction: "dup	v0.16b, w1",
        bytes: &[0x20, 0x0c, 0x01, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1234_56ab)],
            memory: &[],
        }),
    },
];

#[test]
fn dup_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn dup_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
