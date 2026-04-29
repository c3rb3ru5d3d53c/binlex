use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "bl",
        instruction: "bl #0x10",
        bytes: &[0x04, 0x00, 0x00, 0x94],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "bl",
        instruction: "bl #0x20",
        bytes: &[0x08, 0x00, 0x00, 0x94],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[],
            memory: &[],
        }),
    },
];

#[test]
fn bl_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bl_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
