use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldtrsw",
        instruction: "ldtrsw	x0, [x1, #8]",
        bytes: &[0x20, 0x88, 0x80, 0xb8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldtrsw",
        instruction: "ldtrsw	x0, [x1, #8]",
        bytes: &[0x20, 0x88, 0x80, 0xb8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000)],
            memory: &[(0x3008, &[0x01, 0x00, 0x00, 0x80])],
        }),
    },
];

#[test]
fn ldtrsw_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldtrsw_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
