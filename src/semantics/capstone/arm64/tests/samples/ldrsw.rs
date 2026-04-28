use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldrsw",
        instruction: "ldrsw	x0, [x1]",
        bytes: &[0x20, 0x00, 0x80, 0xb9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldrsw",
        instruction: "ldrsw	x0, [x1]",
        bytes: &[0x20, 0x00, 0x80, 0xb9],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x2000)],
            memory: &[(0x2000, &[0x01, 0x00, 0x00, 0x80])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldrsw",
        instruction: "ldrsw	x0, [x1, x2]",
        bytes: &[0x20, 0x68, 0xa2, 0xb8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000), ("x2", 0x10)],
            memory: &[(0x3010, &[0x01, 0x00, 0x00, 0x80])],
        }),
    },
];

#[test]
fn ldrsw_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldrsw_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
