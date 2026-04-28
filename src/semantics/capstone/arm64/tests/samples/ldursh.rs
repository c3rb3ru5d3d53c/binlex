use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldursh",
        instruction: "ldursh	x0, [x1, #8]",
        bytes: &[0x20, 0x80, 0x80, 0x78],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldursh",
        instruction: "ldursh	x0, [x1, #8]",
        bytes: &[0x20, 0x80, 0x80, 0x78],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000)],
            memory: &[(0x3008, &[0x01, 0x80])],
        }),
    },
];

#[test]
fn ldursh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldursh_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
