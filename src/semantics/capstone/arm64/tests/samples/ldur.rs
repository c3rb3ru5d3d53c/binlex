use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldur",
        instruction: "ldur	x0, [x1, #8]",
        bytes: &[0x20, 0x80, 0x40, 0xf8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldur",
        instruction: "ldur	x0, [x1, #8]",
        bytes: &[0x20, 0x80, 0x40, 0xf8],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x3000)],
            memory: &[(0x3008, &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])],
        }),
    },
];

#[test]
fn ldur_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldur_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
