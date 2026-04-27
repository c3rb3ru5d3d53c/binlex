use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "blr",
        instruction: "blr x3",
        bytes: &[0x60, 0x00, 0x3f, 0xd6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 0x1020)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "blr",
        instruction: "blr x17",
        bytes: &[0x20, 0x02, 0x3f, 0xd6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x17", 0x1080)],
            memory: &[],
        }),
    },
];

#[test]
fn blr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn blr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
