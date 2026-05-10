use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "mov",
        instruction: "mov	x0, x1",
        bytes: &[0xe0, 0x03, 0x01, 0xaa],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x1234_5678_9abc_def0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "mov",
        instruction: "mov	w0, w1",
        bytes: &[0xe0, 0x03, 0x01, 0x2a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1234_5678)],
            memory: &[],
        }),
    },
];

#[test]
fn mov_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn mov_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
