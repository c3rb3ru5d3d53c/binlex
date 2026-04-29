use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cinv",
        instruction: "cinv	x0, x1, eq",
        bytes: &[0x20, 0x10, 0x81, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x10), ("z", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cinv",
        instruction: "cinv	w0, w1, ne",
        bytes: &[0x20, 0x00, 0x81, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1234_5678), ("z", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn cinv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cinv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
