use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "fcvtzs",
        instruction: "fcvtzs	x0, d1",
        bytes: &[0x20, 0x00, 0x78, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "fcvtzs",
        instruction: "fcvtzs	x0, d1",
        bytes: &[0x20, 0x00, 0x78, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("d1", 0x4045_0000_0000_0000)],
            memory: &[],
        }),
    },
];

#[test]
fn fcvtzs_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn fcvtzs_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
