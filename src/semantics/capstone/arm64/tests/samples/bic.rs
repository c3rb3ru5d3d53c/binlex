use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "bic",
        instruction: "bic	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x22, 0x8a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "bic",
        instruction: "bic	x0, x1, x2",
        bytes: &[0x20, 0x00, 0x22, 0x8a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0xffff_0000_ffff_0000), ("x2", 0x00ff_00ff_00ff_00ff)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "bic",
        instruction: "bic	w0, w1, w2",
        bytes: &[0x20, 0x00, 0x22, 0x0a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xffff_0000), ("w2", 0x00ff_00ff)],
            memory: &[],
        }),
    },
];

#[test]
fn bic_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bic_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
