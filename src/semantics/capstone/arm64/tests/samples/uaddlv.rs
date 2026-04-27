use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "uaddlv",
        instruction: "uaddlv	h0, v1.16b",
        bytes: &[0x20, 0x38, 0x30, 0x6e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "uaddlv",
        instruction: "uaddlv	h0, v1.8b",
        bytes: &[0x20, 0x38, 0x30, 0x2e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "uaddlv",
        instruction: "uaddlv	h0, v1.8b",
        bytes: &[0x20, 0x38, 0x30, 0x2e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x0000_0000_0000_0000_0807_0605_0403_0201u128)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "uaddlv",
        instruction: "uaddlv	h0, v1.16b",
        bytes: &[0x20, 0x38, 0x30, 0x6e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128)],
            memory: &[],
        }),
    },
];

#[test]
fn uaddlv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn uaddlv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
