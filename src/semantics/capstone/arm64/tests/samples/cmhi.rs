use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cmhi",
        instruction: "cmhi	v0.16b, v1.16b, v2.16b",
        bytes: &[0x20, 0x34, 0x22, 0x6e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cmhi",
        instruction: "cmhi	v0.2s, v1.2s, v2.2s",
        bytes: &[0x20, 0x34, 0xa2, 0x2e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cmhi",
        instruction: "cmhi	v0.16b, v1.16b, v2.16b",
        bytes: &[0x20, 0x34, 0x22, 0x6e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
                ("v2", 0x0f10_0e00_0cff_0a09_aa08_0604_0402_0100u128),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cmhi",
        instruction: "cmhi	v0.2s, v1.2s, v2.2s",
        bytes: &[0x20, 0x34, 0xa2, 0x2e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v1", 0x0000_0000_0000_0000_0000_0004_0000_0002u128),
                ("v2", 0x0000_0000_0000_0000_0000_0003_0000_0005u128),
            ],
            memory: &[],
        }),
    },
];

#[test]
fn cmhi_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cmhi_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
