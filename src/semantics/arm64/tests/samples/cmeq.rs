use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cmeq",
        instruction: "cmeq	v0.16b, v1.16b, v2.16b",
        bytes: &[0x20, 0x8c, 0x22, 0x6e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cmeq",
        instruction: "cmeq	v0.2s, v1.2s, v2.2s",
        bytes: &[0x20, 0x8c, 0xa2, 0x2e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "cmeq",
        instruction: "cmeq	v0.16b, v1.16b, v2.16b",
        bytes: &[0x20, 0x8c, 0x22, 0x6e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v1", 0x100f_0e0d_0c0b_0a09_0807_0605_0403_0201u128),
                ("v2", 0x1001_0e0d_0cff_0a09_aa07_0605_0400_0201u128),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cmeq",
        instruction: "cmeq	v0.2s, v1.2s, v2.2s",
        bytes: &[0x20, 0x8c, 0xa2, 0x2e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v1", 0x0000_0000_0000_0000_0000_0002_0000_0001u128),
                ("v2", 0x0000_0000_0000_0000_0000_0003_0000_0001u128),
            ],
            memory: &[],
        }),
    },
];

#[test]
fn cmeq_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cmeq_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
