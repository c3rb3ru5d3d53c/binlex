use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "uzp1",
        instruction: "uzp1	v0.16b, v1.16b, v2.16b",
        bytes: &[0x20, 0x18, 0x02, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "uzp1",
        instruction: "uzp1	v0.4s, v1.4s, v2.4s",
        bytes: &[0x20, 0x18, 0x82, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "uzp1",
        instruction: "uzp1	v0.16b, v1.16b, v2.16b",
        bytes: &[0x20, 0x18, 0x02, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v1", 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100u128),
                ("v2", 0x1f1e_1d1c_1b1a_1918_1716_1514_1312_1110u128),
            ],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "uzp1",
        instruction: "uzp1	v0.4s, v1.4s, v2.4s",
        bytes: &[0x20, 0x18, 0x82, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[
                ("v1", 0x0000_0004_0000_0003_0000_0002_0000_0001u128),
                ("v2", 0x0000_0008_0000_0007_0000_0006_0000_0005u128),
            ],
            memory: &[],
        }),
    },
];

#[test]
fn uzp1_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn uzp1_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
