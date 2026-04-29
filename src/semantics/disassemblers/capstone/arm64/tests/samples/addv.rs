use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "addv",
        instruction: "addv	b0, v1.16b",
        bytes: &[0x20, 0xb8, 0x31, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "addv",
        instruction: "addv	s0, v1.4s",
        bytes: &[0x20, 0xb8, 0xb1, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "addv",
        instruction: "addv	s0, v1.4s",
        bytes: &[0x20, 0xb8, 0xb1, 0x4e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x0000_0004_0000_0003_0000_0002_0000_0001u128)],
            memory: &[],
        }),
    },
];

#[test]
fn addv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn addv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
