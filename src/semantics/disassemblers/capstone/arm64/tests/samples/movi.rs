use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v0.16b, #0",
        bytes: &[0x00, 0xe4, 0x00, 0x4f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v0.8b, #0",
        bytes: &[0x00, 0xe4, 0x00, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v0.8b, #255",
        bytes: &[0xe0, 0xe7, 0x07, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v1.16b, #255",
        bytes: &[0xe1, 0xe7, 0x07, 0x4f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v1.8b, #1",
        bytes: &[0x21, 0xe4, 0x00, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v0.2d, #0000000000000000",
        bytes: &[0x00, 0xe4, 0x00, 0x6f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v0.2d, #0xffffffffffffffff",
        bytes: &[0xe0, 0xe7, 0x07, 0x6f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v2.2d, #0xffffffffffffffff",
        bytes: &[0xe2, 0xe7, 0x07, 0x6f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v0.2s, #1",
        bytes: &[0x20, 0x04, 0x00, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	v0.2s, #2",
        bytes: &[0x40, 0x04, 0x00, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	d0, #0000000000000000",
        bytes: &[0x00, 0xe4, 0x00, 0x2f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movi",
        instruction: "movi	d0, #0xffffffffffffffff",
        bytes: &[0xe0, 0xe7, 0x07, 0x2f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
];

#[test]
fn movi_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movi_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
