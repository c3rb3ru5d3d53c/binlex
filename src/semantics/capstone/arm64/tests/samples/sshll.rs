use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v0.8h, v1.8b, #0",
        bytes: &[0x20, 0xa4, 0x08, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v0.4s, v1.4h, #0",
        bytes: &[0x20, 0xa4, 0x10, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v1.4s, v0.4h, #0",
        bytes: &[0x01, 0xa4, 0x10, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v0.2d, v1.2s, #0",
        bytes: &[0x20, 0xa4, 0x20, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v0.8h, v1.8b, #0",
        bytes: &[0x20, 0xa4, 0x08, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x0000_0000_0000_0000_aa55_f010_ff01_7f80u128)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v0.4s, v1.4h, #0",
        bytes: &[0x20, 0xa4, 0x10, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x0000_0000_0000_0000_0000_0000_8001_7fffu128)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v1.4s, v0.4h, #0",
        bytes: &[0x01, 0xa4, 0x10, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v0", 0x0000_0000_0000_0000_0000_0000_8001_7fffu128)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sshll",
        instruction: "sshll	v0.2d, v1.2s, #0",
        bytes: &[0x20, 0xa4, 0x20, 0x0f],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("v1", 0x0000_0000_0000_0000_ffff_ffff_7fff_ffffu128)],
            memory: &[],
        }),
    },
];

#[test]
fn sshll_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sshll_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
