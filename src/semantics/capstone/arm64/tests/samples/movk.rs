use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "movk",
        instruction: "movk	x0, #4660, lsl #16",
        bytes: &[0x80, 0x46, 0xa2, 0xf2],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "movk",
        instruction: "movk	x0, #4660, lsl #16",
        bytes: &[0x80, 0x46, 0xa2, 0xf2],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0xffff_ffff_0000_ffff)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "movk",
        instruction: "movk	w0, #4660, lsl #16",
        bytes: &[0x80, 0x46, 0xa2, 0x72],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x0000_ffff)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "movk",
        instruction: "movk	x0, #4660",
        bytes: &[0x80, 0x46, 0x82, 0xf2],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0xffff_ffff_0000_ffff)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "movk",
        instruction: "movk	w0, #4660",
        bytes: &[0x80, 0x46, 0x82, 0x72],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x0000_ffff)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "movk",
        instruction: "movk	x0, #4660, lsl #48",
        bytes: &[0x80, 0x46, 0xe2, 0xf2],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0x0000_ffff_0000_ffff)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "movk",
        instruction: "movk	x0, #4660, lsl #32",
        bytes: &[0x80, 0x46, 0xc2, 0xf2],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0x0000_ffff_0000_ffff)],
            memory: &[],
        }),
    },
];

#[test]
fn movk_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn movk_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
