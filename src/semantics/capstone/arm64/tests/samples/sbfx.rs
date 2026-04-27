use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sbfx",
        instruction: "sbfx	x0, x1, #4, #8",
        bytes: &[0x20, 0x2c, 0x44, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sbfx",
        instruction: "sbfx	x0, x1, #4, #8",
        bytes: &[0x20, 0x2c, 0x44, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0000_0000_0000_0ff0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sbfx",
        instruction: "sbfx	w0, w1, #4, #8",
        bytes: &[0x20, 0x2c, 0x04, 0x13],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x0000_0ff0)],
            memory: &[],
        }),
    },
];

#[test]
fn sbfx_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sbfx_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
