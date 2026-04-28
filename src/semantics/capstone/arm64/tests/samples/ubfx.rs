use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ubfx",
        instruction: "ubfx	x0, x1, #4, #8",
        bytes: &[0x20, 0x2c, 0x44, 0xd3],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ubfx",
        instruction: "ubfx	x0, x1, #4, #8",
        bytes: &[0x20, 0x2c, 0x44, 0xd3],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0123_4567_89ab_cdef)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ubfx",
        instruction: "ubfx	w0, w1, #4, #8",
        bytes: &[0x20, 0x2c, 0x04, 0x53],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x89ab_cdef)],
            memory: &[],
        }),
    },
];

#[test]
fn ubfx_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ubfx_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
