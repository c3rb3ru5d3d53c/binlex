use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "bfxil",
        instruction: "bfxil	x0, x1, #4, #8",
        bytes: &[0x20, 0x2c, 0x44, 0xb3],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "bfxil",
        instruction: "bfxil	x0, x1, #4, #8",
        bytes: &[0x20, 0x2c, 0x44, 0xb3],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 0xffff_0000_ffff_0000), ("x1", 0x0123_4567_89ab_cdef)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "bfxil",
        instruction: "bfxil	w0, w1, #4, #8",
        bytes: &[0x20, 0x2c, 0x04, 0x33],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0xffff_0000), ("w1", 0x89ab_cdef)],
            memory: &[],
        }),
    },
];

#[test]
fn bfxil_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn bfxil_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
