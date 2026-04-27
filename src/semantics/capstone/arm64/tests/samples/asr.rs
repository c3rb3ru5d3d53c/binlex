use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "asr",
        instruction: "asr	x0, x1, #3",
        bytes: &[0x20, 0xfc, 0x43, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "asr",
        instruction: "asr	x0, x1, #3",
        bytes: &[0x20, 0xfc, 0x43, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0xf123_4567_89ab_cdef)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "asr",
        instruction: "asr	w0, w1, #3",
        bytes: &[0x20, 0x7c, 0x03, 0x13],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xf234_5678)],
            memory: &[],
        }),
    },
];

#[test]
fn asr_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn asr_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
