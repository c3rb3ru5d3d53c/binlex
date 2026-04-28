use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "asrv",
        instruction: "asr	x0, x1, x2",
        bytes: &[0x20, 0x28, 0xc2, 0x9a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0xf123_4567_89ab_cdef), ("x2", 3)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "asrv",
        instruction: "asr	w0, w1, w2",
        bytes: &[0x20, 0x28, 0xc2, 0x1a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xf234_5678), ("w2", 3)],
            memory: &[],
        }),
    },
];

#[test]
fn asrv_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn asrv_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
