use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "rbit",
        instruction: "rbit	x0, x1",
        bytes: &[0x20, 0x00, 0xc0, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "rbit",
        instruction: "rbit	x0, x1",
        bytes: &[0x20, 0x00, 0xc0, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0123_4567_89ab_cdef)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "rbit",
        instruction: "rbit	w0, w1",
        bytes: &[0x20, 0x00, 0xc0, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x1234_5678)],
            memory: &[],
        }),
    },
];

#[test]
fn rbit_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn rbit_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
