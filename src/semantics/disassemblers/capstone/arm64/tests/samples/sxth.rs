use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sxth",
        instruction: "sxth	x0, w1",
        bytes: &[0x20, 0x3c, 0x40, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "sxth",
        instruction: "sxth	x0, w1",
        bytes: &[0x20, 0x3c, 0x40, 0x93],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x0000_8001)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sxth",
        instruction: "sxth	w0, w1",
        bytes: &[0x20, 0x3c, 0x00, 0x13],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x0000_8001)],
            memory: &[],
        }),
    },
];

#[test]
fn sxth_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sxth_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
