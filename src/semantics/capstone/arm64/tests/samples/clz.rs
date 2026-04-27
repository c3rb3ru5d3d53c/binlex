use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "clz",
        instruction: "clz	x0, x1",
        bytes: &[0x20, 0x10, 0xc0, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "clz",
        instruction: "clz	x0, x1",
        bytes: &[0x20, 0x10, 0xc0, 0xda],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x0000_0000_0000_00f0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "clz",
        instruction: "clz	w0, w1",
        bytes: &[0x20, 0x10, 0xc0, 0x5a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x0000_00f0)],
            memory: &[],
        }),
    },
];

#[test]
fn clz_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn clz_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
