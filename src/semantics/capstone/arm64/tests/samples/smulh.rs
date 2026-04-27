use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "smulh",
        instruction: "smulh	x0, x1, x2",
        bytes: &[0x20, 0x7c, 0x42, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "smulh",
        instruction: "smulh	x0, x1, x2",
        bytes: &[0x20, 0x7c, 0x42, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0xffff_ffff_ffff_fffe), ("x2", 3)],
            memory: &[],
        }),
    },
];

#[test]
fn smulh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn smulh_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
