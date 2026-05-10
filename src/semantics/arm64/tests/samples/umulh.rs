use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "umulh",
        instruction: "umulh	x0, x1, x2",
        bytes: &[0x20, 0x7c, 0xc2, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "umulh",
        instruction: "umulh	x0, x1, x2",
        bytes: &[0x20, 0x7c, 0xc2, 0x9b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0xffff_ffff_ffff_ffff), ("x2", 2)],
            memory: &[],
        }),
    },
];

#[test]
fn umulh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn umulh_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
