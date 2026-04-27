use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldarh",
        instruction: "ldarh	w0, [x1]",
        bytes: &[0x20, 0xfc, 0xdf, 0x48],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ldarh",
        instruction: "ldarh	w0, [x1]",
        bytes: &[0x20, 0xfc, 0xdf, 0x48],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x2000)],
            memory: &[(0x2000, &[0xcd, 0xab])],
        }),
    },
];

#[test]
fn ldarh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldarh_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
