use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "stlrh",
        instruction: "stlrh	w0, [x1]",
        bytes: &[0x20, 0xfc, 0x9f, 0x48],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "stlrh",
        instruction: "stlrh	w0, [x1]",
        bytes: &[0x20, 0xfc, 0x9f, 0x48],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x1234_abcd), ("x1", 0x2000)],
            memory: &[(0x2000, &[0x00, 0x00])],
        }),
    },
];

#[test]
fn stlrh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn stlrh_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
