use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "strh",
        instruction: "strh	w0, [x1]",
        bytes: &[0x20, 0x00, 0x00, 0x79],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "strh",
        instruction: "strh	w0, [x1]",
        bytes: &[0x20, 0x00, 0x00, 0x79],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x1234_abcd), ("x1", 0x2000)],
            memory: &[(0x2000, &[0x00, 0x00])],
        }),
    },
    Arm64Sample {
        mnemonic: "strh",
        instruction: "strh	w0, [x1, x2]",
        bytes: &[0x20, 0x68, 0x22, 0x78],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 0x1234_abcd), ("x1", 0x3000), ("x2", 0x10)],
            memory: &[(0x3010, &[0x00, 0x00])],
        }),
    },
];

#[test]
fn strh_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn strh_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
