use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ldpsw",
        instruction: "ldpsw x0, x1, [x2]",
        bytes: &[0x40, 0x04, 0x40, 0x69],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x3000)],
            memory: &[(0x3000, &[0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldpsw",
        instruction: "ldpsw x0, x1, [x2], #8",
        bytes: &[0x40, 0x04, 0xc1, 0x68],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x2", 0x3000)],
            memory: &[(0x3000, &[0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff])],
        }),
    },
    Arm64Sample {
        mnemonic: "ldpsw",
        instruction: "ldpsw x0, x1, [sp, #-8]!",
        bytes: &[0xe0, 0x07, 0xff, 0x69],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("sp", 0x2ff0)],
            memory: &[(0x2fe8, &[0x01, 0x00, 0x00, 0x80, 0xfe, 0xff, 0xff, 0xff])],
        }),
    },
];

#[test]
fn ldpsw_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ldpsw_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
