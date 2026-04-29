use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ret",
        instruction: "ret",
        bytes: &[0xc0, 0x03, 0x5f, 0xd6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x30", 0x1040)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "ret",
        instruction: "ret x3",
        bytes: &[0x60, 0x00, 0x5f, 0xd6],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x3", 0x1080)],
            memory: &[],
        }),
    },
];

#[test]
fn ret_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ret_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
