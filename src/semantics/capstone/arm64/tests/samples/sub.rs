use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "sub",
        instruction: "sub x0, x1, x2",
        bytes: &[0x20, 0x00, 0x02, 0xcb],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 7), ("x2", 3)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "sub",
        instruction: "sub w0, w1, w2",
        bytes: &[0x20, 0x00, 0x02, 0x4b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 7), ("w2", 3)],
            memory: &[],
        }),
    },
];

#[test]
fn sub_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn sub_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
