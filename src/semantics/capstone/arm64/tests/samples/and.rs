use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "and",
        instruction: "and x0, x1, x2",
        bytes: &[0x20, 0x00, 0x02, 0x8a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0xf0f0_f0f0_f0f0_f0f0), ("x2", 0x0ff0_0ff0_0ff0_0ff0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "and",
        instruction: "and w0, w1, w2",
        bytes: &[0x20, 0x00, 0x02, 0x0a],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0xf0f0_f0f0), ("w2", 0x0ff0_0ff0)],
            memory: &[],
        }),
    },
];

#[test]
fn and_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn and_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
