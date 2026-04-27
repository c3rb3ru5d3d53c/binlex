use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "cmp",
        instruction: "cmp x0, x1",
        bytes: &[0x1f, 0x00, 0x01, 0xeb],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x0", 5), ("x1", 7), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "cmp",
        instruction: "cmp w0, w1",
        bytes: &[0x1f, 0x00, 0x01, 0x6b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w0", 5), ("w1", 7), ("n", 0), ("z", 0), ("c", 0), ("v", 0)],
            memory: &[],
        }),
    },
];

#[test]
fn cmp_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn cmp_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
