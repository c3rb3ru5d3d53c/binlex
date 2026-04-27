use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "add",
        instruction: "add x0, x1, x2",
        bytes: &[0x20, 0x00, 0x02, 0x8b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 0x7fff_ffff_ffff_ffff), ("x2", 1)],
            memory: &[],
        }),
    },
    Arm64Sample {
        mnemonic: "add",
        instruction: "add w0, w1, w2",
        bytes: &[0x20, 0x00, 0x02, 0x0b],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("w1", 0x7fff_ffff), ("w2", 1)],
            memory: &[],
        }),
    },
];

#[test]
fn add_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn add_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
