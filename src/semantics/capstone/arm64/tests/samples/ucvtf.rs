use super::{Arm64FixtureSpec, Arm64Sample, assert_conformance_cases, assert_sample_statuses};
use crate::semantics::SemanticStatus;

pub(crate) const SAMPLES: &[Arm64Sample] = &[
    Arm64Sample {
        mnemonic: "ucvtf",
        instruction: "ucvtf	d0, x1",
        bytes: &[0x20, 0x00, 0x63, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: None,
    },
    Arm64Sample {
        mnemonic: "ucvtf",
        instruction: "ucvtf	d0, x1",
        bytes: &[0x20, 0x00, 0x63, 0x9e],
        expected_status: Some(SemanticStatus::Complete),
        fixture: Some(Arm64FixtureSpec {
            registers: &[("x1", 42)],
            memory: &[],
        }),
    },
];

#[test]
fn ucvtf_semantics_regressions_stay_complete() {
    assert_sample_statuses(SAMPLES);
}

#[test]
fn ucvtf_semantics_match_unicorn_transitions() {
    assert_conformance_cases(SAMPLES);
}
